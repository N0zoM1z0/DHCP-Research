# 12_option_dhcp_test_final_v3.py

from scapy.all import *
import logging
import random
import time

# --- 配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
INTERFACE_NAME = "ens37"
# 我们想要注册的主机名
TEST_HOSTNAME = "my-test-pc"
# 【关键】我们想要伪造的长度值
# "my-test-pc" 的实际长度是 10
CUSTOM_HOSTNAME_LEN = 8
# ---

conf.iface = INTERFACE_NAME

try:
    MY_MAC = get_if_hwaddr(conf.iface)
    print(f"[*] 使用网卡: '{conf.iface}'")
    print(f"[*] 本机 MAC 地址: {MY_MAC}")
    print(f"[*] 准备注册的主机名: '{TEST_HOSTNAME}' (实际长度: {len(TEST_HOSTNAME.encode())})")
    print(f"[*] 将在 Option 12 中使用伪造的长度: {CUSTOM_HOSTNAME_LEN}")
except Exception as e:
    print(f"[!] 获取网卡 '{conf.iface}' 信息失败: {e}")
    exit()

TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)
print(f"[*] 本次 DHCP 会话 ID (xid): {hex(TRANSACTION_ID)}")

# ==================== 代码修改部分 开始 ====================
# 1. 仅为需要自定义的 Option 12 构建完整的 TLV 字节序列
# Type = 12 (0x0c)
# Length = 我们自定义的长度
# Value = 主机名的字节表示
custom_hostname_option_tlv = b'\x0c' + bytes([CUSTOM_HOSTNAME_LEN]) + TEST_HOSTNAME.encode('utf-8')

# 2. 将这个自定义的字节序列包装进 Raw 层对象中
raw_hostname_option = Raw(load=custom_hostname_option_tlv)
# ==================== 代码修改部分 结束 ====================


# --- 步骤 1 & 2: Discover 和 Offer ---
param_req_list = [1, 3, 6, 15]
dhcp_discover = (
    Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
    # 使用 Scapy 的标准方式处理大部分选项
    # 仅将我们自定义的选项作为 DHCPOption 对象插入
    DHCP(options=[
        ("message-type", "discover"),          # Scapy 会正确处理
        ("param_req_list", param_req_list),  # Scapy 会正确处理
        raw_hostname_option,                   # Scapy 会直接使用我们提供的原始字节
        ("end")                                # Scapy 会正确处理
    ])
)

socket = conf.L2listen(type=ETH_P_ALL, iface=INTERFACE_NAME, filter="udp and (port 67 or 68)")

print("\n--- 步骤 1: 发送 DHCP DISCOVER (包含自定义长度的主机名) ---")
sendp(dhcp_discover, iface=INTERFACE_NAME, verbose=False)

print("[*] 等待 DHCP OFFER 响应...")
dhcp_offer = None
start_time = time.time()
while time.time() - start_time < 10:
    packets = socket.sniff(timeout=1, count=5)
    for pkt in packets:
        if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
            if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                dhcp_offer = pkt
                break
    if dhcp_offer:
        break

if dhcp_offer is None:
    print("[!] 未收到 DHCP OFFER 包。请检查防火墙或网络环境。")
    socket.close()
    exit()

print("[+] 成功收到 DHCP OFFER!")
offered_ip = dhcp_offer[BOOTP].yiaddr

server_ip = None
for opt in dhcp_offer[DHCP].options:
    if opt[0] == 'server_id':
        server_ip = opt[1]
        break

if server_ip is None:
    print("[!] 错误：在DHCP OFFER包中未找到 'server_id' 选项！")
    socket.close()
    exit()

# --- 步骤 3 & 4: Request 和 ACK ---
dhcp_request = (
    Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
    # 在 Request 包中也使用同样的方法
    DHCP(options=[
        ("message-type", "request"),
        ("requested_addr", offered_ip),
        ("server_id", server_ip),
        raw_hostname_option,  # 复用我们创建的自定义 Option 对象
        ("end")
    ])
)

print("\n--- 步骤 2: 发送 DHCP REQUEST (包含自定义长度的主机名) ---")
sendp(dhcp_request, iface=INTERFACE_NAME, verbose=False)

# ... 后续代码与您最初的版本完全相同，无需修改 ...
print("[*] 等待 DHCP ACK 响应...")
dhcp_ack = None
start_time = time.time()
while time.time() - start_time < 10:
    packets = socket.sniff(timeout=1, count=5)
    for pkt in packets:
        if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
            if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                dhcp_ack = pkt
                break
    if dhcp_ack:
        break

if dhcp_ack is None:
    print("[!] 未收到 DHCP ACK 包。")
    socket.close()
    exit()

final_ip = dhcp_ack[BOOTP].yiaddr
print(f"[+] 成功收到 DHCP ACK! 获得了 IP: {final_ip}")

print("\n--- 步骤 3: 验证路由器的本地 DNS 记录 ---")
print(f"[*] 正在向路由器 ({server_ip}) 查询主机名 '{TEST_HOSTNAME}'...")

try:
    dns_query = IP(dst=server_ip)/UDP()/DNS(rd=1, qd=DNSQR(qname=TEST_HOSTNAME))
    dns_response = sr1(dns_query, timeout=5, verbose=False)

    if dns_response and dns_response.haslayer(DNS) and dns_response.haslayer(DNSRR):
        resolved_ip = dns_response[DNSRR].rdata
        print(f"[+] DNS 查询成功！'{TEST_HOSTNAME}' 被解析为: {resolved_ip}")
        if resolved_ip == final_ip:
            print(f"\n[***] 成功！路由器已将主机名 '{TEST_HOSTNAME}' 动态注册到 IP {final_ip}！ [***]")
        else:
            print(f"\n[!] 失败：解析到的 IP ({resolved_ip}) 与获取到的 IP ({final_ip}) 不匹配。")
    elif dns_response and dns_response.haslayer(DNS) and dns_response[DNS].rcode == 3:
         print(f"\n[-] 失败：路由器回应了 NXDOMAIN (域名不存在)。")
    else:
        print("\n[-] 失败：未收到有效的 DNS 回应或查询超时。")
        if dns_response:
            dns_response.summary()

except Exception as e:
    print(f"\n[!] DNS 验证过程中发生错误: {e}")

finally:
    socket.close()