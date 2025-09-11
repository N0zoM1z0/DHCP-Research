# 81_option_fqdn_test.py

from scapy.all import *
import logging
import random
import time

# --- 配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
INTERFACE_NAME = "ens37"
# 我们想要注册的完整域名 (FQDN)
# 注意：标准的FQDN通常以.结尾，但在这里我们省略，函数会自动处理
TEST_FQDN = "my-fqdn-pc.local" 
# ---

conf.iface = INTERFACE_NAME

# ==================== 主要修改部分 开始 ====================

def encode_fqdn(fqdn):
    """
    将一个标准的域名字符串编码为DNS线格式 (wire format)。
    例如: "my-pc.local" -> b'\x05my-pc\x05local\x00'
    """
    # 移除末尾可能存在的点，并按点分割
    labels = fqdn.strip('.').split('.')
    encoded = b''
    for label in labels:
        encoded += bytes([len(label)]) + label.encode('ascii')
    return encoded + b'\x00' # 以空字节结尾

# 根据 RFC 4702 构建 Option 81 的值
# Flags: S=1 (服务器更新A记录), E=1 (线格式编码), O=0, N=0 -> 0b00000101 -> 5
dhcp_opt_81_flags = 0b00000101
dhcp_opt_81_rcode1 = 0
dhcp_opt_81_rcode2 = 0
encoded_fqdn = encode_fqdn(TEST_FQDN)

# 将所有部分拼接成最终的Option 81的字节值
option_81_value = bytes([dhcp_opt_81_flags, dhcp_opt_81_rcode1, dhcp_opt_81_rcode2]) + encoded_fqdn

# ==================== 主要修改部分 结束 ====================


try:
    MY_MAC = get_if_hwaddr(conf.iface)
    print(f"[*] 使用网卡: '{conf.iface}'")
    print(f"[*] 本机 MAC 地址: {MY_MAC}")
    print(f"[*] 准备注册的 FQDN: '{TEST_FQDN}'")
    print(f"[*] 构建的 Option 81 数据 (Hex): {option_81_value.hex()}")
except Exception as e:
    print(f"[!] 获取网卡 '{conf.iface}' 信息失败: {e}")
    exit()

TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)
print(f"[*] 本次 DHCP 会话 ID (xid): {hex(TRANSACTION_ID)}")

# --- 步骤 1 & 2: Discover 和 Offer ---
param_req_list = [1, 3, 6, 15, 81] # 我们也请求服务器返回Option 81
dhcp_discover = (
    Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
    DHCP(options=[
        ("message-type", "discover"),
        ("param_req_list", param_req_list),
        (81, option_81_value), # <--- 使用 Option 81
        ("end")
    ])
)

socket = conf.L2listen(type=ETH_P_ALL, iface=INTERFACE_NAME, filter="udp and (port 67 or 68)")

print("\n--- 步骤 1: 发送 DHCP DISCOVER (包含 FQDN Option 81) ---")
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
    print("[!] 未收到 DHCP OFFER 包。")
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
    DHCP(options=[
        ("message-type", "request"),
        ("requested_addr", offered_ip),
        ("server_id", server_ip),
        (81, option_81_value), # <--- 在 Request 中再次声明 FQDN Option 81
        ("end")
    ])
)

print("\n--- 步骤 2: 发送 DHCP REQUEST (包含 FQDN Option 81) ---")
sendp(dhcp_request, iface=INTERFACE_NAME, verbose=False)

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

# --- 步骤 5: 验证 DNS 记录 ---
print("\n--- 步骤 3: 验证路由器的本地 DNS 记录 ---")
print(f"[*] 正在向路由器 ({server_ip}) 查询 FQDN '{TEST_FQDN}'...")

try:
    # 构造一个 DNS 查询包
    dns_query = IP(dst=server_ip)/UDP()/DNS(rd=1, qd=DNSQR(qname=TEST_FQDN)) # <--- 查询 FQDN
    
    # 发送查询并等待回应
    dns_response = sr1(dns_query, timeout=5, verbose=False)

    if dns_response and dns_response.haslayer(DNS) and dns_response.haslayer(DNSRR):
        resolved_ip = dns_response[DNSRR].rdata
        print(f"[+] DNS 查询成功！'{TEST_FQDN}' 被解析为: {resolved_ip}")
        if resolved_ip == final_ip:
            print(f"\n[***] 成功！路由器已将 FQDN '{TEST_FQDN}' 动态注册到 IP {final_ip}！ [***]")
            print("[!!!] 这是一个重要的安全发现：该路由器支持并执行了RFC 4702动态DNS更新。")
        else:
            print(f"\n[!] 失败：解析到的 IP ({resolved_ip}) 与获取到的 IP ({final_ip}) 不匹配。")
    elif dns_response and dns_response.haslayer(DNS) and dns_response[DNS].rcode == 3:
         print(f"\n[-] 失败：路由器回应了 NXDOMAIN (域名不存在)。")
         print("[✓] 这是一个好的安全表现：路由器收到了Option 81但没有执行动态注册。")
    else:
        print("\n[-] 失败：未收到有效的 DNS 回应或查询超时。")
        if dns_response:
            dns_response.summary()

except Exception as e:
    print(f"\n[!] DNS 验证过程中发生错误: {e}")

finally:
    socket.close()