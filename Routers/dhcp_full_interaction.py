# dhcp_full_interaction.py

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
import logging
import random
from scapy.layers.inet import UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import mac2str

# 关闭 Scapy 的一些警告信息
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# ----------------------------------------------------------------------------------
# 1. 配置
# ----------------------------------------------------------------------------------
INTERFACE_NAME = "ens37"
conf.iface = INTERFACE_NAME

try:
    MY_MAC = get_if_hwaddr(conf.iface)
    print(f"[*] 使用网卡: '{conf.iface}'")
    print(f"[*] 本机 MAC 地址: {MY_MAC}")
except Exception as e:
    print(f"[!] 获取网卡 '{conf.iface}' 信息失败: {e}")
    exit()

TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)
print(f"[*] 本次 DHCP 会话 ID (xid): {hex(TRANSACTION_ID)}")


# ----------------------------------------------------------------------------------
# 2. (D)iscover: 发送 DHCP 发现包
# ----------------------------------------------------------------------------------
print("\n--- 步骤 1: 发送 DHCP DISCOVER ---")
dhcp_discover = (
    Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags=0x8000) /
    DHCP(options=[("message-type", "discover"), ("end")])
)

# 在开始监听之前，先打开抓包器
# 这种方法可以确保我们不会错过任何包
socket = conf.L2listen(
    type=ETH_P_ALL,
    iface=INTERFACE_NAME,
    filter="udp and (port 67 or port 68)"
)

print("[*] 开始监听 DHCP 响应...")
print("[*] 发送 DHCP DISCOVER 包...")
sendp(dhcp_discover, iface=INTERFACE_NAME, verbose=False)

print("[*] 等待 DHCP OFFER 响应...")
dhcp_offer = None
start_time = time.time()
timeout = 10  # 10 秒超时

while time.time() - start_time < timeout:
    packets = socket.sniff(timeout=1, count=10)
    for pkt in packets:
        if DHCP in pkt:
            msg_type = None
            for opt in pkt[DHCP].options:
                if opt[0] == 'message-type':
                    msg_type = opt[1]
                    break
            
            if msg_type == 2 and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:  # OFFER
                dhcp_offer = pkt
                break
    
    if dhcp_offer:
        break

# ----------------------------------------------------------------------------------
# 3. (O)ffer: 处理服务器的提供
# ----------------------------------------------------------------------------------
print("\n--- 步骤 2: 等待并解析 DHCP OFFER ---")
if dhcp_offer is None:
    print("[!] 未收到 DHCP OFFER 包。")
    socket.close()
    exit()

offered_ip = dhcp_offer[BOOTP].yiaddr
server_ip = None
for opt in dhcp_offer[DHCP].options:
    if opt[0] == 'server_id':
        server_ip = opt[1]
        break

print(f"[+] 成功收到 DHCP OFFER!")
print(f"    - 路由器提供的 IP 地址: {offered_ip}")
print(f"    - DHCP 服务器 IP 地址: {server_ip}")

# ----------------------------------------------------------------------------------
# 4. (R)equest: 发送 DHCP 请求包
# ----------------------------------------------------------------------------------
print("\n--- 步骤 3: 发送 DHCP REQUEST ---")
dhcp_request = (
    Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags=0x8000) /
    DHCP(options=[
        ("message-type", "request"),
        ("requested_addr", offered_ip),
        ("server_id", server_ip),
        ("end")
    ])
)

print("[*] 发送 DHCP REQUEST 包...")
sendp(dhcp_request, iface=INTERFACE_NAME, verbose=False)

print("[*] 等待 DHCP ACK 响应...")
dhcp_ack = None
start_time = time.time()

while time.time() - start_time < timeout:
    packets = socket.sniff(timeout=1, count=10)
    for pkt in packets:
        if DHCP in pkt:
            msg_type = None
            for opt in pkt[DHCP].options:
                if opt[0] == 'message-type':
                    msg_type = opt[1]
                    break
            
            if (msg_type == 5 or msg_type == 6) and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:  # ACK or NAK
                dhcp_ack = pkt
                break
    
    if dhcp_ack:
        break

# 关闭套接字
socket.close()

# ----------------------------------------------------------------------------------
# 5. (A)cknowledgment: 处理最终确认
# ----------------------------------------------------------------------------------
print("\n--- 步骤 4: 等待并解析 DHCP ACK ---")
if dhcp_ack is None:
    print("[!] 未收到 DHCP ACK 包。请求可能失败。")
    exit()

# 检查是 ACK 还是 NAK
is_ack = False
for opt in dhcp_ack[DHCP].options:
    if opt[0] == 'message-type' and opt[1] == 5:  # 5 = ACK
        is_ack = True
        break

if is_ack:
    final_ip = dhcp_ack[BOOTP].yiaddr
    print(f"[+] 成功收到 DHCP ACK!")
    print(f"    - 路由器已确认分配 IP: {final_ip}")
    print("\n[***] DHCP DORA 交互模拟在 Linux 上成功！ [***]")
else:
    print("[!] 收到的是 DHCP NAK 包 (拒绝)。")
    for opt in dhcp_ack[DHCP].options:
        if opt[0] == 'message':
            print(f"    - 拒绝原因: {opt[1]}")
            break