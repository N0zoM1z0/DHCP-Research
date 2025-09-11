# test_dns_options.py

from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
import logging
import random
import time
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
# 2. (D)iscover: 构造带有特定请求的发现包
# ----------------------------------------------------------------------------------
print("\n--- 步骤 1: 发送 DHCP DISCOVER ---")

# =================================================================
# ====> 核心修改在这里！ <====
# =================================================================
# 我们在 DHCP options 中加入 "param_req_list" (Option 55)
# 列表中的数字是 Option 的代号，代表我们想向服务器请求哪些信息
# 1  = Subnet Mask, 3  = Router (Gateway)
# 6  = DNS Server, 15 = Domain Name, 119 = Domain Search List
param_req_list = [1, 3, 6, 15, 119]

dhcp_discover = (
    Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
    IP(src="0.0.0.0", dst="255.255.255.255") /
    UDP(sport=68, dport=67) /
    BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
    DHCP(options=[
        ("message-type", "discover"),
        ("param_req_list", param_req_list), # <--- 加入我们的请求列表
        ("end")
    ])
)

# ----------------------------------------------------------------------------------
# 后续的收发逻辑与之前成功的脚本完全相同
# ----------------------------------------------------------------------------------

# 在开始监听之前，先打开抓包器
socket = conf.L2listen(
    type=ETH_P_ALL,
    iface=INTERFACE_NAME,
    filter="udp and (port 67 or port 68)"
)

print(f"[*] 索要的 Option 列表: {param_req_list}")
print("[*] 开始监听 DHCP 响应...")
print("[*] 发送 DHCP DISCOVER 包...")
sendp(dhcp_discover, iface=INTERFACE_NAME, verbose=False)

print("[*] 等待 DHCP OFFER 响应...")
dhcp_offer = None
start_time = time.time()
timeout = 10

while time.time() - start_time < timeout:
    packets = socket.sniff(timeout=1, count=10)
    for pkt in packets:
        if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
            if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                dhcp_offer = pkt
                break
    if dhcp_offer:
        break

print("\n--- 步骤 2: 分析 DHCP OFFER 包 ---")
if dhcp_offer is None:
    print("[!] 未收到 DHCP OFFER 包。")
    socket.close()
    exit()

print("[+] 成功收到 DHCP OFFER!")
print("[+] 服务器回应的 Options 如下:")
# 打印出服务器回应的所有 Options
for opt in dhcp_offer[DHCP].options:
    if isinstance(opt, tuple):
        print(f"    - {opt[0]}: {opt[1]}")

socket.close()
print("\n[***] DNS 相关 Option 探测完成！ [***]")