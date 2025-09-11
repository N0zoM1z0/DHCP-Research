# 114_option_dhcp_test.py

from scapy.all import *
import logging
import random
import time

# --- 配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
INTERFACE_NAME = "ens37"
# ---

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

# --- 步骤 1: Discover ---
print("\n--- 步骤 1: 发送 DHCP DISCOVER (请求 Option 114) ---")

# =================================================================
# ====> 核心修改在这里！ <====
# =================================================================
# 我们在 DHCP options 中加入 "param_req_list" (Option 55)
# 这次我们主要关心的是 Option 114 (Captive Portal)
# 1  = Subnet Mask, 3  = Router (Gateway)
# 114 = Captive Portal
param_req_list = [1, 3, 114]

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

# --- 收发逻辑 (与之前成功的脚本相同) ---
socket = conf.L2listen(type=ETH_P_ALL, iface=INTERFACE_NAME, filter="udp and (port 67 or port 68)")

print(f"[*] 索要的 Option 列表: {param_req_list}")
print("[*] 开始监听 DHCP 响应...")
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

socket.close()

# --- 步骤 2: 分析结果 ---
print("\n--- 步骤 2: 分析 DHCP OFFER 包 ---")
if dhcp_offer is None:
    print("[!] 未收到 DHCP OFFER 包。")
    exit()

print("[+] 成功收到 DHCP OFFER!")
print("[+] 服务器回应的 Options 如下:")

option_114_found = False
option_114_content = None

for opt in dhcp_offer[DHCP].options:
    if isinstance(opt, tuple):
        # Scapy 将 Option 114 解析为 'captive-portal'
        # 我们同时打印出所有收到的 option 以便观察
        print(f"    - {opt[0]}: {opt[1]}")
        if opt[0] == 'captive-portal':
            option_114_found = True
            option_114_content = opt[1]

print("\n" + "="*40)
print("--- 最终结论 ---")
if option_114_found:
    print(f"[!!!] 有意思的发现：路由器回应了 Option 114 (Captive-Portal)！")
    print(f"[*] 门户 URL 为: {option_114_content.decode('utf-8', errors='ignore')}")
    print("[*] 这表明该路由器的 DHCP 服务支持强制门户功能，通常用于访客网络或 Web 认证。")
else:
    print(f"[✓] 正常表现：路由器没有回应 Option 114。")
    print("[*] 这表明该路由器的 DHCP 服务不支持（或未配置）强制门户功能。这是标准家庭网络下的正常行为。")
print("="*40)