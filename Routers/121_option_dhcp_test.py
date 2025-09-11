# 121_option_dhcp_test.py

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
print("\n--- 步骤 1: 发送 DHCP DISCOVER (请求 Option 121) ---")

# =================================================================
# ====> 核心修改在这里！ <====
# =================================================================
# 我们在 DHCP options 中加入 "param_req_list" (Option 55)
# 这次我们主要关心的是 Option 121
# 1  = Subnet Mask, 3  = Router (Gateway)
# 121 = Classless Static Route
param_req_list = [1, 3, 121]

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
socket = conf.L2listen(type=ETH_P_ALL, iface=INTERFACE_NAME, filter="udp and (port 67 or 68)")

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

option_121_found = False
option_121_content = None

for opt in dhcp_offer[DHCP].options:
    if isinstance(opt, tuple):
        print(f"    - {opt[0]}: {opt[1]}")
        # Scapy 将 Option 121 解析为 'classless-static-routes'
        if opt[0] == 'classless-static-routes':
            option_121_found = True
            option_121_content = opt[1]

print("\n" + "="*40)
print("--- 最终结论 ---")
if option_121_found:
    print(f"[!!!] 重要安全发现：路由器回应了 Option 121！")
    print(f"[*] 路由内容为: {option_121_content}")
    print("[*] 这表明该路由器的 DHCP 服务支持下发静态路由，存在被用于 TunnelVision 类似攻击的潜在风险。")
else:
    print(f"[✓] 好的安全表现：路由器没有回应 Option 121。")
    print("[*] 这表明该路由器的 DHCP 服务不支持（或未配置）下发静态路由功能，针对 TunnelVision 攻击的服务端风险较低。")
print("="*40)