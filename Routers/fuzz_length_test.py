# dhcp_fuzzer.py

from scapy.all import *
import logging
import random
import time
import os

# --- 配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
INTERFACE_NAME = "ens37"

# 我们要重点攻击的 DHCP Option 代码列表
# 1: Subnet, 3: Router, 6: DNS, 12: Hostname, 15: Domain, 42: NTP, 51: Lease Time
FUZZ_TARGETS = [1, 3, 6, 12, 15, 42, 51] 

# 每次发包后的等待时间（秒）
# 设置得足够长，以便路由器有时间崩溃、重启和恢复
DELAY_BETWEEN_PACKETS = 1 # 2 分钟
# ---

conf.iface = INTERFACE_NAME

try:
    MY_MAC = get_if_hwaddr(conf.iface)
    print(f"[*] Fuzzer 将使用网卡: '{conf.iface}'")
    print(f"[*] MAC 地址: {MY_MAC}")
except Exception as e:
    print(f"[!] 获取网卡 '{conf.iface}' 信息失败: {e}")
    exit()

print(f"[*] Fuzzing 目标 Options: {FUZZ_TARGETS}")
print(f"[*] 每次发包后将等待 {DELAY_BETWEEN_PACKETS} 秒。")
print("[*] 请在另一个终端窗口中持续 ping 您的路由器以监控其状态。")
print("\n" + "="*50)

iteration_count = 1

while True:
    try:
        print(f"\n[+] --- Fuzzing 迭代: #{iteration_count} ---")
        
        # --- Fuzzing 逻辑 ---
        # 1. 随机选择一个目标 Option
        option_code = random.choice(FUZZ_TARGETS)
        
        # 2. 生成一个随机的错误长度 (0-255)
        malformed_length = random.randint(0, 255)
        
        # 3. 生成对应长度的随机字节作为内容
        malformed_value = os.urandom(malformed_length)
        
        print(f"    --> 目标: Option {option_code}")
        print(f"    --> 注入长度: {malformed_length}")

        # --- 构造数据包 ---
        TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)
        
        # 手动构建畸形的 option 字节
        malformed_option = bytes([option_code, malformed_length]) + malformed_value
        
        # 组合成完整的 options 字节流
        dhcp_options = b'\x35\x01\x01' + malformed_option + b'\xff' # Discover + Malformed Option + End

        dhcp_discover_fuzz = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
            DHCP(options=dhcp_options)
        )

        # --- 发送数据包 ---
        print("[*] 发送畸形 Discover 包...")
        sendp(dhcp_discover_fuzz, iface=INTERFACE_NAME, verbose=False)
        print("[+] 发送成功。")

        # --- 等待 ---
        print(f"[*] 开始等待 {DELAY_BETWEEN_PACKETS} 秒，请密切观察 ping 的状态...")
        time.sleep(DELAY_BETWEEN_PACKETS)
        
        iteration_count += 1

    except KeyboardInterrupt:
        print("\n[!] Fuzzing 被用户中断。正在退出...")
        break
    except Exception as e:
        print(f"\n[!] 发生错误: {e}")
        time.sleep(5)