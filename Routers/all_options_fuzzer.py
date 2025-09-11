#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# all_options_fuzzer.py

from scapy.all import *
import logging
import random
import time
import os
import socket as std_socket # 导入标准库的 socket，用于 IP 地址转换

# --- 配置 ---
# 屏蔽 Scapy 的IPv6路由警告等，保持输出清洁
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# !!! 重要：请将此处的网卡名称修改为您系统中用于测试的网卡 !!!
INTERFACE_NAME = "ens37" 

# Fuzzing 目标：我们将遍历所有可能的 DHCP Option 代码，从 0 到 255
# 这覆盖了您提供的列表中的所有选项以及所有已定义、未定义和保留的选项。
FUZZ_TARGETS = list(range(256))

# 每次 Fuzz 循环后的等待时间（秒）。
# 注意：如果服务器崩溃，需要给它足够的时间来重启。
# 在实际测试中，这个值可能需要设置得更长，例如 60 或 120 秒。
DELAY_BETWEEN_PACKETS = 2 
# ---

# 初始化 Scapy 配置
conf.iface = INTERFACE_NAME

try:
    # 尝试获取网卡 MAC 地址，如果网卡不存在则会报错
    MY_MAC = get_if_hwaddr(conf.iface)
except Exception:
    print(f"[!] 错误: 无法找到名为 '{INTERFACE_NAME}' 的网卡。请检查配置。")
    exit(1)

print("="*50)
print("          DHCP 全选项状态化 Fuzzer")
print("="*50)
print(f"[*] Fuzzer 将使用网卡: '{conf.iface}' (MAC: {MY_MAC})")
print(f"[*] Fuzzing 目标 Options: 0-255 (所有可能性)")
print(f"[*] 每次循环后将等待 {DELAY_BETWEEN_PACKETS} 秒。")
print("[*] 警告: 此工具可能导致网络服务中断。")
print("[*] 请仅在您拥有权限的测试环境中使用！")
print("[*] 建议在另一个终端窗口中持续 ping 您的路由器以监控其状态。")
print("   (例如: ping 192.168.1.1 -t)")
print("\n" + "="*50)
print("[*] Fuzzer 将在 5 秒后启动...")
time.sleep(5)

iteration_count = 1

while True:
    try:
        print(f"\n[+] --- Fuzzing 迭代: #{iteration_count} ---")
        TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)

        # --- 步骤 1: 正常的 Discover -> Offer ---
        # 模拟客户端寻找 DHCP 服务器
        dhcp_discover = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
            DHCP(options=[("message-type", "discover"), ("end")])
        )
        
        # 创建一个二层套接字用于监听 DHCP 回复
        socket = conf.L2listen(type=ETH_P_ALL, iface=INTERFACE_NAME, filter="udp and (port 67 or 68)")
        
        # 发送 Discover 包
        sendp(dhcp_discover, iface=INTERFACE_NAME, verbose=False)

        # 等待服务器的 Offer 包
        dhcp_offer = None
        start_time = time.time()
        # 等待最多 5 秒
        while time.time() - start_time < 1:
            packets = socket.sniff(timeout=1, count=10)
            for pkt in packets:
                # 确认是 DHCP Offer 并且 Transaction ID 匹配
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer:
                break
        
        if not dhcp_offer:
            print("[!] 未收到 OFFER, 跳过此次迭代。可能是网络波动或服务器无响应。")
            socket.close()
            iteration_count += 1
            time.sleep(1) # 等待更长时间再重试
            continue
        
        # 从 Offer 包中提取服务器提供的 IP 和服务器自身的 IP
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = dhcp_offer[IP].src # 更可靠的获取 server_id 的方式
        
        # 也可以从 DHCP options 中获取
        server_id_from_opt = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_id_from_opt = opt[1]
                break
        
        if not server_id_from_opt:
            print("[!] 错误: 未能在 OFFER 包的 Options 中找到 server_id。")
            socket.close()
            continue

        print(f"[*] 状态正常：已收到 OFFER, IP: {offered_ip}, Server: {server_ip}")
        
        # --- 步骤 2: 构造并发送畸形的 Request ---
        
        # Fuzzing 逻辑: 随机选择一个 Option，并生成畸形数据
        option_code = random.choice(FUZZ_TARGETS)
        malformed_length = random.randint(0, 255) # 长度也可以是0或超过常规的最大值
        malformed_value = os.urandom(malformed_length)
        
        print(f"    --> 注入目标: Option {option_code} (长度: {malformed_length})")
        
        # =================================================================
        # ====> 核心: 手动构建所有 Options 的字节流以绕过 Scapy 验证 <====
        # =================================================================
        # Option 53: DHCP Message Type (Request) -> b'\x35\x01\x03'
        opt_msg_type = b'\x35\x01\x03'
        # Option 50: Requested IP Address -> b'\x32\x04' + IP地址的4个字节
        opt_req_addr = b'\x32\x04' + std_socket.inet_aton(offered_ip)
        # Option 54: DHCP Server Identifier -> b'\x36\x04' + 服务器IP的4个字节
        opt_server_id = b'\x36\x04' + std_socket.inet_aton(server_ip)
        # 我们要注入的畸形 Option
        malformed_option = bytes([option_code, malformed_length]) + malformed_value
        # 结束符
        opt_end = b'\xff'
        
        # 拼接成最终的 options 载荷
        # 放置顺序: 必须的选项 -> 畸形选项 -> 结束符
        final_options = opt_msg_type + opt_req_addr + opt_server_id + malformed_option + opt_end
        
        # 构建完整的畸形 DHCP Request 包
        dhcp_request_fuzz = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
            DHCP(options=final_options) # <--- 直接使用我们拼接好的原始字节流
        )
        
        print("[*] 发送畸形 Request 包...")
        sendp(dhcp_request_fuzz, iface=INTERFACE_NAME, verbose=False)
    
        
        # --- 步骤 3: 观察服务器的最终回应 (ACK/NAK) ---
        print("[*] 等待最终回应 (ACK/NAK)...")
        final_response = None
        start_time = time.time()
        # 等待最多 5 秒
        while time.time() - start_time < 1:
            packets = socket.sniff(timeout=1, count=10)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
                    # 5 = ACK, 6 = NAK
                    if any(opt[1] in [5, 6] for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        final_response = pkt
                        break
            if final_response:
                break
        
        if final_response:
            msg_type = [opt[1] for opt in final_response[DHCP].options if opt[0] == 'message-type'][0]
            if msg_type == 5:
                print("[+] 服务器回应了 ACK。它似乎正常处理了我们的畸形请求。")
            elif msg_type == 6:
                print("[!] 服务器回应了 NAK (拒绝)。这是一个有意思的发现！说明服务器解析了该选项并认为其无效。")
        else:
            print("\n" + "!"*60)
            print("[!!!] CRITICAL: 服务器在5秒内没有回应！")
            print(f"[!!!] 这可能意味着服务已崩溃或挂起！请立即检查 ping 的状态！")
            print(f"[!!!] 触发崩溃的可能是: Option {option_code} with length {malformed_length}")
            print("!"*60 + "\n")
            # 如果可能崩溃，等待更长时间让服务恢复
            time.sleep(60) 
            
        socket.close()
        iteration_count += 1
        
        # --- 等待，给路由器恢复时间 ---
        print(f"[*] Fuzz 循环结束，等待 {DELAY_BETWEEN_PACKETS} 秒...")
        time.sleep(DELAY_BETWEEN_PACKETS)

    except KeyboardInterrupt:
        print("\n[!] Fuzzing 被用户中断。正在退出...")
        if 'socket' in locals() and not socket.closed:
            socket.close()
        break
    except Exception as e:
        print(f"\n[!] 发生未知错误: {e}")
        print("[!] 可能是 Scapy 或网络接口问题。等待 10 秒后重试...")
        if 'socket' in locals() and not socket.closed:
            socket.close()
        time.sleep(10)