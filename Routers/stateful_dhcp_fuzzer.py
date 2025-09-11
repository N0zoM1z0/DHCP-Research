# stateful_dhcp_fuzzer.py

from scapy.all import *
import logging
import random
import time
import os
import socket as std_socket # 导入标准库的 socket，用于 IP 地址转换

# --- 配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
INTERFACE_NAME = "ens37"

# 我们要重点攻击的 DHCP Option 代码列表
FUZZ_TARGETS = [1, 3, 6, 12, 15, 42, 51, 54, 60, 61, 119, 121, 252] 

# 每次 Fuzz 循环后的等待时间（秒）
DELAY_BETWEEN_PACKETS = 1 # 2 分钟
# ---

conf.iface = INTERFACE_NAME
MY_MAC = get_if_hwaddr(conf.iface)
print(f"[*] Fuzzer 将使用网卡: '{conf.iface}' (MAC: {MY_MAC})")
print(f"[*] Fuzzing 目标 Options: {FUZZ_TARGETS}")
print(f"[*] 每次循环后将等待 {DELAY_BETWEEN_PACKETS} 秒。")
print("[*] 请在另一个终端窗口中持续 ping 您的路由器以监控其状态。")
print("\n" + "="*50)

iteration_count = 1

while True:
    try:
        print(f"\n[+] --- Fuzzing 迭代: #{iteration_count} ---")
        TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)

        # --- 步骤 1: 正常的 Discover -> Offer ---
        dhcp_discover = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
            DHCP(options=[("message-type", "discover"), ("end")])
        )
        socket = conf.L2listen(type=ETH_P_ALL, iface=INTERFACE_NAME, filter="udp and (port 67 or 68)")
        
        sendp(dhcp_discover, iface=INTERFACE_NAME, verbose=False)

        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 1:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer: break
        
        if not dhcp_offer:
            print("[!] 未收到 OFFER, 跳过此次迭代。可能是网络波动。")
            socket.close()
            iteration_count += 1
            time.sleep(10)
            continue
        
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break

        if not server_ip:
            print("[!] 错误: 未能在 OFFER 包中找到 server_id。")
            socket.close()
            continue
        print(f"[*] 状态正常：已收到 OFFER, IP: {offered_ip}, Server: {server_ip}")
        
        # --- 步骤 2: 构造并发送畸形的 Request ---
        
        # Fuzzing 逻辑
        option_code = random.choice(FUZZ_TARGETS)
        malformed_length = random.randint(0, 255)
        malformed_value = os.urandom(malformed_length)
        print(f"    --> 注入目标: Option {option_code} (长度: {malformed_length})")
        
        # =================================================================
        # ====> 核心修正：手动构建所有 Options 的字节流 <====
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
        final_options = opt_msg_type + opt_req_addr + opt_server_id + malformed_option + opt_end
        
        dhcp_request_fuzz = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
            DHCP(options=final_options) # <--- 直接使用我们拼接好的字节流
        )
        
        print("[*] 发送畸形 Request 包...")
        sendp(dhcp_request_fuzz, iface=INTERFACE_NAME, verbose=False)
  
        
        # --- 步骤 3: 观察服务器的最终回应 (ACK/NAK) ---
        print("[*] 等待最终回应 (ACK/NAK)...")
        dhcp_ack = None
        start_time = time.time()
        while time.time() - start_time < 1:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
                    if any(opt[1] in [5, 6] for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack: break
        
        if dhcp_ack:
            msg_type = None
            for opt in dhcp_ack[DHCP].options:
                if opt[0] == 'message-type':
                    msg_type = opt[1]
                    break
            if msg_type == 5:
                print("[+] 服务器回应了 ACK。它似乎正常处理了我们的畸形请求。")
            elif msg_type == 6:
                print("[!] 服务器回应了 NAK (拒绝)。这是一个有意思的发现！")
        else:
            print("[!!!] 服务器没有回应！这可能意味着服务已崩溃！请立即检查 ping 的状态！")
            
        socket.close()
        iteration_count += 1
        
        # --- 等待，给路由器恢复时间 ---
        print(f"[*] 开始等待 {DELAY_BETWEEN_PACKETS} 秒...")
        time.sleep(DELAY_BETWEEN_PACKETS)

    except KeyboardInterrupt:
        print("\n[!] Fuzzing 被用户中断。正在退出...")
        if 'socket' in locals() and not socket.closed: socket.close()
        break
    except Exception as e:
        print(f"\n[!] 发生错误: {e}")
        if 'socket' in locals() and not socket.closed: socket.close()
        time.sleep(5)