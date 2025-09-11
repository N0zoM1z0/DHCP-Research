#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# intelligent_dhcp_fuzzer_final.py

from scapy.all import *
import logging
import random
import time
import os
import socket as std_socket

# --- 配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# !!! 重要：请将此处的网卡名称修改为您系统中用于测试的网卡 !!!
INTERFACE_NAME = "ens37"

# 每次 Fuzz 循环后的等待时间（秒）
DELAY_BETWEEN_PACKETS = 1
# ---

# [和之前相同的 Fuzzing 逻辑生成器]
OPTION_SPECS = {0: {'name': 'Pad', 'type': 'special_no_len_val'}, 1: {'name': 'Subnet Mask', 'type': 'ip_address', 'length': 4}, 2: {'name': 'Time Offset', 'type': 'fixed_bytes', 'length': 4}, 3: {'name': 'Router', 'type': 'ip_list'}, 4: {'name': 'Time Server', 'type': 'ip_list'}, 5: {'name': 'Name Server', 'type': 'ip_list'}, 6: {'name': 'Domain Server', 'type': 'ip_list'}, 7: {'name': 'Log Server', 'type': 'ip_list'}, 8: {'name': 'Quotes Server', 'type': 'ip_list'}, 9: {'name': 'LPR Server', 'type': 'ip_list'}, 10: {'name': 'Impress Server', 'type': 'ip_list'}}
def generate_fuzz_cases(option_code, spec):
    cases = []
    cases.append( ("空值 (长度为0)", bytes([option_code, 0])) )
    cases.append( ("超长随机值 (长度255)", bytes([option_code, 255]) + os.urandom(255)) )
    cases.append( ("超长空字节 (长度255)", bytes([option_code, 255]) + (b'\x00' * 255)) )
    opt_type = spec.get('type')
    if opt_type == 'special_no_len_val':
        cases.append( ("给Pad添加长度和值 (len=1, val=0x00)", bytes([option_code, 1, 0x00])) )
        cases.append( ("给Pad添加超长值", bytes([option_code, 255]) + os.urandom(255)) )
        return cases
    if 'length' in spec:
        length = spec['length']
        cases.append( (f"长度比规定少1 ({length-1}字节)", bytes([option_code, length - 1]) + os.urandom(length - 1)) )
        cases.append( (f"长度比规定多1 ({length+1}字节)", bytes([option_code, length + 1]) + os.urandom(length + 1)) )
        cases.append( (f"正确长度 ({length}字节), 内容全为0x00", bytes([option_code, length]) + (b'\x00' * length)) )
        cases.append( (f"正确长度 ({length}字节), 内容全为0xFF", bytes([option_code, length]) + (b'\xff' * length)) )
    if opt_type == 'ip_address':
        cases.append( ("IP地址为 0.0.0.0", bytes([option_code, 4]) + std_socket.inet_aton("0.0.0.0")) )
        cases.append( ("IP地址为 255.255.255.255", bytes([option_code, 4]) + std_socket.inet_aton("255.255.255.255")) )
    if opt_type == 'ip_list':
        cases.append( ("IP列表长度为3 (非4的倍数)", bytes([option_code, 3]) + os.urandom(3)) )
        cases.append( ("IP列表长度为5 (非4的倍数)", bytes([option_code, 5]) + os.urandom(5)) )
        bad_ip_list = std_socket.inet_aton("1.2.3.4") + b'\xDE\xAD\xBE'
        cases.append( ("IP列表包含不完整的IP (7字节)", bytes([option_code, 7]) + bad_ip_list) )
        long_ip_list = b''
        for _ in range(50):
            long_ip_list += std_socket.inet_aton(f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}")
        cases.append( ("包含50个IP地址的超长列表", bytes([option_code, 200]) + long_ip_list) )
    return cases


# =====================================================================
# ====> 这是严格按照第一个脚本的监听逻辑修复后的函数 <====
# =====================================================================
def perform_fuzz_iteration(malformed_option, case_description):
    """
    执行一次完整的 Discover -> Offer -> Malformed Request -> Response 流程
    """
    global iteration_count
    print(f"\n[+] --- Fuzzing 迭代: #{iteration_count} ---")
    print(f"    --> 测试用例: {case_description}")
    
    TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)
    socket = None # 预先定义 socket 变量
    try:
        # --- 步骤 1: 正常的 Discover -> Offer ---
        dhcp_discover = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
            DHCP(options=[("message-type", "discover"), ("end")])
        )
        # 创建一个覆盖整个交互过程的 socket
        socket = conf.L2listen(type=ETH_P_ALL, iface=INTERFACE_NAME, filter="udp and (port 67 or 68)")
        
        print("[*] 发送 Discover 包...")
        sendp(dhcp_discover, iface=INTERFACE_NAME, verbose=False)

        # --- 核心修改点 1: 复现第一个脚本的循环监听逻辑来捕获 Offer ---
        print("[*] 等待 Offer...")
        dhcp_offer = None
        start_time = time.time()
        # 监听 5 秒，持续尝试 sniff
        while time.time() - start_time < 5:
            packets = socket.sniff(timeout=1, count=5) # 每次最多嗅探1秒
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
                    # 检查消息类型是否为 Offer (2)
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break # 找到 Offer，跳出内层循环
            if dhcp_offer:
                break # 找到 Offer，跳出外层循环
        
        if not dhcp_offer:
            print("[!] 未收到 OFFER, 跳过此次测试。")
            # finally 块会处理 socket 关闭和迭代计数
            return

        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = dhcp_offer[IP].src
        print(f"[*] 状态正常：已收到 OFFER, IP: {offered_ip}, Server: {server_ip}")

        # --- 步骤 2: 构造并发送畸形的 Request ---
        opt_msg_type = b'\x35\x01\x03' # DHCP Request
        opt_req_addr = b'\x32\x04' + std_socket.inet_aton(offered_ip)
        opt_server_id = b'\x36\x04' + std_socket.inet_aton(server_ip)
        opt_end = b'\xff'
        
        final_options = opt_msg_type + opt_req_addr + opt_server_id + malformed_option + opt_end
        
        dhcp_request_fuzz = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
            DHCP(options=final_options)
        )
        
        print("[*] 发送畸形 Request 包...")
        sendp(dhcp_request_fuzz, iface=INTERFACE_NAME, verbose=False)
        
        # --- 步骤 3: 观察服务器的最终回应 (ACK/NAK) ---
        # --- 核心修改点 2: 再次使用循环监听逻辑来捕获 ACK/NAK ---
        print("[*] 等待最终回应 (ACK/NAK)...")
        final_response = None
        start_time = time.time()
        # 同样监听 5 秒
        while time.time() - start_time < 5:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == TRANSACTION_ID:
                    # 检查消息类型是否为 ACK (5) 或 NAK (6)
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
                print("[!] 服务器回应了 NAK (拒绝)。这是一个有意思的发现！")
        else:
            print("\n" + "!"*60)
            print("[!!!] CRITICAL: 服务器没有回应！这可能意味着服务已崩溃！")
            print(f"[!!!] 请立即检查 ping 的状态！触发问题的测试用例:")
            print(f"[!!!] {case_description}")
            print("!"*60 + "\n")
            time.sleep(30)
            
    finally:
        # 确保无论发生什么，socket 都会被关闭，并且执行后续等待
        if socket:
            socket.close()
        iteration_count += 1
        print(f"[*] 等待 {DELAY_BETWEEN_PACKETS} 秒...")
        time.sleep(DELAY_BETWEEN_PACKETS)


# ==============================================================================
# ====> 主程序入口 <====
# ==============================================================================

if __name__ == "__main__":
    try:
        conf.iface = INTERFACE_NAME
        MY_MAC = get_if_hwaddr(conf.iface)
    except Exception:
        print(f"[!] 错误: 无法找到名为 '{INTERFACE_NAME}' 的网卡。请检查配置。")
        exit(1)

    print("="*50)
    print("      DHCP 智能状态化 Fuzzer (最终版)")
    print("="*50)
    print(f"[*] Fuzzer 将使用网卡: '{conf.iface}' (MAC: {MY_MAC})")
    print(f"[*] 目标 Options: {list(OPTION_SPECS.keys())}")
    print("[*] 建议在另一个终端窗口中持续 ping 您的路由器以监控其状态。")
    print("\n[*] Fuzzer 将在 5 秒后启动...")
    time.sleep(5)
    
    iteration_count = 1
    
    try:
        # 完整的循环，会测试所有定义的 Option 和 Case
        while True:
            for code, spec in OPTION_SPECS.items():
                print("\n" + "="*60)
                print(f"[#] 开始对 Option {code} ({spec['name']}) 进行 Fuzzing 测试")
                print("="*60)
                
                fuzz_cases = generate_fuzz_cases(code, spec)
                for description, malformed_payload in fuzz_cases:
                    perform_fuzz_iteration(malformed_payload, f"Option {code} - {description}")
                    
    except KeyboardInterrupt:
        print("\n[!] Fuzzing 被用户中断。正在退出...")
    except Exception as e:
        print(f"\n[!] 发生严重错误: {e}")
        import traceback
        traceback.print_exc()

    print("\n[*] 所有已定义的测试用例均已完成。")