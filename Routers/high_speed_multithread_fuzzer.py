#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# high_speed_multithread_fuzzer.py

from scapy.all import *
import logging
import random
import time
import os
import socket as std_socket
import threading
import itertools # 用于生成唯一的 Transaction ID

# --- 配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# !!! 重要：请将此处的网卡名称修改为您系统中用于测试的网卡 !!!
INTERFACE_NAME = "ens37"

# Fuzzing 目标范围
FUZZ_TARGETS = list(range(256))

# 并发线程数：启动多少个 Fuzzer 实例并行工作。
# 请根据您的 CPU 性能和网络环境调整。从 4 或 8 开始。
# 注意：过高的数值可能会因为 Python 的 GIL 和网络栈限制而导致性能下降。
NUM_THREADS = 8

# 每个数据包的超时时间（秒），需要设置得很短以实现高速
PACKET_TIMEOUT = 0.5
# ---

# 全局线程安全计数器和锁
iteration_count = 0
counter_lock = threading.Lock()

# 用于为每个线程生成唯一的 Transaction ID，避免交叉干扰
# 使用 itertools.count() 保证线程安全和唯一性
xid_generator = itertools.count(start=random.randint(1, 10000))

def get_next_xid():
    return next(xid_generator)

def fuzz_worker(thread_id):
    """单个 Fuzzer 线程的工作函数"""
    global iteration_count
    
    # 尝试获取此线程的 MAC 地址
    try:
        # 为了让每个线程看起来像独立的客户端，我们可以在基础 MAC 上做微小改动
        # 注意：这需要网卡和驱动支持（混杂模式下通常可以）
        base_mac_bytes = mac2str(get_if_hwaddr(INTERFACE_NAME))
        # 修改 MAC 的最后一个字节
        local_mac_bytes = base_mac_bytes[:-1] + bytes([ (base_mac_bytes[-1] + thread_id) % 256 ])
        MY_MAC = str2mac(local_mac_bytes)
    except Exception:
        print(f"[Thread-{thread_id}] [!] 错误: 无法获取网卡 '{INTERFACE_NAME}' 的 MAC 地址。线程退出。")
        return

    while True:
        try:
            TRANSACTION_ID = get_next_xid() & 0xFFFFFFFF

            # --- 步骤 1: Discover -> Offer ---
            dhcp_discover = (
                Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
                DHCP(options=[("message-type", "discover"), ("end")])
            )

            # 使用 ans, unans = srp() 来发送和接收，比 L2listen 更适合快速、一次性的交互
            # srp 会自动处理发送、接收和匹配回复
            ans, unans = srp(dhcp_discover, iface=INTERFACE_NAME, timeout=PACKET_TIMEOUT, verbose=False, multi=False)

            if not ans:
                # print(f"[Thread-{thread_id}] [!] 未收到 OFFER。") # 在高速模式下可以注释掉，避免刷屏
                continue
            
            # ans 是一个包含 (发送包, 接收包) 对的列表
            dhcp_offer = ans[0][1] # 获取第一个应答包

            # 确认是 DHCP Offer
            if not (DHCP in dhcp_offer and any(opt[1] == 2 for opt in dhcp_offer[DHCP].options if opt[0] == 'message-type')):
                 continue

            offered_ip = dhcp_offer[BOOTP].yiaddr
            server_ip = dhcp_offer[IP].src

            # --- 步骤 2: 构造并发送畸形的 Request ---
            option_code = random.choice(FUZZ_TARGETS)
            malformed_length = random.randint(0, 255)
            malformed_value = os.urandom(malformed_length)
            
            opt_msg_type = b'\x35\x01\x03'
            opt_req_addr = b'\x32\x04' + std_socket.inet_aton(offered_ip)
            opt_server_id = b'\x36\x04' + std_socket.inet_aton(server_ip)
            malformed_option = bytes([option_code, malformed_length]) + malformed_value
            opt_end = b'\xff'
            final_options = opt_msg_type + opt_req_addr + opt_server_id + malformed_option + opt_end

            dhcp_request_fuzz = (
                Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags='B') /
                DHCP(options=final_options)
            )

            # 使用 sendp 发送，但不关心回应，因为我们的目标是看服务器是否会挂掉
            sendp(dhcp_request_fuzz, iface=INTERFACE_NAME, verbose=False)
            
            # --- 步骤 3: （可选）短暂监听最终回应 ---
            # 在高速模式下，我们主要通过外部 ping 来判断服务器状态，
            # 内部监听会降低速度。这里可以省略或使用极短的超时。
            
            # 更新全局计数器
            with counter_lock:
                iteration_count += 1

        except Exception as e:
            # 在高速模式下，错误很常见（例如，网络拥塞），可以忽略
            # print(f"[Thread-{thread_id}] 发生错误: {e}")
            pass

def monitor():
    """监控线程，定期打印发包速度"""
    last_count = 0
    last_time = time.time()
    while True:
        time.sleep(2) # 每 2 秒报告一次
        current_time = time.time()
        with counter_lock:
            current_count = iteration_count
        
        delta_count = current_count - last_count
        delta_time = current_time - last_time
        
        if delta_time > 0:
            pps = delta_count / delta_time
            print(f"[*] 当前速度: {pps:.2f} 次迭代/秒 (总计: {current_count} 次)")
        
        last_count = current_count
        last_time = current_time

# --- 主程序 ---
if __name__ == "__main__":
    try:
        MY_MAC = get_if_hwaddr(INTERFACE_NAME)
    except Exception:
        print(f"[!] 致命错误: 无法找到名为 '{INTERFACE_NAME}' 的网卡。请检查配置。")
        exit(1)

    print("="*60)
    print("       DHCP 全选项状态化 Fuzzer (多线程高速版)")
    print("="*60)
    print(f"[*] Fuzzer 将使用网卡: '{conf.iface}' (主 MAC: {MY_MAC})")
    print(f"[*] Fuzzing 目标 Options: 0-255 (所有可能性)")
    print(f"[*] 并发线程数: {NUM_THREADS}")
    print("\n" + "!"*60)
    print("!!! 极度危险：此脚本将以极高速度冲击 DHCP 服务器 !!!")
    print("!!!         请确保在完全隔离的环境中运行！         !!!")
    print("!"*60 + "\n")
    print("[*] 建议在另一个终端窗口中持续 ping 您的路由器以监控其状态。")
    print("   (例如: ping 192.168.1.1 -t)")
    print("\n[*] Fuzzer 将在 8 秒后启动...")
    time.sleep(8)

    threads = []
    
    # 启动监控线程
    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()

    # 启动 Fuzzer 工作线程
    for i in range(NUM_THREADS):
        thread = threading.Thread(target=fuzz_worker, args=(i,))
        thread.daemon = True # 设置为守护线程，主程序退出时它们也会退出
        threads.append(thread)
        thread.start()
        print(f"[*] 工作线程 Thread-{i} 已启动。")

    # 等待所有线程完成 (由于是无限循环，这里主要用于响应 Ctrl+C)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Fuzzing 被用户中断。正在退出...")