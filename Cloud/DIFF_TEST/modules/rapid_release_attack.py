from scapy.all import *
import logging
import random
import time
import sys

# --- Scapy 日志和输出配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

def test_rapid_release_attack(interface_name, num_cycles=10):
    """
    测试快速释放和重新申请IP，对服务器状态机进行压力测试
    :param interface_name: 要使用的网络接口名称
    :param num_cycles: 尝试攻击的循环次数
    :return: 测试结果字典
    """
    print(f"[*] 开始在接口 {interface_name} 上进行快速释放/重申请攻击测试...")
    print(f"[*] 将执行 {num_cycles} 个循环。")

    socket = None
    try:
        mac_addr = get_if_hwaddr(interface_name)
        assigned_ips_log = []
        unique_ips = set()
        response_times = []
        release_to_assign_delays = []
        
        # 初始化测试结果
        result = {
            "status": "成功",
            "cycles_completed": 0,
            "unique_ips_assigned": 0,
            "address_reuse_rate": 0,
            "avg_response_time": 0,
            "max_response_time": 0,
            "server_crashed": "否",
        }
        
        # 创建套接字用于捕获响应
        socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=interface_name,
            filter="udp and (port 67 or port 68)"
        )

        for i in range(num_cycles):
            cycle_start_time = time.time()
            xid = random.randint(1, 0xFFFFFFFF)
            print(f"\n--- 第 {i + 1}/{num_cycles} 轮 ---")

            # 1. 获取IP地址 - DISCOVER
            print("[+] 发送 DHCP Discover...")
            dhcp_discover = (
                Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac_addr), xid=xid) /
                DHCP(options=[("message-type", "discover"), ("end")])
            )
            
            discover_time = time.time()
            sendp(dhcp_discover, iface=interface_name, verbose=False)

            # 等待 DHCP Offer
            dhcp_offer = None
            start_time = time.time()
            while time.time() - start_time < 5:
                packets = socket.sniff(timeout=1, count=5)
                for pkt in packets:
                    if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                        if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                            dhcp_offer = pkt
                            break
                if dhcp_offer:
                    break

            if dhcp_offer is None:
                print("[!] 未收到 DHCP Offer，服务器可能无响应。")
                result["server_crashed"] = "可能" if i > 0 else "否"
                break

            offer_time = time.time() - discover_time
            print(f"[*] 收到 DHCP Offer 响应时间: {offer_time:.3f}秒")
            
            # 2. 从 Offer 包中提取信息
            offered_ip = dhcp_offer[BOOTP].yiaddr
            server_id = None
            for opt in dhcp_offer[DHCP].options:
                if opt[0] == 'server_id':
                    server_id = opt[1]
                    break
            
            if not server_id:
                print("[!] Offer 包中未找到 'server_id'，无法继续。")
                continue

            # 3. 发送 REQUEST
            print(f"[+] 发送 DHCP Request 请求 IP: {offered_ip}...")
            dhcp_request = (
                Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac_addr), xid=xid) /
                DHCP(options=[
                    ("message-type", "request"),
                    ("server_id", server_id),
                    ("requested_addr", offered_ip),
                    ("end")
                ])
            )
            
            request_time = time.time()
            sendp(dhcp_request, iface=interface_name, verbose=False)
            
            # 等待 DHCP ACK
            dhcp_ack = None
            start_time = time.time()
            while time.time() - start_time < 5:
                packets = socket.sniff(timeout=1, count=5)
                for pkt in packets:
                    if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                        if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                            dhcp_ack = pkt
                            break
                if dhcp_ack:
                    break
                    
            if dhcp_ack is None:
                print("[!] 未收到 DHCP ACK，服务器可能无响应。")
                result["server_crashed"] = "可能" if i > 0 else "否"
                break
                
            ack_time = time.time() - request_time
            print(f"[*] 收到 DHCP ACK 响应时间: {ack_time:.3f}秒")
            
            assigned_ip = dhcp_ack[BOOTP].yiaddr
            assigned_ips_log.append(assigned_ip)
            unique_ips.add(assigned_ip)
            
            # 记录响应时间
            total_time = time.time() - discover_time
            response_times.append(total_time)
            print(f"[*] 成功获取 IP: {assigned_ip} 总用时: {total_time:.3f}秒")
            
            # 4. 立即释放该IP地址
            print(f"[+] 立即发送 DHCP Release 释放地址 {assigned_ip}...")
            dhcp_release = (
                Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
                IP(src=assigned_ip, dst=server_id) /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac_addr), ciaddr=assigned_ip, xid=random.randint(1, 0xFFFFFFFF)) /
                DHCP(options=[
                    ("message-type", "release"),
                    ("server_id", server_id),
                    ("end")
                ])
            )
            
            release_time = time.time()
            sendp(dhcp_release, iface=interface_name, verbose=False)
            
            # 不等待任何响应，直接计算这次循环的时间
            cycle_time = time.time() - cycle_start_time
            release_to_assign_delays.append(cycle_time)
            print(f"[*] 第 {i + 1} 轮完成, 用时: {cycle_time:.3f}秒")
            
            # 记录成功完成的循环数
            result["cycles_completed"] = i + 1
            
            # 微小延迟，避免绝对并发可能导致的网络设备或系统负载问题
            time.sleep(0.1)

        # 分析测试结果
        if response_times:
            result["avg_response_time"] = round(sum(response_times) / len(response_times), 3)
            result["max_response_time"] = round(max(response_times), 3)
        
        result["unique_ips_assigned"] = len(unique_ips)
        result["assigned_ips"] = list(assigned_ips_log)
        
        # 计算IP重用率 = (总循环数 - 唯一IP数) / 总循环数
        if result["cycles_completed"] > 0:
            reuse_rate = (result["cycles_completed"] - result["unique_ips_assigned"]) / result["cycles_completed"]
            result["address_reuse_rate"] = round(reuse_rate * 100, 1)  # 转换为百分比
            
        # 状态机弹性评分 (1-10分，分数越高表示状态机越健壮)
        state_machine_score = calculate_state_machine_resilience(
            result["unique_ips_assigned"],
            result["cycles_completed"],
            result["avg_response_time"],
            result["server_crashed"]
        )
        
        result["state_machine_resilience"] = state_machine_score
        
        # 安全评估
        if state_machine_score >= 8:
            result["security_assessment"] = "高度安全 - 状态机非常健壮"
        elif state_machine_score >= 6:
            result["security_assessment"] = "较安全 - 状态机基本健壮"
        elif state_machine_score >= 4:
            result["security_assessment"] = "一般 - 状态机有改进空间"
        else:
            result["security_assessment"] = "不安全 - 状态机脆弱"
        
        print("\n[*] 测试完成。")
        print(f"[*] 在测试期间，服务器共分配了 {len(unique_ips)} 个不同的 IP 地址")
        print(f"[*] IP重用率: {result['address_reuse_rate']}% (越高越好，表示服务器能有效回收IP)")
        print(f"[*] 平均响应时间: {result['avg_response_time']}秒")
        print(f"[*] 状态机弹性评分: {state_machine_score}/10")
        
        return result

    except Exception as e:
        print(f"\n[!] 测试过程中发生异常: {e}")
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()

def calculate_state_machine_resilience(unique_ips, total_cycles, avg_response_time, server_crashed):
    """计算DHCP服务器状态机弹性评分(1-10)"""
    if server_crashed == "是" or server_crashed == "可能":
        return 1  # 服务器崩溃是最严重的问题
    
    if total_cycles == 0:
        return 1  # 无法完成任何测试
    
    # 1. IP重用率分数 (最高4分)
    # 理想情况下，服务器应该重用同一个IP，而不是每次分配新IP
    reuse_rate = (total_cycles - unique_ips) / total_cycles
    reuse_score = min(reuse_rate * 4, 4)
    
    # 2. 响应时间分数 (最高3分)
    # 响应时间越短越好，我们认为0.5秒以内是最佳的
    time_score = 3 * max(0, 1 - (avg_response_time / 2))
    
    # 3. 稳定性分数 (最高3分)
    # 完成所有周期为满分
    stability = total_cycles / max(unique_ips, 1)  # 避免除零
    stability_score = min(stability * 1.5, 3)
    
    # 总分 = IP重用 + 响应时间 + 稳定性
    total_score = reuse_score + time_score + stability_score
    
    return round(total_score, 1)