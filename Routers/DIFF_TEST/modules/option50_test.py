"""
DHCP Option 50 (Requested IP Address) 在 DISCOVER 中的测试模块

这个模块测试DHCP服务器如何处理在DHCPDISCOVER报文中包含的Option 50请求。
在标准流程中，Option 50通常在DHCPREQUEST中使用，但RFC也允许客户端在DISCOVER阶段
"建议"一个IP地址，服务器可以选择尊重或忽略这个建议。

测试目的:
- 检测服务器对客户端IP建议的处理策略
- 揭示服务器内部IP分配逻辑的可预测性
- 评估服务器的策略是否可能被滥用
"""

from scapy.all import *
import logging
import random
import time
import socket

def is_valid_ip(ip_str):
    """检查IP地址格式是否有效"""
    try:
        socket.inet_aton(ip_str)
        return True
    except:
        return False

def ip_increment(ip_str, increment=1):
    """将IP地址递增指定值"""
    try:
        # 将IP地址转换为整数
        ip_parts = list(map(int, ip_str.split('.')))
        ip_int = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        
        # 递增
        ip_int += increment
        
        # 转回点分十进制
        new_ip = [
            (ip_int >> 24) & 0xFF,
            (ip_int >> 16) & 0xFF,
            (ip_int >> 8) & 0xFF,
            ip_int & 0xFF
        ]
        
        return '.'.join(map(str, new_ip))
    except:
        return ip_str

def test_option50_in_discover(interface_name):
    """
    测试DHCP服务器对Discover中包含Option 50的处理
    
    测试策略:
    1. 执行一次标准DORA获取合法IP
    2. 释放此IP，记录它的值
    3. 再次执行DORA，但在Discover中包含Option 50，请求特定IP
    4. 分析服务器是否尊重请求，以及其分配策略
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        # --- 1. 第一轮DORA：获取参考IP ---
        mac_addr = get_if_hwaddr(interface_name)
        xid1 = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid1, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("end")
            ])
        )
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP Offer ---
        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid1:
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
            BOOTP(chaddr=mac2str(mac_addr), xid=xid1, flags='B') /
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
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid1:
                    if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break
                
        if dhcp_ack is None:
            return {"status": "失败", "reason": "未收到 DHCP ACK"}
        
        # 获取第一次分配的IP
        reference_ip = dhcp_ack[BOOTP].yiaddr
        print(f"  -- 第一次获取到IP: {reference_ip}")
        
        # --- 2. 发送DHCP Release释放此IP ---
        dhcp_release = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src=reference_ip, dst=server_ip) /  # 源IP设为已分配的IP
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), ciaddr=reference_ip) /
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", server_ip),
                ("end")
            ])
        )
        
        # 发送释放请求
        sendp(dhcp_release, iface=interface_name, verbose=False)
        print(f"  -- 已释放IP {reference_ip}")
        
        # 关闭旧socket
        socket.close()
        socket = None
        
        # 等待一会儿让服务器处理释放
        time.sleep(3)
        
        # --- 3. 构造和发送包含Option 50的DHCP Discover ---
        # 尝试请求与之前相同的IP
        requested_ip = reference_ip
        print(f"  -- 尝试在DISCOVER中请求特定IP: {requested_ip}")
        
        xid2 = random.randint(1, 0xFFFFFFFF)
        
        # 发送带有Option 50的DHCP Discover
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid2, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("requested_addr", requested_ip),  # Option 50: 请求特定IP
                ("end")
            ])
        )
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP Offer ---
        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid2:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer:
                break
                
        if dhcp_offer is None:
            return {
                "status": "失败", 
                "reason": "在使用Option 50后未收到OFFER",
                "reference_ip": reference_ip,
                "requested_ip": requested_ip
            }
            
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
            BOOTP(chaddr=mac2str(mac_addr), xid=xid2, flags='B') /
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
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid2:
                    if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break
                
        if dhcp_ack is None:
            return {
                "status": "失败", 
                "reason": "在使用Option 50后未收到ACK",
                "reference_ip": reference_ip,
                "requested_ip": requested_ip,
                "offered_ip": offered_ip
            }
            
        # 获取最终分配的IP
        final_ip = dhcp_ack[BOOTP].yiaddr
        
        # --- 4. 进行第三轮测试: 尝试请求一个有可能不在DHCP范围内的IP ---
        # 关闭旧socket
        socket.close()
        socket = None
        
        # 释放刚刚获得的IP
        dhcp_release = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src=final_ip, dst=server_ip) /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), ciaddr=final_ip) /
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", server_ip),
                ("end")
            ])
        )
        
        sendp(dhcp_release, iface=interface_name, verbose=False)
        
        # 等待一会儿让服务器处理释放
        time.sleep(3)
        
        # 尝试请求一个"边界"IP地址
        # 我们将参考IP的最后一个数字增加100，这可能会超出DHCP范围
        edge_ip = ip_increment(reference_ip, 100)
        print(f"  -- 尝试在DISCOVER中请求边界IP: {edge_ip}")
        
        xid3 = random.randint(1, 0xFFFFFFFF)
        
        # 发送带有"边界"IP的Option 50 DHCP Discover
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid3, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("requested_addr", edge_ip),  # Option 50: 请求可能超出范围的IP
                ("end")
            ])
        )
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # 等待DHCP Offer
        dhcp_offer_edge = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid3:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer_edge = pkt
                        break
            if dhcp_offer_edge:
                break
                
        edge_test_result = {}
        if dhcp_offer_edge:
            edge_offered_ip = dhcp_offer_edge[BOOTP].yiaddr
            edge_test_result = {
                "edge_request_successful": "是",
                "requested_edge_ip": edge_ip,
                "offered_edge_ip": edge_offered_ip,
                "honored_edge_request": "是" if edge_offered_ip == edge_ip else "否"
            }
        else:
            edge_test_result = {
                "edge_request_successful": "否",
                "requested_edge_ip": edge_ip,
                "edge_request_reason": "未收到OFFER，可能IP不在服务器范围内"
            }
        
        # --- 5. 分析结果 ---
        # 判断服务器是否尊重Option 50请求
        request_honored = (final_ip == requested_ip)
        
        if request_honored:
            policy = "尊重客户端请求 (分配了请求的IP)"
            policy_score = 5  # 中等分数：既方便客户端，也可能被利用
        else:
            policy = "忽略客户端请求 (分配了其他IP)"
            policy_score = 8  # 较高分数：更安全，但对合法客户端可能不太方便
            
        # 根据边界测试进一步分析安全性
        if edge_test_result.get("edge_request_successful") == "是" and edge_test_result.get("honored_edge_request") == "是":
            policy_detail = "服务器接受任何客户端建议的IP地址，包括可能超出正常范围的地址"
            security_posture = "风险较高 (可能被利用指定任意IP)"
            security_score = 2
        elif request_honored:
            policy_detail = "服务器接受客户端建议的IP，但仅限于合理范围内"
            security_posture = "中等 (接受先前分配的IP建议)"
            security_score = 6
        else:
            policy_detail = "服务器基于自身策略分配IP，忽略客户端建议"
            security_posture = "安全 (完全控制IP分配)"
            security_score = 9
        
        return {
            "status": "成功",
            "reference_ip": reference_ip,
            "requested_ip": requested_ip,
            "assigned_ip": final_ip,
            "request_honored": "是" if request_honored else "否",
            "option50_policy": policy,
            "policy_detail": policy_detail,
            "security_posture": security_posture,
            "security_score": security_score,
            "policy_score": policy_score,
            **edge_test_result
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
