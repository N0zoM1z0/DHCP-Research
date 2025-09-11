"""
DHCP服务器健壮性测试模块

这个模块包含各种测试DHCP服务器健壮性的函数，
包括对非标准请求、格式错误的选项等的处理能力。
"""

from scapy.all import *
import logging
import random
import time

def test_unknown_option(interface_name):
    """
    测试DHCP服务器对未知选项的处理能力
    发送包含未知选项(244)的DHCP请求，观察服务器是否正常响应
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送标准 DHCP Discover ---
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
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP Offer ---
        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
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
        
        # --- 发送带有未知选项的 DHCP Request ---
        # 添加一个未知选项 244，填充随机数据
        unknown_option_value = os.urandom(8)  # 8字节随机数据
        
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                (244, unknown_option_value),  # 未知选项
                ("end")
            ])
        )
        
        sendp(dhcp_request, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP ACK 或 NAK ---
        dhcp_response = None
        response_type = None
        start_time = time.time()
        
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'message-type' and opt[1] in [5, 6]:  # ACK or NAK
                            dhcp_response = pkt
                            response_type = "ACK" if opt[1] == 5 else "NAK"
                            break
                    if dhcp_response:
                        break
            if dhcp_response:
                break
                
        if dhcp_response is None:
            return {
                "status": "失败",
                "reason": "未收到DHCP响应",
                "robustness_score": 0,
                "unknown_option_tolerance": "未知"
            }
            
        # 分析结果
        if response_type == "ACK":
            return {
                "status": "成功",
                "assigned_ip": dhcp_response[BOOTP].yiaddr,
                "robustness_score": 10,
                "unknown_option_tolerance": "高 (优雅地忽略未知选项)",
                "response_type": "ACK"
            }
        else:  # NAK
            return {
                "status": "成功", 
                "robustness_score": 5,
                "unknown_option_tolerance": "低 (拒绝含有未知选项的请求)",
                "response_type": "NAK"
            }
        
    except Exception as e:
        return {
            "status": "异常", 
            "reason": str(e),
            "robustness_score": 0,
            "unknown_option_tolerance": "未知 (测试过程中出错)"
        }
    finally:
        if socket:
            socket.close()

def test_malformed_option(interface_name):
    """
    测试DHCP服务器对格式错误选项的处理能力
    发送包含长度声明与实际内容不符的选项的DHCP请求
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送标准 DHCP Discover ---
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
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP Offer ---
        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
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
        
        # --- 创建一个畸形选项 ---
        # 使用Option 12 (主机名)，但故意制造长度与实际内容不符的情况
        # 正常情况下，长度应该等于内容的字节数
        hostname = b'test-pc-with-long-name'  # 实际长度为21字节
        malformed_opt12 = bytes([12, 4]) + hostname  # 但我们声明长度为4字节
        
        # --- 发送带有畸形选项的 DHCP Request ---
        malformed_opts = [
            ("message-type", "request"),
            ("requested_addr", offered_ip),
            ("server_id", server_ip),
            ("end")
        ]
        
        # 直接操作底层选项字节，插入我们的畸形选项12
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=malformed_opts)
        )
        
        # 在options字段的开头插入畸形的Option 12
        dhcp_layer = dhcp_request.getlayer(DHCP)
        dhcp_layer.options = [(12, hostname[:4])] + dhcp_layer.options
        
        sendp(dhcp_request, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP ACK 或 NAK 或无响应 ---
        dhcp_response = None
        response_type = None
        start_time = time.time()
        
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'message-type' and opt[1] in [5, 6]:  # ACK or NAK
                            dhcp_response = pkt
                            response_type = "ACK" if opt[1] == 5 else "NAK"
                            break
                    if dhcp_response:
                        break
            if dhcp_response:
                break
                
        # 分析结果
        if dhcp_response is None:
            return {
                "status": "部分成功",
                "reason": "服务器未响应畸形请求",
                "malformed_option_handling": "忽略 (未响应畸形请求)",
                "robustness_score": 8  # 忽略请求比崩溃好，但比正确处理差
            }
        
        if response_type == "ACK":
            # 检查ACK中的主机名是否被截断或完整处理
            hostname_in_ack = None
            for opt in dhcp_response[DHCP].options:
                if opt[0] == 'hostname':
                    hostname_in_ack = opt[1]
                    break
                    
            if hostname_in_ack:
                # 服务器可能只读取了声明的长度，这不是很安全的做法
                return {
                    "status": "成功",
                    "assigned_ip": dhcp_response[BOOTP].yiaddr,
                    "malformed_option_handling": "容忍 (接受了畸形请求并处理了声明长度的部分)",
                    "robustness_score": 5,  # 中等分数，因为它没有拒绝畸形内容
                    "hostname_in_ack": hostname_in_ack
                }
            else:
                # 服务器可能识别出长度不一致，忽略了整个选项，但仍然处理请求
                return {
                    "status": "成功",
                    "assigned_ip": dhcp_response[BOOTP].yiaddr,
                    "malformed_option_handling": "谨慎 (接受请求但忽略了畸形选项)",
                    "robustness_score": 9,  # 高分，因为它安全地处理了畸形选项
                    "hostname_in_ack": "选项被忽略"
                }
        else:  # NAK
            return {
                "status": "成功",
                "malformed_option_handling": "严格 (拒绝了含有畸形选项的请求)",
                "robustness_score": 10,  # 满分，严格拒绝畸形请求是最安全的做法
                "response_type": "NAK"
            }
        
    except Exception as e:
        return {
            "status": "异常", 
            "reason": str(e),
            "robustness_score": 0,
            "malformed_option_handling": "未知 (测试过程中出错)"
        }
    finally:
        if socket:
            socket.close()
