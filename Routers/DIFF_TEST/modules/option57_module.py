"""
DHCP Option 57 (Maximum DHCP Message Size) 测试模块

这个模块测试DHCP服务器是否尊重客户端声明的最大消息大小限制。
这对于内存受限的设备（如IoT设备、打印机等）非常重要。

RFC 2132规定：客户端可以使用Option 57声明自己能够处理的DHCP消息最大长度。
服务器应当尊重这一限制，确保返回的DHCP消息不超过客户端指定的大小。
"""

from scapy.all import *
import logging
import random
import time

def test_option57(interface_name):
    """
    测试DHCP服务器对Option 57 (Maximum DHCP Message Size)的处理
    
    测试策略:
    1. 发送一个包含Option 57的DHCP Discover，设置一个较小的最大消息长度
    2. 同时请求多个DHCP选项，引诱服务器返回一个"大包"
    3. 测量实际收到的DHCP Offer包的长度
    4. 比较实际长度和我们声明的最大长度
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    # 设置一个较小的最大消息大小 (单位: 字节)
    # 标准DHCP包通常至少300字节，我们设置一个稍小的值来测试
    max_size = 300
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # 请求大量选项，引诱服务器返回一个较大的包
        # 包含几乎所有常见选项
        param_req_list = [1, 3, 6, 12, 15, 28, 33, 43, 51, 53, 54, 55, 58, 59, 60, 61, 66, 67, 121, 249, 252]
        
        # --- 发送 DHCP Discover ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("max_dhcp_size", max_size),  # Option 57: 最大DHCP消息大小
                ("param_req_list", param_req_list),  # 请求大量选项
                ("hostname", "small-memory-device"),  # 暗示这是一个内存受限设备
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
            
        # --- 分析 DHCP OFFER 包 ---
        # 计算DHCP数据包的总长度
        offer_length = len(dhcp_offer)
        
        # 提取服务器ID和其他基本信息
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
        
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # 计算选项的数量，分析服务器回应
        option_count = 0
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple):
                option_count += 1
        
        # 判断服务器是否尊重最大消息大小
        respects_max_size = offer_length <= max_size
        
        # --- 完成DORA流程 ---
        # 发送标准的DHCP Request
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("max_dhcp_size", max_size),  # 保持一致性
                ("end")
            ])
        )
        
        sendp(dhcp_request, iface=interface_name, verbose=False)
        
        # 等待 DHCP ACK
        dhcp_ack = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break
                
        if dhcp_ack is None:
            return {
                "status": "部分成功", 
                "reason": "收到OFFER但未收到ACK",
                "offer_size": offer_length,
                "max_size_declared": max_size,
                "respects_max_size": "是" if respects_max_size else "否",
                "option_count": option_count
            }
        
        # 计算ACK包的长度
        ack_length = len(dhcp_ack)
        respects_max_size_ack = ack_length <= max_size
        
        # 分析服务器行为
        if respects_max_size and respects_max_size_ack:
            compliance = "完全遵循"
            compliance_details = "在OFFER和ACK中都尊重最大消息大小限制"
        elif respects_max_size:
            compliance = "部分遵循"
            compliance_details = "在OFFER中尊重但在ACK中忽略最大消息大小限制"
        elif respects_max_size_ack:
            compliance = "部分遵循"
            compliance_details = "在OFFER中忽略但在ACK中尊重最大消息大小限制"
        else:
            compliance = "不遵循"
            compliance_details = "完全忽略最大消息大小限制"
        
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "offer_size": offer_length,
            "ack_size": ack_length,
            "max_size_declared": max_size,
            "respects_max_size_offer": "是" if respects_max_size else "否",
            "respects_max_size_ack": "是" if respects_max_size_ack else "否",
            "option_count": option_count,
            "option57_compliance": compliance,
            "compliance_details": compliance_details,
            "size_optimization": "是" if (not respects_max_size and option_count < len(param_req_list)) else "否"
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
