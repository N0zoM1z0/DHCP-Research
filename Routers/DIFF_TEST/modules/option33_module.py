"""
DHCP Option 33 (Static Route) 测试模块

这个模块测试路由器对Option 33的支持情况，该选项是早期用于配置静态路由的方法。
现在它已经被更灵活的Option 121 (Classless Static Route) 所取代，但许多服务器仍支持它。

RFC 2132规定：
- Option 33提供一系列的(目标IP, 路由器IP)对
- 每对占用8字节
- 仅支持传统的A/B/C类网络掩码，不支持无类域间路由(CIDR)
"""

from scapy.all import *
import logging
import random
import time

def test_option33(interface_name):
    """
    测试DHCP服务器对Option 33 (Static Route)的支持
    
    测试策略:
    1. 发送请求Option 33的DHCP DISCOVER
    2. 检查服务器是否在响应中提供此选项
    3. 与Option 121的结果对比，分析服务器的代码库年代
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        # 在 param_req_list 中请求 Option 33 (Static Route)
        param_req_list = [1, 3, 33]
        
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("param_req_list", param_req_list),
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
        option33_found = False
        option33_content = None
        
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'static-routes':
                option33_found = True
                option33_content = opt[1]
                
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
        
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # --- 继续完成DORA流程 ---
        # 发送 DHCP Request
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("param_req_list", param_req_list),  # 再次请求 Option 33
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
            return {"status": "失败", "reason": "未收到 DHCP ACK"}
            
        # 检查ACK包中是否也有Option 33
        option33_in_ack = False
        option33_ack_content = None
        
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'static-routes':
                option33_in_ack = True
                option33_ack_content = opt[1]
        
        # 解析静态路由数据（如果有）
        static_routes = []
        if option33_content:
            try:
                # Option 33的格式是一系列的(目标IP, 路由器IP)对
                i = 0
                while i < len(option33_content):
                    if i + 8 <= len(option33_content):  # 确保有足够的字节
                        dest_ip = '.'.join(str(b) for b in option33_content[i:i+4])
                        router_ip = '.'.join(str(b) for b in option33_content[i+4:i+8])
                        static_routes.append(f"{dest_ip} via {router_ip}")
                    i += 8
            except:
                pass
        
        # 计算代码年代的分析结果
        code_age = "现代 (仅支持Option 121)" if not option33_found else "老旧 (支持Option 33)"
        if option33_found:
            code_age_details = "路由器DHCP服务支持老式Option 33，代码库可能保留了向后兼容层"
        else:
            code_age_details = "路由器DHCP服务不支持老式Option 33，可能是较新的代码库"
        
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "option33_support": "是" if option33_found else "否",
            "static_routes": static_routes if static_routes else "N/A",
            "option33_in_ack": "是" if option33_in_ack else "否",
            "code_age": code_age,
            "code_age_details": code_age_details,
            "backward_compatibility": "高" if option33_found else "低"
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
