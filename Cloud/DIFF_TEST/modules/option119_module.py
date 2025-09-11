"""
DHCP Option 119 (Domain Search) 测试模块

这个模块测试路由器对Option 119的支持情况，该选项用于配置DNS域名搜索列表。
当客户端进行DNS查询且未提供完全限定域名时，系统会尝试使用这些后缀逐个查询。

RFC 3397规定：
- Option 119包含一个或多个DNS域名搜索后缀
- 格式使用DNS编码的域名列表，类似于Option 15但允许多个域名
- 常见值如："example.com"，"corp.example.com"，"branch.corp.example.com"
"""

from scapy.all import *
import logging
import random
import time
import struct
import binascii
import re

def parse_domain_search_list(option_data):
    """
    解析Option 119的域名搜索列表
    
    Option 119使用压缩的DNS格式编码，需要特殊解析
    
    参数:
    option_data: Option 119的原始字节
    
    返回:
    list: 解析后的域名列表
    """
    domains = []
    
    try:
        # 简单解析方法：查找字符串中的可打印字符
        current_domain = ""
        for byte in option_data:
            if 32 <= byte <= 126:  # 可打印ASCII字符
                current_domain += chr(byte)
            elif byte == 0:  # 域名分隔符
                if current_domain:
                    domains.append(current_domain)
                    current_domain = ""
        
        if current_domain:  # 添加最后一个域名
            domains.append(current_domain)
        
        # 如果简单方法失败，尝试寻找更明显的域名模式
        if not domains:
            text = option_data.decode('utf-8', errors='ignore')
            domain_pattern = re.compile(r'[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}')
            domains = domain_pattern.findall(text)
        
        # 清理域名（移除多余的点和空格）
        cleaned_domains = []
        for domain in domains:
            domain = domain.strip().strip('.')
            if domain and '.' in domain:
                cleaned_domains.append(domain)
        
        return cleaned_domains
    
    except Exception as e:
        print(f"  -- 域名解析错误: {e}")
        return ["<解析错误>"]

def test_option119(interface_name):
    """
    测试DHCP服务器对Option 119 (Domain Search)的支持
    
    测试策略:
    1. 发送请求Option 119的DHCP DISCOVER
    2. 分析服务器的响应，检查是否返回域名搜索列表
    3. 同时请求Option 15 (Domain Name)，比较两者的内容
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        # 在param_req_list中同时请求Option 15和119
        param_req_list = [1, 3, 6, 15, 119]
        
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
        option15_found = False
        option15_content = None
        option119_found = False
        option119_content = None
        
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple):
                if opt[0] == 'domain':  # Option 15
                    option15_found = True
                    option15_content = opt[1]
                elif opt[0] == 'domain-search':  # Option 119
                    option119_found = True
                    option119_content = opt[1]
                
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
                ("param_req_list", param_req_list),  # 再次请求Option 15和119
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
            
        # 检查ACK包中的Option 15和119
        option15_in_ack = False
        option15_ack_content = None
        option119_in_ack = False
        option119_ack_content = None
        
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple):
                if opt[0] == 'domain':  # Option 15
                    option15_in_ack = True
                    option15_ack_content = opt[1]
                elif opt[0] == 'domain-search':  # Option 119
                    option119_in_ack = True
                    option119_ack_content = opt[1]
        
        # 使用ACK中的值（如果有）否则使用OFFER中的值
        final_option15 = option15_ack_content if option15_in_ack else option15_content
        final_option119 = option119_ack_content if option119_in_ack else option119_content
        
        # 解析域名搜索列表
        search_domains = None
        if final_option119:
            search_domains = parse_domain_search_list(final_option119)
        
        # 分析DNS完整度
        dns_integration = "低"
        if option119_found:
            dns_integration = "高 (支持域名搜索列表)"
        elif option15_found:
            dns_integration = "中 (仅支持单一域名)"
            
        # 确定是否提供了多域名搜索
        multi_domain_support = "否"
        if search_domains and len(search_domains) > 1:
            multi_domain_support = "是"
        
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "option15_support": "是" if option15_found else "否",
            "domain_name": final_option15 if final_option15 else "N/A",
            "option119_support": "是" if option119_found else "否",
            "domain_search_list": search_domains if search_domains else "N/A",
            "dns_integration": dns_integration,
            "multi_domain_support": multi_domain_support,
            "dns_flexibility": "高" if multi_domain_support == "是" else "低"
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
