"""
DHCP Option 42 (NTP Servers) 测试模块

这个模块测试路由器对NTP服务器地址请求的处理方式。
NTP服务器允许客户端同步网络时间。
"""

from scapy.all import *
import logging
import random
import time
import socket

def is_private_ip(ip_str):
    """
    检查IP地址是否为私有地址
    
    参数:
    ip_str: IP地址字符串
    
    返回:
    bool: 如果是私有地址则为True，否则为False
    """
    try:
        ip = socket.inet_aton(ip_str)
        # 转换为整数
        ip_int = int.from_bytes(ip, byteorder='big')
        
        # 检查是否为私有地址范围
        if ((ip_int >= 0x0A000000 and ip_int <= 0x0AFFFFFF) or    # 10.0.0.0/8
            (ip_int >= 0xAC100000 and ip_int <= 0xAC1FFFFF) or    # 172.16.0.0/12
            (ip_int >= 0xC0A80000 and ip_int <= 0xC0A8FFFF)):     # 192.168.0.0/16
            return True
        return False
    except:
        return False

def is_router_address(ip_str, network_base="192.168"):
    """检查IP是否可能是路由器地址(192.168.x.1或其他常见模式)"""
    return ip_str.startswith(network_base) and ip_str.endswith('.1')

def analyze_ntp_servers(server_list):
    """
    分析NTP服务器地址列表，提供关于它们的更多信息
    
    参数:
    server_list: NTP服务器IP地址列表
    
    返回:
    dict: 分析结果
    """
    if not server_list:
        return {
            "count": 0,
            "analysis": "未提供NTP服务器"
        }
        
    private_ips = []
    public_ips = []
    router_ips = []
    
    for ip in server_list:
        if is_router_address(ip):
            router_ips.append(ip)
        elif is_private_ip(ip):
            private_ips.append(ip)
        else:
            public_ips.append(ip)
    
    result = {
        "count": len(server_list),
        "servers": server_list,
        "private_count": len(private_ips),
        "public_count": len(public_ips),
        "router_count": len(router_ips),
        "private_servers": private_ips,
        "public_servers": public_ips,
        "router_servers": router_ips,
    }
    
    # 生成分析说明
    if len(router_ips) > 0:
        result["router_as_ntp"] = "是"
        result["analysis"] = "路由器自身提供NTP服务"
    elif len(private_ips) > 0 and len(public_ips) == 0:
        result["router_as_ntp"] = "否"
        result["analysis"] = "提供内网NTP服务器"
    elif len(public_ips) > 0:
        result["router_as_ntp"] = "否"
        result["analysis"] = "提供公网NTP服务器"
        # 检查是否是标准公共NTP服务器
        common_ntp = ["pool.ntp.org", "time.apple.com", "time.windows.com", 
                      "time.google.com", "ntp.aliyun.com", "ntp.tencent.com"]
        result["using_common_ntp"] = "未知"
        for server in common_ntp:
            try:
                ips = socket.gethostbyname_ex(server)[2]
                for ip in ips:
                    if ip in public_ips:
                        result["using_common_ntp"] = "是"
                        result["ntp_provider"] = server
                        break
            except:
                continue
    
    return result

def test_option42(interface_name):
    """
    测试 DHCP Option 42 (NTP Servers) 功能
    返回测试结果字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        # 我们在 DHCP options 中加入 "param_req_list" (Option 55)
        # 请求 Option 42 (NTP Servers)
        param_req_list = [1, 3, 6, 42]  # 标准选项 + NTP服务器
        
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
        option42_found = False
        ntp_servers = []
        
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'ntp':
                option42_found = True
                # NTP服务器可能有多个，以列表形式返回
                if isinstance(opt[1], list):
                    ntp_servers = opt[1]
                else:
                    ntp_servers = [opt[1]]
                
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
                ("param_req_list", param_req_list),  # 再次请求 Option 42
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
            
        # 检查ACK包中是否也有Option 42
        option42_in_ack = False
        ntp_servers_in_ack = []
        
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'ntp':
                option42_in_ack = True
                # NTP服务器可能有多个
                if isinstance(opt[1], list):
                    ntp_servers_in_ack = opt[1]
                else:
                    ntp_servers_in_ack = [opt[1]]
                    
        # 如果ACK中有NTP服务器，使用这个作为最终结果
        final_ntp_servers = ntp_servers_in_ack if option42_in_ack else ntp_servers
        
        # 分析NTP服务器配置
        ntp_analysis = analyze_ntp_servers(final_ntp_servers)
        
        result = {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "option42_support": "是" if option42_found or option42_in_ack else "否",
            "ntp_servers": final_ntp_servers if final_ntp_servers else "N/A",
            "ntp_server_count": len(final_ntp_servers),
            "option42_in_offer": "是" if option42_found else "否",
            "option42_in_ack": "是" if option42_in_ack else "否",
        }
        
        # 将分析结果合并到返回值
        if ntp_analysis:
            for key, value in ntp_analysis.items():
                if key != 'servers':  # 避免重复
                    result[f"ntp_{key}"] = value
        
        return result
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
