from scapy.all import *
import logging
import random
import time

def test_option114(interface_name):
    """
    测试 DHCP Option 114 (Captive Portal) 功能
    返回测试结果字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        # 我们在 DHCP options 中加入 "param_req_list" (Option 55)
        # 请求 Option 114 (Captive Portal)
        param_req_list = [1, 3, 114]
        
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
        option114_found = False
        option114_content = None
        
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'captive-portal':
                option114_found = True
                option114_content = opt[1]
                
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
                ("param_req_list", param_req_list),  # 再次请求 Option 114
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
            
        # 检查ACK包中是否也有Option 114
        option114_in_ack = False
        option114_ack_content = None
        
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'captive-portal':
                option114_in_ack = True
                option114_ack_content = opt[1]
        
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "option114_support": "是" if option114_found else "否",
            "option114_content": option114_content.decode('utf-8', errors='ignore') if option114_found and option114_content else "N/A",
            "option114_in_ack": "是" if option114_in_ack else "否",
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
