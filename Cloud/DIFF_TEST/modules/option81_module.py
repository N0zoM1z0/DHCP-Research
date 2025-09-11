from scapy.all import *
import logging
import random
import time

def encode_fqdn(fqdn):
    """
    将一个标准的域名字符串编码为DNS线格式 (wire format)。
    例如: "my-pc.local" -> b'\x05my-pc\x05local\x00'
    """
    labels = fqdn.strip('.').split('.')
    encoded = b''
    for label in labels:
        encoded += bytes([len(label)]) + label.encode('ascii')
    return encoded + b'\x00'  # 以空字节结尾

def test_option81(interface_name, test_fqdn="my-fqdn-pc.local"):
    """
    测试 DHCP Option 81 (FQDN) 功能
    返回测试结果字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        # 构建 Option 81 的值
        dhcp_opt_81_flags = 0b00000101  # S=1, E=1, O=0, N=0
        dhcp_opt_81_rcode1 = 0
        dhcp_opt_81_rcode2 = 0
        encoded_fqdn = encode_fqdn(test_fqdn)
        
        option_81_value = bytes([dhcp_opt_81_flags, dhcp_opt_81_rcode1, dhcp_opt_81_rcode2]) + encoded_fqdn
        
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        param_req_list = [1, 3, 6, 15, 81]  # 请求服务器返回 Option 81
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("param_req_list", param_req_list),
                (81, option_81_value),  # Option 81 FQDN
                ("end")
            ])
        )
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or 68)")
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
                (81, option_81_value),  # 再次在 Request 中声明 FQDN
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
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break
                
        if dhcp_ack is None:
            return {"status": "失败", "reason": "未收到 DHCP ACK"}
            
        final_ip = dhcp_ack[BOOTP].yiaddr
        
        # --- 验证 DNS 记录 ---
        dns_query = IP(dst=server_ip)/UDP()/DNS(rd=1, qd=DNSQR(qname=test_fqdn))
        dns_response = sr1(dns_query, timeout=5, verbose=False)
        
        fqdn_registered = False
        resolved_ip = None
        
        if dns_response and dns_response.haslayer(DNS) and dns_response.haslayer(DNSRR):
            resolved_ip = dns_response[DNSRR].rdata
            fqdn_registered = (resolved_ip == final_ip)
        
        return {
            "status": "成功",
            "assigned_ip": final_ip,
            "fqdn": test_fqdn,
            "server_ip": server_ip,
            "dns_registered": "是" if fqdn_registered else "否",
            "resolved_ip": resolved_ip if resolved_ip else "N/A",
            "option81_support": "是" if any(isinstance(opt, tuple) and opt[0] == 81 for opt in dhcp_ack[DHCP].options) else "否"
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
