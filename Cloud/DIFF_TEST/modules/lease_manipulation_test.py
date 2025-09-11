"""
DHCP 租约操纵测试模块

这个模块测试DHCP服务器对租约操作（特别是租约释放）的安全处理能力。
重点测试服务器在收到DHCPRELEASE消息时是否正确验证客户端身份。

根据RFC 2131规定：
- 服务器在收到DHCPRELEASE时，应该(SHOULD)验证ciaddr字段是否与发送请求的客户端匹配
- 具体而言，验证MAC地址(chaddr)是否为分配此IP的原始客户端
"""

from scapy.all import *
import logging
import random
import time
import os

def generate_random_mac():
    """生成随机MAC地址，保证第一个字节的低位为0（单播地址）"""
    mac = [random.randint(0, 255) & 0xFE] + [random.randint(0, 255) for _ in range(5)]
    return ':'.join('%02x' % b for b in mac)

def test_spurious_release_security(interface_name):
    """
    测试DHCP服务器对伪造DHCPRELEASE消息的安全处理能力
    
    测试策略:
    1. 使用真实MAC地址获取合法IP
    2. 使用伪造的MAC地址发送DHCPRELEASE，尝试释放该IP
    3. 使用真实MAC再次请求，验证服务器是否接受了伪造释放
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        # --- 1. 首先，用真实MAC获取一个合法的IP租约 ---
        real_mac = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        dhcp_discover = (
            Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(real_mac), xid=xid, flags='B') /
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
        
        # --- 发送 DHCP Request ---
        dhcp_request = (
            Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(real_mac), xid=xid, flags='B') /
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
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break
                
        if dhcp_ack is None:
            return {"status": "失败", "reason": "未收到 DHCP ACK"}
            
        legit_ip = dhcp_ack[BOOTP].yiaddr
        
        # 保存此IP作为第一次合法获取的IP
        original_ip = legit_ip
        
        # 关闭socket，清理资源
        socket.close()
        socket = None
        
        # --- 2. 构造一个伪造MAC的DHCPRELEASE ---
        # 生成一个不同于真实MAC的随机MAC
        fake_mac = generate_random_mac()
        while fake_mac == real_mac:  # 确保伪造MAC与真实MAC不同
            fake_mac = generate_random_mac()
        
        print(f"  -- 使用伪造MAC {fake_mac} 尝试释放IP {legit_ip}")
        
        # 发送DHCPRELEASE消息
        dhcp_release = (
            Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src=legit_ip, dst=server_ip) /  # 源IP设为已分配的IP
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(fake_mac), ciaddr=legit_ip) /  # 关键参数：伪造MAC + 合法IP
            DHCP(options=[
                ("message-type", "release"),
                ("server_id", server_ip),
                ("end")
            ])
        )
        
        # 直接发送伪造的释放请求
        sendp(dhcp_release, iface=interface_name, verbose=False)
        
        # 等待一会儿让服务器处理释放请求
        time.sleep(3)
        
        # --- 3. 使用真实MAC再次进行DORA流程，看是否能获得相同IP ---
        # 生成新的事务ID
        new_xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        dhcp_discover = (
            Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(real_mac), xid=new_xid, flags='B') /
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
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == new_xid:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer:
                break
                
        if dhcp_offer is None:
            return {
                "status": "部分成功",
                "reason": "在伪造释放后未收到新的OFFER",
                "original_ip": original_ip,
                "security_posture": "未知（服务器可能变得不稳定）",
                "security_score": 5
            }
            
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
        
        # --- 发送 DHCP Request ---
        dhcp_request = (
            Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(real_mac), xid=new_xid, flags='B') /
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
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == new_xid:
                    if any(opt[1] == 5 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break
                
        if dhcp_ack is None:
            return {
                "status": "部分成功",
                "reason": "在伪造释放后收到OFFER但未收到ACK",
                "original_ip": original_ip,
                "offered_ip_after_spoof": offered_ip,
                "security_posture": "未知（服务器可能变得不稳定）",
                "security_score": 5
            }
            
        # 获取第二次分配的IP
        new_ip = dhcp_ack[BOOTP].yiaddr
        
        # --- 4. 分析结果 ---
        same_ip = (original_ip == new_ip)
        
        if same_ip:
            security_posture = "安全 (服务器忽略了来自错误MAC的Release请求)"
            security_score = 10
            spoof_vulnerable = "否"
        else:
            security_posture = "不安全 (服务器接受了来自错误MAC的Release请求)"
            security_score = 1
            spoof_vulnerable = "是"
        
        return {
            "status": "成功",
            "original_ip": original_ip,
            "ip_after_spoof": new_ip,
            "same_ip_reused": "是" if same_ip else "否",
            "security_posture": security_posture,
            "spoof_release_vulnerable": spoof_vulnerable,
            "security_score": security_score,
            "fake_mac_used": fake_mac
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
