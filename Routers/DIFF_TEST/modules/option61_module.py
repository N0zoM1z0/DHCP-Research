"""
DHCP Option 61 (Client Identifier) 测试模块

这个模块测试路由器对客户端标识符的处理方式，包括:
1. 基本支持测试 - 路由器是否正确处理包含客户端标识符的请求
2. 标识符优先级测试 - 路由器是否优先使用客户端标识符而非MAC地址来分配IP
"""

from scapy.all import *
import logging
import random
import time
import os

def test_option61_basic(interface_name):
    """
    基本的Option 61测试 - 检查路由器是否接受并处理包含客户端标识符的请求
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # 构建一个标准格式的客户端标识符 (type=1 表示以太网，后跟MAC地址)
        client_id = b'\x01' + mac2str(mac_addr)
        
        # --- 发送带有Option 61的DHCP Discover ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("client_id", client_id),  # Option 61
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
        
        # --- 发送带有Option 61的DHCP Request ---
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("client_id", client_id),  # Option 61
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
            
        # --- 检查是否有服务器回复的Option 61 ---
        option61_in_ack = False
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'client_id':
                option61_in_ack = True
                break
                
        # --- 保存此IP地址用于后续测试 ---
        with open(f"/tmp/dhcp_option61_ip_{interface_name}.txt", "w") as f:
            f.write(dhcp_ack[BOOTP].yiaddr)
        
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "option61_support": "是",
            "option61_in_ack": "是" if option61_in_ack else "否",
            "client_id_type": "标准MAC地址型"
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()

def test_option61_custom(interface_name):
    """
    自定义客户端标识符测试 - 使用非MAC格式的客户端标识符
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # 使用自定义文本作为客户端标识符
        custom_client_id = b"this-is-my-custom-id"
        
        # --- 发送带有自定义Option 61的DHCP Discover ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("client_id", custom_client_id),  # 自定义Option 61
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
            return {"status": "失败", "reason": "未收到 DHCP OFFER", "custom_id_support": "否"}
            
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
                
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # --- 发送带有自定义Option 61的DHCP Request ---
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("client_id", custom_client_id),  # 自定义Option 61
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
            return {
                "status": "失败", 
                "reason": "未收到 DHCP ACK", 
                "custom_id_support": "否"
            }
        
        # 检查是否使用了之前使用标准格式分配的相同IP
        same_ip_as_standard = False
        try:
            with open(f"/tmp/dhcp_option61_ip_{interface_name}.txt", "r") as f:
                previous_ip = f.read().strip()
                same_ip_as_standard = (previous_ip == dhcp_ack[BOOTP].yiaddr)
        except:
            pass
            
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "custom_id_support": "是",
            "same_ip_as_standard": "是" if same_ip_as_standard else "否",
            "client_id_priority": "高" if same_ip_as_standard else "低"
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e), "custom_id_support": "未知"}
    finally:
        if socket:
            socket.close()

def test_option61_mac_change(interface_name):
    """
    MAC地址变化测试 - 使用相同的客户端标识符但不同的MAC地址
    测试路由器是否以客户端标识符为优先还是以MAC地址为准
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        real_mac = get_if_hwaddr(interface_name)
        
        # 生成一个随机的假MAC地址，但保证它与真实MAC不同
        fake_mac_bytes = [random.randint(0, 255) for _ in range(6)]
        # 确保第一个字节是偶数 (非多播地址)
        fake_mac_bytes[0] = fake_mac_bytes[0] & 0xFE  
        fake_mac = ':'.join([f"{b:02x}" for b in fake_mac_bytes])
        
        # 但客户端标识符使用真实MAC
        client_id = b'\x01' + mac2str(real_mac)
        
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送带有真实客户端标识符但假MAC地址的DHCP Discover ---
        dhcp_discover = (
            Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(fake_mac), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("client_id", client_id),  # 真实MAC的客户端标识符
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
            return {"status": "失败", "reason": "未收到 DHCP OFFER", "mac_change_handling": "拒绝"}
            
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
                
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # --- 发送带有真实客户端标识符但假MAC地址的DHCP Request ---
        dhcp_request = (
            Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(fake_mac), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("client_id", client_id),  # 真实MAC的客户端标识符
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
            return {
                "status": "失败", 
                "reason": "未收到 DHCP ACK", 
                "mac_change_handling": "拒绝"
            }
            
        # 检查是否分配了与之前基本测试相同的IP (即基于客户端标识符)
        same_ip_as_basic = False
        try:
            with open(f"/tmp/dhcp_option61_ip_{interface_name}.txt", "r") as f:
                previous_ip = f.read().strip()
                same_ip_as_basic = (previous_ip == dhcp_ack[BOOTP].yiaddr)
        except:
            pass
            
        # 分析服务器对MAC和客户端标识符的优先处理方式
        priority_analysis = "未知"
        if same_ip_as_basic:
            priority_analysis = "使用客户端标识符 (Option 61) 作为主要标识"
        else:
            priority_analysis = "使用MAC地址 (chaddr) 作为主要标识"
            
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "mac_change_handling": "接受",
            "real_mac": real_mac,
            "fake_mac": fake_mac,
            "client_id_priority": priority_analysis,
            "same_ip_as_basic": "是" if same_ip_as_basic else "否",
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e), "mac_change_handling": "未知"}
    finally:
        if socket:
            socket.close()

def test_option61(interface_name):
    """
    执行完整的Option 61测试套件，包括基本支持测试、自定义ID测试和MAC变更测试
    """
    # 1. 先测试基本支持
    basic_result = test_option61_basic(interface_name)
    
    # 如果基本测试失败，直接返回失败结果
    if basic_result["status"] != "成功":
        return {
            "status": "失败",
            "reason": "基本Option 61测试失败: " + basic_result.get("reason", "未知原因"),
            "option61_support": "否"
        }
    
    # 2. 测试自定义客户端标识符
    custom_result = test_option61_custom(interface_name)
    
    # 3. 测试MAC变更但客户端标识符不变
    mac_change_result = test_option61_mac_change(interface_name)
    
    # 汇总结果
    return {
        "status": "成功",
        "option61_support": "是",
        "assigned_ip": basic_result["assigned_ip"],
        "server_ip": basic_result["server_ip"],
        "standard_id_support": "是",
        "custom_id_support": custom_result.get("custom_id_support", "否"),
        "mac_change_handling": mac_change_result.get("mac_change_handling", "未知"),
        "client_id_priority": mac_change_result.get("client_id_priority", "未知"),
        "identification_policy": ("基于客户端标识符" if mac_change_result.get("same_ip_as_basic") == "是" 
                                else "基于MAC地址")
    }
