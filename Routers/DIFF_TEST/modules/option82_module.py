"""
DHCP Option 82 (Relay Agent Information) 测试模块

这个模块测试DHCP服务器对Option 82的处理，该选项通常只应出现在DHCP中继代理转发的消息中。
当客户端直接发送包含此选项的请求时，测试DHCP服务器的安全处理能力和RFC规范遵守程度。

按照RFC 3046规范：
- Option 82应该由DHCP中继代理添加，而不是客户端
- 客户端发送的包中如果包含Option 82，服务器应当谨慎处理，可能的处理方式包括：
  1. 忽略该选项并正常处理请求（宽容模式）
  2. 丢弃请求（严格模式，可能认为这是欺骗尝试）
  3. 将此选项原样返回（不规范但常见的实现）
"""

from scapy.all import *
import logging
import random
import time

def test_option82(interface_name):
    """
    测试DHCP服务器对客户端发送的Option 82的处理
    
    Option 82包含两个常见的子选项:
    - 子选项1: Circuit ID (标识客户连接的电路)
    - 子选项2: Remote ID (标识中继代理)
    
    测试策略:
    1. 发送一个包含Option 82的DHCP Discover，模拟一个"不规范"客户端
    2. 观察服务器是否仍然回应OFFER
    3. 如果收到OFFER，检查其中是否包含Option 82
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # 构造Option 82及其子选项
        # 子选项1 (Circuit ID): 网络标识+端口，例如 "eth0:1"
        circuit_id = b"eth0:1"
        sub_opt1 = bytes([1, len(circuit_id)]) + circuit_id
        
        # 子选项2 (Remote ID): 通常是中继代理的MAC地址
        remote_id = b"\xaa\xbb\xcc\xdd\xee\xff"  # 一个假的MAC地址
        sub_opt2 = bytes([2, len(remote_id)]) + remote_id
        
        # 完整的Option 82
        relay_agent_info = sub_opt1 + sub_opt2
        
        # --- 发送带有Option 82的DHCP Discover ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                (82, relay_agent_info),  # Option 82: Relay Agent Information
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
            return {
                "status": "部分成功", 
                "reason": "未收到DHCP OFFER",
                "option82_handling": "严格 (拒绝带有Option 82的客户端请求)",
                "security_posture": "安全 (遵循RFC 3046安全建议)",
                "security_score": 9
            }
            
        # --- 分析 DHCP OFFER 包 ---
        option82_in_offer = False
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 82:
                option82_in_offer = True
                break
                
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
        
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # --- 发送带有Option 82的DHCP Request ---
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                (82, relay_agent_info),  # Option 82: Relay Agent Information
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
                "status": "部分成功", 
                "reason": "收到OFFER但未收到ACK",
                "option82_handling": "半严格 (在请求阶段拒绝)",
                "option82_in_offer": "是" if option82_in_offer else "否",
                "security_posture": "中等 (允许发现但拒绝分配IP)",
                "security_score": 5
            }
            
        # 检查ACK中是否包含Option 82
        option82_in_ack = False
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 82:
                option82_in_ack = True
                break
                
        # 分析处理模式和安全态度
        handling_mode = ""
        security_posture = ""
        security_score = 0
        
        if option82_in_offer and option82_in_ack:
            handling_mode = "回显 (Echo)"
            security_posture = "不安全 (盲目回显选项，可能造成信息泄露)"
            security_score = 2
        elif not option82_in_offer and not option82_in_ack:
            handling_mode = "忽略 (Strip)"
            security_posture = "一般 (接受但不回显，属于宽容模式)"
            security_score = 5
        else:
            handling_mode = "混合 (不一致处理)"
            security_posture = "不规范 (处理逻辑不一致)"
            security_score = 3
            
        return {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "option82_handling": handling_mode,
            "option82_in_offer": "是" if option82_in_offer else "否",
            "option82_in_ack": "是" if option82_in_ack else "否",
            "security_posture": security_posture,
            "security_score": security_score
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
