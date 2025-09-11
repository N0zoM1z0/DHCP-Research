"""
DHCP Option 80 (Rapid Commit) 测试模块

这个模块测试路由器对Option 80的支持情况，该选项可以将标准的4步DORA流程简化为2步。
当客户端在DISCOVER包中包含此选项时，支持的服务器可以直接用ACK回应，跳过OFFER和REQUEST阶段。

RFC 4039规定：
- 客户端可以在DISCOVER中加入一个空的Option 80
- 服务器如果支持快速提交，则直接回复一个包含Option 80的ACK
- 否则服务器将忽略此选项，进行标准的OFFER响应
"""

from scapy.all import *
import logging
import random
import time

def test_option80(interface_name):
    """
    测试服务器对DHCP Option 80 (Rapid Commit)的支持
    
    测试策略:
    1. 发送一个包含Option 80的DHCP Discover
    2. 观察服务器的响应：
       - 如果直接收到ACK，则支持Rapid Commit
       - 如果收到OFFER，则不支持但退回到标准流程
       - 如果无响应，则服务器对此选项处理异常
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送包含Option 80的DHCP Discover ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                (80, b''),  # Option 80: Rapid Commit (空值)
                ("end")
            ])
        )
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待响应（可能是OFFER或者直接ACK） ---
        dhcp_offer = None
        dhcp_ack = None
        start_time = time.time()
        
        print("  -- 等待服务器响应，可能是标准的OFFER或直接ACK...")
        while time.time() - start_time < 10:
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    for opt in pkt[DHCP].options:
                        if opt[0] == 'message-type':
                            if opt[1] == 2:  # OFFER
                                dhcp_offer = pkt
                                print("  -- 收到DHCP OFFER，服务器不支持Rapid Commit")
                                break
                            elif opt[1] == 5:  # ACK
                                dhcp_ack = pkt
                                print("  -- 收到DHCP ACK，服务器可能支持Rapid Commit")
                                break
                if dhcp_offer or dhcp_ack:
                    break
            if dhcp_offer or dhcp_ack:
                break
        
        # 分析结果
        if not dhcp_offer and not dhcp_ack:
            # 服务器没有响应
            return {
                "status": "失败",
                "reason": "服务器未响应包含Option 80的DISCOVER请求",
                "option80_support": "未知 (服务器无响应)",
                "rapid_commit_enabled": "否"
            }
        
        elif dhcp_ack:
            # 检查ACK中是否包含Option 80，确认是Rapid Commit响应
            rapid_commit_confirmed = False
            for opt in dhcp_ack[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == 80:
                    rapid_commit_confirmed = True
                    break
            
            if rapid_commit_confirmed:
                print("  -- 确认: ACK中包含Option 80，服务器完全支持Rapid Commit")
                return {
                    "status": "成功",
                    "assigned_ip": dhcp_ack[BOOTP].yiaddr,
                    "option80_support": "是",
                    "rapid_commit_enabled": "是",
                    "dora_steps": "2步 (Discover-Ack)",
                    "efficiency_optimization": "高 (跳过了两个步骤)",
                    "performance_rating": 10
                }
            else:
                print("  -- 注意: 收到ACK但不包含Option 80，这是一个不标准的实现")
                return {
                    "status": "成功",
                    "assigned_ip": dhcp_ack[BOOTP].yiaddr,
                    "option80_support": "部分支持",
                    "rapid_commit_enabled": "是，但实现不标准",
                    "dora_steps": "2步 (Discover-Ack)",
                    "efficiency_optimization": "高 (跳过了两个步骤)",
                    "performance_rating": 8,
                    "note": "服务器使用Rapid Commit但ACK中没有包含Option 80，不完全符合RFC 4039"
                }
        
        else:  # dhcp_offer 存在
            # 服务器回退到了标准流程，我们需要完成剩余的步骤
            offered_ip = dhcp_offer[BOOTP].yiaddr
            server_ip = None
            for opt in dhcp_offer[DHCP].options:
                if opt[0] == 'server_id':
                    server_ip = opt[1]
                    break
            
            if server_ip is None:
                return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
            
            # --- 发送标准的DHCP Request ---
            dhcp_request = (
                Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
                DHCP(options=[
                    ("message-type", "request"),
                    ("requested_addr", offered_ip),
                    ("server_id", server_ip),
                    ("end")
                ])
            )
            
            sendp(dhcp_request, iface=interface_name, verbose=False)
            
            # --- 等待标准的DHCP ACK ---
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
                    "status": "部分失败",
                    "reason": "收到OFFER但未能完成标准DORA流程",
                    "option80_support": "否",
                    "rapid_commit_enabled": "否"
                }
            
            return {
                "status": "成功",
                "assigned_ip": dhcp_ack[BOOTP].yiaddr,
                "option80_support": "否",
                "rapid_commit_enabled": "否",
                "dora_steps": "4步 (标准DORA)",
                "efficiency_optimization": "无",
                "performance_rating": 5,
                "note": "服务器不支持Rapid Commit，使用了标准的DORA流程"
            }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
