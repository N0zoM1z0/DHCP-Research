"""
DHCP Option 77 (User Class) 测试模块

这个模块测试路由器对Option 77的响应，该选项允许客户端指明自己的用户类别，
服务器可以基于此提供差异化的配置。类似于Option 60 (厂商类别)，但面向用户而非厂商。

RFC 3004规定：
- 客户端可以发送一个或多个用户类字符串
- 服务器可以根据这些字符串应用不同的配置策略
"""

from scapy.all import *
import logging
import random
import time
import binascii

def compare_dhcp_offers(offer1, offer2):
    """比较两个DHCP OFFER包的差异"""
    differences = {}
    
    # 比较基本配置
    if offer1[BOOTP].yiaddr != offer2[BOOTP].yiaddr:
        differences["assigned_ip"] = {
            "offer1": offer1[BOOTP].yiaddr,
            "offer2": offer2[BOOTP].yiaddr
        }
    
    # 提取和比较所有选项
    options1 = {}
    options2 = {}
    
    for opt in offer1[DHCP].options:
        if isinstance(opt, tuple) and opt[0] != 'message-type' and opt[0] != 'server_id':
            options1[opt[0]] = opt[1]
    
    for opt in offer2[DHCP].options:
        if isinstance(opt, tuple) and opt[0] != 'message-type' and opt[0] != 'server_id':
            options2[opt[0]] = opt[1]
    
    # 找出所有在任一offer中出现的选项
    all_options = set(list(options1.keys()) + list(options2.keys()))
    
    for opt in all_options:
        # 如果选项只在一个offer中存在
        if opt in options1 and opt not in options2:
            differences[f"option_{opt}"] = {
                "offer1": options1[opt],
                "offer2": "不存在"
            }
        elif opt in options2 and opt not in options1:
            differences[f"option_{opt}"] = {
                "offer1": "不存在",
                "offer2": options2[opt]
            }
        # 如果选项在两个offer中都存在但值不同
        elif opt in options1 and opt in options2 and options1[opt] != options2[opt]:
            differences[f"option_{opt}"] = {
                "offer1": options1[opt],
                "offer2": options2[opt]
            }
    
    return differences

def test_option77(interface_name):
    """
    测试DHCP服务器对Option 77 (User Class)的处理
    
    测试策略:
    1. 先进行一次不带User Class的标准请求作为基准
    2. 然后分别使用几种常见的User Class进行测试
    3. 比较每种User Class导致的配置差异
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    
    # 定义几种常见的用户类，可能会触发特殊配置
    user_classes = [
        "guest",          # 访客
        "gaming",         # 游戏设备
        "streaming",      # 流媒体设备
        "iot",            # 物联网设备
        "voice",          # 语音设备
        "admin",          # 管理设备
        "work-from-home"  # 远程办公
    ]
    
    base_offer = None
    user_class_responses = {}
    special_policies_found = []
    
    try:
        # 首先进行基准测试 - 不带Option 77
        base_offer = get_dhcp_offer(interface_name)
        if not base_offer:
            return {"status": "失败", "reason": "基准测试未能获取DHCP OFFER"}
            
        # 记录基准IP地址
        base_ip = base_offer[BOOTP].yiaddr
        print(f"  -- 基准测试: 获得IP {base_ip}")
        
        # 测试每个用户类
        for user_class in user_classes:
            print(f"  -- 测试用户类: {user_class}")
            offer = get_dhcp_offer(interface_name, user_class)
            
            if not offer:
                user_class_responses[user_class] = {
                    "status": "无响应",
                    "可能原因": "服务器拒绝此用户类或发生错误"
                }
                continue
                
            # 比较与基准配置的差异
            differences = compare_dhcp_offers(base_offer, offer)
            
            if differences:
                print(f"  -- 发现差异配置! 用户类 '{user_class}' 触发了不同的DHCP策略")
                special_policies_found.append(user_class)
                user_class_responses[user_class] = {
                    "status": "特殊策略",
                    "assigned_ip": offer[BOOTP].yiaddr,
                    "differences": differences
                }
            else:
                user_class_responses[user_class] = {
                    "status": "标准策略",
                    "assigned_ip": offer[BOOTP].yiaddr,
                    "note": "与基准配置相同"
                }
        
        # 总结结果
        return {
            "status": "成功",
            "base_ip": base_ip,
            "option77_support": "是" if special_policies_found else "否",
            "user_classes_tested": len(user_classes),
            "special_policies_found": len(special_policies_found),
            "special_user_classes": special_policies_found,
            "user_class_responses": user_class_responses,
            "user_class_sensitivity": "高" if len(special_policies_found) > 1 else 
                                      "低" if len(special_policies_found) == 1 else 
                                      "无"
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}

def get_dhcp_offer(interface_name, user_class=None):
    """
    发送DHCP DISCOVER并获取OFFER响应
    
    参数:
    interface_name: 网络接口名称
    user_class: 可选的用户类字符串
    
    返回:
    packet: DHCP OFFER包，如果未收到则返回None
    """
    socket = None
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # 构建DHCP选项
        options = [
            ("message-type", "discover"),
            ("end")
        ]
        
        # 如果指定了用户类，则添加Option 77
        if user_class:
            # 注意：RFC 3004规定User Class可以是多个类，但这里我们只使用单个类
            options.insert(-1, (77, user_class.encode()))
        
        # --- 发送 DHCP Discover ---
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=options)
        )
        
        socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP Offer ---
        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 5:  # 5秒超时
            packets = socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer:
                break
        
        return dhcp_offer
        
    finally:
        if socket:
            socket.close()
