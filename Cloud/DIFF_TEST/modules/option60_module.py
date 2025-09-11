"""
DHCP Option 60 (Vendor Class Identifier) 测试模块

这个模块测试路由器对厂商类型标识符的处理方式，包括:
1. 基本VCI支持测试 - 路由器是否接受带有VCI的请求
2. 特定VCI测试 - 路由器对不同厂商ID是否有特殊处理
3. Option 43响应测试 - 是否对特定VCI返回厂商特定信息
"""

from scapy.all import *
import logging
import random
import time
import binascii

def extract_option43(dhcp_packet):
    """从DHCP包中提取Option 43 (厂商特定信息) 并返回格式化的内容"""
    for opt in dhcp_packet[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == 'vendor_specific' and opt[1]:
            # 转换成十六进制字符串以便阅读
            return {
                "raw_hex": binascii.hexlify(opt[1]).decode('utf-8'),
                "length": len(opt[1]),
                "printable": ''.join([chr(b) if 32 <= b <= 126 else '.' for b in opt[1]])
            }
    return None

def test_option60_with_vci(interface_name, vci_string):
    """
    使用指定的厂商类型标识符进行测试
    
    参数:
    interface_name: 网络接口名称
    vci_string: 要测试的厂商类型标识符字符串
    
    返回:
    dict: 测试结果字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送带有Option 60的DHCP Discover ---
        param_req_list = [1, 3, 6, 43]  # 请求Option 43
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("vendor_class_id", vci_string),  # Option 60
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
            return {
                "status": "失败", 
                "reason": "未收到 DHCP OFFER", 
                "vci": vci_string,
                "vci_support": "否"
            }
            
        # 检查是否在OFFER中收到Option 43
        option43_in_offer = extract_option43(dhcp_offer)
            
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
                
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # --- 发送带有Option 60的DHCP Request ---
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("vendor_class_id", vci_string),  # Option 60
                ("param_req_list", param_req_list),
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
                "vci": vci_string,
                "vci_support": "未知"
            }
        
        # 检查是否在ACK中收到Option 43
        option43_in_ack = extract_option43(dhcp_ack)
        
        result = {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "vci": vci_string,
            "vci_support": "是",
            "option43_in_offer": "是" if option43_in_offer else "否",
            "option43_in_ack": "是" if option43_in_ack else "否",
        }
        
        # 如果有Option 43，添加其内容到结果中
        if option43_in_offer:
            result["option43_offer_content"] = option43_in_offer
        if option43_in_ack:
            result["option43_ack_content"] = option43_in_ack
            
        return result
        
    except Exception as e:
        return {
            "status": "异常", 
            "reason": str(e), 
            "vci": vci_string,
            "vci_support": "未知"
        }
    finally:
        if socket:
            socket.close()

def test_option60(interface_name):
    """
    执行完整的Option 60测试套件，测试不同的厂商类型标识符
    """
    # 测试的厂商类型标识符列表
    vci_list = [
        "MSFT 5.0",           # Microsoft Windows
        "android-dhcp-10",    # Android设备
        "HUAWEI:STB",         # 华为机顶盒
        "IPTV_STB",           # 通用IPTV机顶盒
        "ArubaAP",            # Aruba无线接入点
        "udhcp 1.19.4"        # 嵌入式设备常用
    ]
    
    results = {}
    option43_responses = {}
    test_summaries = []
    
    # 测试所有VCI
    for vci in vci_list:
        print(f"  -- 测试厂商标识: {vci}")
        result = test_option60_with_vci(interface_name, vci)
        results[vci] = result
        
        # 记录有Option 43响应的VCI
        if result.get("option43_in_ack") == "是":
            option43_responses[vci] = result.get("option43_ack_content", {})
            test_summaries.append(f"VCI '{vci}' 触发了Option 43响应")
    
    # 汇总结果
    summary = {
        "status": "成功",
        "vci_tests_total": len(vci_list),
        "vci_with_option43_responses": len(option43_responses),
        "option43_responses": option43_responses,
        "test_details": results,
    }
    
    # 添加特性分析
    if len(option43_responses) > 0:
        vci_list_with_responses = list(option43_responses.keys())
        summary["option43_support"] = "是"
        summary["responsive_vcis"] = vci_list_with_responses
        summary["special_vci_handling"] = "是"
        summary["vci_handling_description"] = f"路由器对{len(option43_responses)}个VCI有特殊处理: {', '.join(vci_list_with_responses)}"
    else:
        summary["option43_support"] = "否"
        summary["special_vci_handling"] = "否"
        summary["vci_handling_description"] = "路由器接受所有VCI但没有特殊处理"
    
    # 将分析摘要添加到结果中
    summary["analysis"] = test_summaries
    
    return summary
