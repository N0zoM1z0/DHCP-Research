"""
DHCP Option 43 (Vendor Specific Information) 测试模块

这个模块专注于测试路由器对Option 43的响应，以及这些响应如何与Option 60关联。
由于Option 43主要是作为对Option 60的响应，所以这个模块主要是观察型的。
"""

from scapy.all import *
import logging
import random
import time
import binascii
import re

def decode_option43(raw_bytes):
    """
    尝试解码Option 43内容，识别常见格式
    
    参数:
    raw_bytes: Option 43的原始字节
    
    返回:
    dict: 解码结果和识别到的模式
    """
    result = {
        "raw_hex": binascii.hexlify(raw_bytes).decode('utf-8'),
        "length": len(raw_bytes),
        "printable": ''.join([chr(b) if 32 <= b <= 126 else '.' for b in raw_bytes])
    }
    
    # 尝试识别常见的Option 43格式
    
    # 1. 检查是否是常见的TLV (Type-Length-Value)格式
    if len(raw_bytes) >= 2 and raw_bytes[1] <= len(raw_bytes) - 2:
        result["format"] = "可能是TLV格式"
        try:
            sub_options = []
            i = 0
            while i < len(raw_bytes):
                sub_type = raw_bytes[i]
                if i + 1 >= len(raw_bytes):
                    break
                sub_len = raw_bytes[i+1]
                if i + 2 + sub_len > len(raw_bytes):
                    break
                sub_value = raw_bytes[i+2:i+2+sub_len]
                sub_options.append({
                    "type": sub_type,
                    "length": sub_len,
                    "value_hex": binascii.hexlify(sub_value).decode('utf-8'),
                    "value_ascii": ''.join([chr(b) if 32 <= b <= 126 else '.' for b in sub_value])
                })
                i += 2 + sub_len
            result["tlv_parsing"] = sub_options
        except:
            result["format"] = "非标准TLV格式"
    
    # 2. 检查是否包含URL (常见于强制门户)
    url_pattern = re.compile(rb'https?://[^\s]+')
    url_matches = url_pattern.findall(raw_bytes)
    if url_matches:
        result["contains_url"] = True
        result["urls"] = [m.decode('utf-8', errors='ignore') for m in url_matches]
    
    # 3. 检查是否包含IP地址 (常见于IPTV/VoIP配置)
    ip_pattern = re.compile(rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
    ip_matches = ip_pattern.findall(raw_bytes)
    if ip_matches:
        result["contains_ip"] = True
        result["ips"] = [m.decode('utf-8') for m in ip_matches]
    
    # 根据内容尝试猜测用途
    if "urls" in result:
        result["possible_purpose"] = "强制门户或设备配置URL"
    elif "ips" in result:
        result["possible_purpose"] = "服务器地址(可能用于IPTV或VoIP)"
    elif result["printable"].strip('.'):  # 如果有可打印字符
        result["possible_purpose"] = "配置信息或设备指示符"
    else:
        result["possible_purpose"] = "未知厂商特定数据"
    
    return result

def test_option43_association(interface_name):
    """
    测试不同VCI (Option 60)值如何触发不同的Option 43响应
    
    参数:
    interface_name: 网络接口名称
    
    返回:
    dict: 测试结果字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    
    # 测试的厂商类型标识符列表 - 常见的和可能触发响应的
    vci_list = [
        "MSFT 5.0",           # Microsoft Windows
        "IPTV_STB",           # IPTV机顶盒
        "HUAWEI:STB",         # 华为机顶盒
        "ArubaAP",            # Aruba接入点
        "Cisco Systems",      # Cisco设备
        "VOIP",               # VoIP电话
        "UBNT",               # Ubiquiti设备
        "HP AP",              # HP接入点
        "TP-LINK"             # TP-Link设备
    ]
    
    results = {}
    option43_responses = {}
    
    for vci in vci_list:
        print(f"  -- 测试VCI与Option 43关联: {vci}")
        result = test_single_vci(interface_name, vci)
        results[vci] = result
        
        # 记录有Option 43响应的VCI
        if result.get("option43_received") == "是":
            option43_responses[vci] = result.get("option43_content", {})
    
    # 汇总结果
    responsive_vcis = list(option43_responses.keys())
    summary = {
        "status": "成功",
        "vci_tested": len(vci_list),
        "responsive_vci_count": len(option43_responses),
        "responsive_vcis": responsive_vcis,
        "option43_support": "是" if option43_responses else "否",
        "option43_responses": option43_responses,
        "test_details": results,
    }
    
    # 分析响应模式
    if responsive_vcis:
        summary["analysis"] = f"路由器对{len(responsive_vcis)}种厂商ID有特殊处理: " + ", ".join(responsive_vcis)
        
        # 查看是否有相同的Option 43响应给不同的VCI
        response_patterns = {}
        for vci, resp in option43_responses.items():
            response_hex = resp.get("raw_hex", "")
            if response_hex not in response_patterns:
                response_patterns[response_hex] = []
            response_patterns[response_hex].append(vci)
        
        # 如果有多个VCI收到相同响应，这表明路由器可能有通用配置
        common_responses = {k: v for k, v in response_patterns.items() if len(v) > 1}
        if common_responses:
            summary["common_responses"] = common_responses
            summary["response_pattern"] = "通用模式 (多个VCI收到相同响应)"
        else:
            summary["response_pattern"] = "特定模式 (每个VCI有专属响应)"
    else:
        summary["analysis"] = "路由器不对任何测试的厂商ID返回特定信息"
    
    return summary

def test_single_vci(interface_name, vci_string):
    """
    使用单个VCI进行测试，观察是否触发Option 43响应
    
    参数:
    interface_name: 网络接口名称
    vci_string: 要测试的厂商类型标识符
    
    返回:
    dict: 测试结果字典
    """
    socket = None
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送带有Option 60的DHCP Discover ---
        param_req_list = [1, 3, 6, 43]  # 明确请求Option 43
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
                "vci": vci_string
            }
        
        # 检查Option 43是否在OFFER中
        option43_in_offer = None
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'vendor_specific' and opt[1]:
                option43_in_offer = opt[1]
                break
        
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
                "vci": vci_string
            }
        
        # 检查Option 43是否在ACK中
        option43_in_ack = None
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'vendor_specific' and opt[1]:
                option43_in_ack = opt[1]
                break
        
        result = {
            "status": "成功",
            "vci": vci_string,
            "option43_in_offer": "是" if option43_in_offer else "否",
            "option43_in_ack": "是" if option43_in_ack else "否",
            "option43_received": "是" if (option43_in_offer or option43_in_ack) else "否",
        }
        
        # 如果收到了Option 43，解析内容
        if option43_in_ack:
            result["option43_content"] = decode_option43(option43_in_ack)
        elif option43_in_offer:
            result["option43_content"] = decode_option43(option43_in_offer)
        
        return result
        
    except Exception as e:
        return {
            "status": "异常", 
            "reason": str(e), 
            "vci": vci_string
        }
    finally:
        if socket:
            socket.close()

def test_option43(interface_name):
    """
    执行Option 43测试套件
    """
    return test_option43_association(interface_name)
