"""
DHCP 跨子网IP请求测试模块

这个模块测试DHCP服务器对伪造的跨子网请求的处理能力。
在正常情况下，DHCP服务器会根据客户端所在子网分配对应的IP地址。
当DHCP请求通过中继代理转发时，请求包中的giaddr字段包含了中继代理的IP地址，
服务器根据这个字段判断客户端所在的子网。

本测试模块伪造giaddr字段，检测服务器是否会:
1. 正确识别并拒绝直接来自客户端(而非真正中继)的带有giaddr的请求
2. 错误地根据伪造的giaddr从其他子网地址池分配IP，导致信息泄露或安全漏洞
"""

from scapy.all import *
import logging
import random
import time
import ipaddress

def is_private_ip(ip):
    """检查IP是否为私有地址"""
    try:
        return ipaddress.ip_address(ip).is_private
    except:
        return False

def get_network_ranges(interface_name):
    """
    根据接口的IP地址，推测可能的其他网络范围
    返回一组可能用于测试的伪造giaddr值
    """
    try:
        our_ip = get_if_addr(interface_name)
        our_network = our_ip.split('.')[:3]
        
        # 常见的私有网络范围
        test_networks = []
        
        # 如果我们在192.168网段，尝试10.0.0网段
        if our_network[0] == '192':
            test_networks.append('10.0.0.1')
        # 如果我们在10网段，尝试192.168.1网段
        elif our_network[0] == '10':
            test_networks.append('192.168.1.1')
        # 添加一些其他常见的私有网络网关
        test_networks.extend(['172.16.0.1', '172.31.0.1', '10.1.1.1', '192.168.10.1'])
        
        # 避免与当前网络相同
        current_prefix = '.'.join(our_network)
        test_networks = [ip for ip in test_networks if not ip.startswith(current_prefix)]
        
        return test_networks
    except:
        # 如果获取失败，返回一些默认值
        return ['10.0.0.1', '172.16.0.1', '192.168.1.1']

def test_cross_subnet_request(interface_name):
    """
    测试DHCP服务器对伪造giaddr的跨子网请求的处理
    
    测试策略:
    1. 首先进行标准DORA获取当前网络的正常IP，作为参考
    2. 然后发送带有伪造giaddr的DHCPDISCOVER
    3. 分析服务器的响应，特别是它分配的IP地址范围
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    dhcp_socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        
        # --- 1. 首先进行标准DORA流程获取当前网络的IP ---
        standard_xid = random.randint(1, 0xFFFFFFFF)
        
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=standard_xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("end")
            ])
        )
        
        dhcp_socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
        sendp(dhcp_discover, iface=interface_name, verbose=False)
        
        # --- 等待 DHCP Offer ---
        dhcp_offer = None
        start_time = time.time()
        while time.time() - start_time < 10:
            packets = dhcp_socket.sniff(timeout=1, count=5)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == standard_xid:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer:
                break
                
        if dhcp_offer is None:
            return {"status": "失败", "reason": "未收到 DHCP OFFER"}
            
        # 分析标准Offer获取的网络信息
        standard_offered_ip = dhcp_offer[BOOTP].yiaddr
        standard_subnet = standard_offered_ip.split('.')[:3]  # 提取网络前缀
        
        print(f"  -- 标准DISCOVER获得IP: {standard_offered_ip}")
        print(f"  -- 当前网络前缀: {'.'.join(standard_subnet)}")
        
        # 关闭旧socket，准备进行跨子网测试
        if dhcp_socket:
            dhcp_socket.close()
            dhcp_socket = None
        
        # --- 2. 获取测试用的伪造网络地址 ---
        fake_relay_ips = get_network_ranges(interface_name)
        
        # 确保我们至少有一个测试IP
        if not fake_relay_ips:
            fake_relay_ips = ['10.0.0.1']
        
        # 记录测试结果
        test_results = []
        
        # --- 3. 对每个伪造的中继地址进行测试 ---
        for fake_relay_ip in fake_relay_ips:
            print(f"  -- 测试伪造中继IP: {fake_relay_ip}")
            
            # 创建一个新的事务ID
            cross_subnet_xid = random.randint(1, 0xFFFFFFFF)
            
            # 构造带有伪造giaddr的DISCOVER包
            cross_subnet_discover = (
                Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(mac_addr), xid=cross_subnet_xid, giaddr=fake_relay_ip, flags='B') /
                DHCP(options=[
                    ("message-type", "discover"),
                    ("end")
                ])
            )
            
            dhcp_socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
            sendp(cross_subnet_discover, iface=interface_name, verbose=False)
            
            # 等待跨子网请求的Offer响应
            cross_subnet_offer = None
            start_time = time.time()
            while time.time() - start_time < 10:
                packets = dhcp_socket.sniff(timeout=1, count=5)
                for pkt in packets:
                    if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == cross_subnet_xid:
                        if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                            cross_subnet_offer = pkt
                            break
                if cross_subnet_offer:
                    break
                    
            # 关闭socket以便下次测试
            if dhcp_socket:
                dhcp_socket.close()
                dhcp_socket = None
                
            # 处理结果
            test_result = {
                "fake_relay": fake_relay_ip
            }
            
            if cross_subnet_offer is None:
                test_result["response"] = "无响应"
                test_result["subnet_leakage"] = "否"
                test_result["notes"] = "服务器正确地忽略了带伪造giaddr的请求"
            else:
                cross_offered_ip = cross_subnet_offer[BOOTP].yiaddr
                cross_subnet = cross_offered_ip.split('.')[:3]
                
                test_result["response"] = "OFFER"
                test_result["offered_ip"] = cross_offered_ip
                
                # 判断是否泄露了跨子网信息
                if '.'.join(cross_subnet) != '.'.join(standard_subnet):
                    test_result["subnet_leakage"] = "是"
                    test_result["notes"] = f"安全风险: 服务器从不同子网分配了IP地址 ({cross_offered_ip})"
                else:
                    test_result["subnet_leakage"] = "否"
                    test_result["notes"] = "服务器忽略了伪造的giaddr，仍从标准子网分配IP"
            
            test_results.append(test_result)
        
        # --- 4. 汇总测试结果 ---
        # 判断是否有任何测试显示了子网泄露
        has_subnet_leakage = any(result.get("subnet_leakage") == "是" for result in test_results)
        
        # 确定整体安全级别
        if has_subnet_leakage:
            security_level = "低"
            security_notes = "服务器对giaddr验证不充分，存在子网信息泄露的安全风险"
        elif all(result.get("response") == "无响应" for result in test_results):
            security_level = "高"
            security_notes = "服务器正确拒绝了所有伪造中继的请求"
        else:
            security_level = "中"
            security_notes = "服务器响应了伪造请求，但没有泄露跨子网信息"
        
        return {
            "status": "成功",
            "standard_network": '.'.join(standard_subnet),
            "subnet_leakage_detected": "是" if has_subnet_leakage else "否",
            "topology_security_level": security_level,
            "tested_relay_ips": [result["fake_relay"] for result in test_results],
            "security_notes": security_notes,
            "test_details": test_results
        }
    
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if dhcp_socket:
            dhcp_socket.close()
