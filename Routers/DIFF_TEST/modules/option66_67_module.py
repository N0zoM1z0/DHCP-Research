"""
DHCP Option 66 (TFTP Server Name) 和 Option 67 (Bootfile Name) 测试模块

这个模块测试路由器对PXE引导相关选项的支持情况。
- Option 66: TFTP服务器名称，用于无盘启动时下载引导文件
- Option 67: 引导文件名，指定从TFTP服务器下载的文件名
"""

from scapy.all import *
import logging
import random
import time
import socket

def test_option66_67(interface_name):
    """
    测试 DHCP Option 66 (TFTP Server Name) 和 Option 67 (Bootfile Name) 功能
    返回测试结果字典
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # --- 发送 DHCP Discover ---
        # 在param_req_list中请求Option 66和67
        param_req_list = [1, 3, 6, 66, 67]
        
        # 设置DHCP选项53为1(DHCP Discover)
        dhcp_discover = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "discover"),
                ("param_req_list", param_req_list),
                # 添加一些PXE客户端可能发送的其他选项
                ("vendor_class_id", "PXEClient"),  # 标识为PXE客户端
                ("max_dhcp_size", 1500),
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
            
        # --- 分析 DHCP OFFER 包 ---
        option66_found = False
        option67_found = False
        tftp_server = None
        bootfile_name = None
        
        # 检查OFFER中的Option 66和67
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'tftp_server_name':
                option66_found = True
                tftp_server = opt[1]
                
        # 检查BOOTP头中的siaddr(下一个服务器IP)和file(引导文件名)字段
        siaddr = dhcp_offer[BOOTP].siaddr
        file = dhcp_offer[BOOTP].file
        
        if siaddr != '0.0.0.0':
            # BOOTP siaddr字段提供了TFTP服务器地址
            option66_found = True
            tftp_server = siaddr

        sname = dhcp_offer[BOOTP].sname
        if sname and sname.strip(b'\x00') != b'':
            # sname 字段也可能提供了TFTP服务器信息
            option66_found = True
            if tftp_server is None: # 避免覆盖siaddr的结果
                tftp_server = sname.decode('utf-8', errors='ignore').strip('\x00')

        if file and file.strip(b'\x00') != b'':
            # BOOTP file字段提供了引导文件名
            option67_found = True
            bootfile_name = file.decode('utf-8', errors='ignore').strip('\x00')

        # 检查正式的Option 67
        for opt in dhcp_offer[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'bootfile_name':
                option67_found = True
                bootfile_name = opt[1]
                
        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break
        
        if server_ip is None:
            return {"status": "失败", "reason": "在DHCP OFFER包中未找到 'server_id' 选项"}
        
        # --- 继续完成DORA流程 ---
        # 发送 DHCP Request
        dhcp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags='B') /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("param_req_list", param_req_list),  # 再次请求 Option 66和67
                ("vendor_class_id", "PXEClient"),  # 再次表明是PXE客户端
                ("end")
            ])
        )
        
        sendp(dhcp_request, iface=interface_name, verbose=False)
        
        # 等待 DHCP ACK
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
            
        # 检查ACK包中的Option 66和67以及BOOTP字段
        option66_in_ack = False
        option67_in_ack = False
        tftp_server_in_ack = None
        bootfile_name_in_ack = None
        
        # 检查ACK中的Option 66
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'tftp_server_name':
                option66_in_ack = True
                tftp_server_in_ack = opt[1]
                
        # 检查ACK中的BOOTP siaddr和file字段
        siaddr_ack = dhcp_ack[BOOTP].siaddr
        file_ack = dhcp_ack[BOOTP].file
        
        if siaddr_ack != '0.0.0.0':
            option66_in_ack = True
            tftp_server_in_ack = siaddr_ack
            
        if file_ack and file_ack.strip(b'\x00') != b'':
            option67_in_ack = True
            bootfile_name_in_ack = file_ack.decode('utf-8', errors='ignore').strip('\x00')
            
        # 检查正式的Option 67
        for opt in dhcp_ack[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'bootfile_name':
                option67_in_ack = True
                bootfile_name_in_ack = opt[1]
                
        # 合并结果，优先使用ACK中的信息
        final_tftp_server = tftp_server_in_ack if option66_in_ack else tftp_server
        final_bootfile_name = bootfile_name_in_ack if option67_in_ack else bootfile_name
        
        # 分析PXE引导支持程度
        pxe_support_level = "无"
        if option66_found or option66_in_ack:
            if option67_found or option67_in_ack:
                pxe_support_level = "完整支持 (提供TFTP服务器和引导文件名)"
            else:
                pxe_support_level = "部分支持 (仅提供TFTP服务器)"
        elif option67_found or option67_in_ack:
            pxe_support_level = "部分支持 (仅提供引导文件名)"
            
        result = {
            "status": "成功",
            "assigned_ip": dhcp_ack[BOOTP].yiaddr,
            "server_ip": server_ip,
            "option66_support": "是" if (option66_found or option66_in_ack) else "否",
            "option67_support": "是" if (option67_found or option67_in_ack) else "否",
            "tftp_server": final_tftp_server if final_tftp_server else "N/A",
            "bootfile_name": final_bootfile_name if final_bootfile_name else "N/A",
            "pxe_support_level": pxe_support_level,
            "option66_in_offer": "是" if option66_found else "否",
            "option66_in_ack": "是" if option66_in_ack else "否",
            "option67_in_offer": "是" if option67_found else "否", 
            "option67_in_ack": "是" if option67_in_ack else "否",
            "bootp_siaddr_used": "是" if (siaddr != '0.0.0.0' or siaddr_ack != '0.0.0.0') else "否",
            "bootp_file_used": "是" if ((file and file.strip(b'\x00') != b'') or 
                                      (file_ack and file_ack.strip(b'\x00') != b'')) else "否",
        }
        
        return result
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()
