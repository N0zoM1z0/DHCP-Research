from scapy.all import *
import random
import time
import logging
import sys
import os

def test_bootp_legacy(interface_name):
    """
    Tests if the DHCP server supports legacy BOOTP protocol and if it exhibits different behavior
    when responding to pure BOOTP requests vs standard DHCP requests.
    
    BOOTP is DHCP's predecessor and uses the same packet structure but without DHCP-specific options.
    Many DHCP servers maintain backwards compatibility with BOOTP clients, which may expose
    insecure or unmaintained code paths.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    socket = None
    bootp_result = {}
    
    try:
        # Get the MAC address of the specified interface
        mac_addr = get_if_hwaddr(interface_name)
        # Convert MAC address to byte string for the chaddr field
        mac_bytes = mac2str(mac_addr)
        
        # Generate a random transaction ID (xid)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # Build a pure BOOTP request (no DHCP options layer)
        bootp_request = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(
                op=1,                # BOOTREQUEST
                htype=1,             # Hardware type: Ethernet
                hlen=6,              # Hardware address length: 6 bytes
                hops=0,
                xid=xid,
                secs=0,
                flags=0x8000,        # Broadcast flag set
                ciaddr="0.0.0.0",
                yiaddr="0.0.0.0",
                siaddr="0.0.0.0",
                giaddr="0.0.0.0",
                chaddr=mac_bytes + b'\x00' * 10,  # Client hardware address padded to 16 bytes
                sname=b'\x00' * 64,  # Server name field (empty)
                file=b'\x00' * 128,  # Boot file name (empty)
                options=b'\x63\x82\x53\x63'  # Magic cookie for BOOTP
            )
        )
        
        # Create a socket to listen for responses
        socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=interface_name,
            filter="udp and (port 67 or port 68)"
        )
        
        # Send the BOOTP request
        sendp(bootp_request, iface=interface_name, verbose=False)
        
        # Listen for BOOTP replies
        bootp_reply = None
        start_time = time.time()
        timeout = 5
        
        while time.time() - start_time < timeout:
            packets = socket.sniff(timeout=1, count=10)
            for pkt in packets:
                if BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[BOOTP].xid == xid:  # BOOTREPLY
                    bootp_reply = pkt
                    break
            if bootp_reply:
                break
        
        if bootp_reply is None:
            bootp_result = {
                "status": "失败",
                "reason": "未收到BOOTP响应",
                "bootp_support": "否",
                "details": "服务器不支持纯BOOTP协议"
            }
        else:
            # Check if it's a pure BOOTP reply (no DHCP options)
            is_pure_bootp = True
            if DHCP in bootp_reply:
                for opt in bootp_reply[DHCP].options:
                    if isinstance(opt, tuple) and opt[0] == 'message-type':
                        is_pure_bootp = False
                        break
            
            # Get the assigned IP
            assigned_ip = bootp_reply[BOOTP].yiaddr
            
            # Now perform a standard DHCP test for comparison
            dhcp_result = perform_standard_dhcp_test(interface_name)
            
            # Compare BOOTP and DHCP behaviors
            if dhcp_result.get("status") == "成功":
                dhcp_ip = dhcp_result.get("assigned_ip", "N/A")
                policy_diff = "相同IP分配策略" if assigned_ip == dhcp_ip else "不同IP分配策略"
                security_concern = "低" if policy_diff == "相同IP分配策略" else "高"
            else:
                policy_diff = "无法比较 (DHCP测试失败)"
                security_concern = "未知"
            
            bootp_result = {
                "status": "成功",
                "bootp_support": "是",
                "is_pure_bootp": "是" if is_pure_bootp else "否",
                "assigned_ip": assigned_ip,
                "dhcp_vs_bootp": policy_diff,
                "security_concern": security_concern,
                "legacy_code_presence": "极可能" if is_pure_bootp else "可能",
                "code_age": estimate_code_age(bootp_reply, is_pure_bootp)
            }
            
            # Test with malformed BOOTP packet
            malformed_result = test_malformed_bootp(interface_name, xid + 1)
            bootp_result.update(malformed_result)
        
        return bootp_result
        
    except Exception as e:
        return {
            "status": "异常",
            "reason": str(e),
            "bootp_support": "未知",
            "details": "测试过程中发生异常"
        }
    finally:
        if socket:
            socket.close()

def test_malformed_bootp(interface_name, xid):
    """Test with malformed BOOTP packets to check robustness"""
    socket = None
    try:
        mac_addr = get_if_hwaddr(interface_name)
        mac_bytes = mac2str(mac_addr)
        
        # Build a malformed BOOTP request (invalid hardware type and incorrect hlen)
        malformed_bootp = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(
                op=1,            # BOOTREQUEST
                htype=99,        # Invalid hardware type (valid is 1 for Ethernet)
                hlen=10,         # Incorrect hardware address length (should be 6 for MAC)
                hops=0,
                xid=xid,
                secs=0,
                flags=0x8000,
                ciaddr="0.0.0.0",
                yiaddr="0.0.0.0",
                siaddr="0.0.0.0",
                giaddr="0.0.0.0",
                chaddr=mac_bytes + b'\x00' * 10,
                sname=b'\x00' * 64,
                file=b'\x00' * 128,
                options=b'\x63\x82\x53\x63'  # Magic cookie
            )
        )
        
        socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=interface_name,
            filter="udp and (port 67 or port 68)"
        )
        
        sendp(malformed_bootp, iface=interface_name, verbose=False)
        
        # Listen for replies
        malformed_reply = None
        start_time = time.time()
        timeout = 5
        
        while time.time() - start_time < timeout:
            packets = socket.sniff(timeout=1, count=10)
            for pkt in packets:
                if BOOTP in pkt and pkt[BOOTP].op == 2 and pkt[BOOTP].xid == xid:
                    malformed_reply = pkt
                    break
            if malformed_reply:
                break
        
        if malformed_reply is None:
            return {
                "malformed_bootp_handling": "拒绝响应 (安全)",
                "validation_quality": "高"
            }
        else:
            # The server responded to a malformed BOOTP packet
            return {
                "malformed_bootp_handling": "接受并响应 (不安全)",
                "validation_quality": "低",
                "security_risk": "高 - 服务器没有严格验证BOOTP包格式"
            }
            
    except Exception as e:
        return {
            "malformed_bootp_handling": "测试异常",
            "validation_quality": "未知",
            "error": str(e)
        }
    finally:
        if socket:
            socket.close()

def perform_standard_dhcp_test(interface_name):
    """Perform a standard DHCP test for comparison with BOOTP results"""
    socket = None
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # DHCP Discover
        discover_pkt = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), ("end")])
        )
        
        socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=interface_name,
            filter="udp and (port 67 or port 68)"
        )
        
        sendp(discover_pkt, iface=interface_name, verbose=False)
        
        # Wait for Offer
        dhcp_offer = None
        start_time = time.time()
        timeout = 5
        
        while time.time() - start_time < timeout:
            packets = socket.sniff(timeout=1, count=10)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_offer = pkt
                        break
            if dhcp_offer:
                break
        
        if dhcp_offer is None:
            return {"status": "失败", "reason": "未收到DHCP OFFER"}
        
        # Return the assigned IP for comparison
        return {
            "status": "成功",
            "assigned_ip": dhcp_offer[BOOTP].yiaddr
        }
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()

def estimate_code_age(bootp_reply, is_pure_bootp):
    """
    Estimate the age of the DHCP server codebase based on protocol behavior
    """
    if not is_pure_bootp:
        return "较新 (混合了DHCP选项)"
    
    # Check for specific indicators in BOOTP reply
    # 1. Does it use fixed-length fields exactly as in RFC951?
    # 2. Are there any vendor extensions in the 'options' field?
    has_vendor_extensions = False
    if DHCP in bootp_reply:
        for opt in bootp_reply[DHCP].options:
            if isinstance(opt, tuple) and opt[0] == 'vendor_specific':
                has_vendor_extensions = True
                break
    
    # Check if 'file' field is used in a legacy way
    legacy_file_usage = False
    if bootp_reply[BOOTP].file and bootp_reply[BOOTP].file.strip(b'\x00'):
        legacy_file_usage = True
    
    # Make age estimation
    if legacy_file_usage and not has_vendor_extensions:
        return "非常老 (1985-1993, 纯RFC951风格)"
    elif is_pure_bootp and not has_vendor_extensions:
        return "老 (1993-2000, 早期BOOTP扩展)"
    elif is_pure_bootp and has_vendor_extensions:
        return "中等 (2000-2010, 后期BOOTP支持)"
    else:
        return "现代 (2010以后, DHCP主导)"

# For standalone testing
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface_name>")
        sys.exit(1)
    
    interface = sys.argv[1]
    result = test_bootp_legacy(interface)
    print(f"BOOTP Legacy Test Results for {interface}:")
    for key, value in result.items():
        print(f"{key}: {value}")