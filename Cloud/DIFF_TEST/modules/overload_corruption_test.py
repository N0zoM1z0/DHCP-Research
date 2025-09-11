from scapy.all import *
import random
import time
import logging
import sys
import os

def test_overload_corruption(interface_name):
    """
    Tests the DHCP server's resilience against malformed DHCP option overload fields.
    
    The DHCP Option 52 (Overload) allows DHCP options to be stored in the BOOTP header's
    'file' and 'sname' fields. This creates complex parsing logic that may be vulnerable
    to buffer overflow attacks if not properly implemented.
    
    This test sends various malformed overload options to test the server's robustness.
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    results = {
        "status": "进行中",
        "tests_run": 0,
        "tests_passed": 0,
        "vulnerabilities": []
    }
    
    # Prepare a list of test cases
    test_cases = [
        {
            "name": "sname_overflow",
            "description": "SNAME字段缓冲区溢出测试",
            "overload_value": 2,  # Use sname field
            "sname": b'\x0c\x04' + b'A' * 100,  # Option 12 (hostname) with incorrect length
            "file": b'\x00' * 128
        },
        {
            "name": "file_overflow",
            "description": "FILE字段缓冲区溢出测试",
            "overload_value": 1,  # Use file field
            "sname": b'\x00' * 64,
            "file": b'\x3c\x04' + b'B' * 200  # Option 60 (VCI) with incorrect length
        },
        {
            "name": "both_fields_overflow",
            "description": "同时溢出SNAME和FILE字段",
            "overload_value": 3,  # Use both sname and file fields
            "sname": b'\x0c\x10' + b'C' * 80,  # Option 12 with length 16 but more data
            "file": b'\x3c\x20' + b'D' * 150   # Option 60 with length 32 but more data
        },
        {
            "name": "cross_field_option",
            "description": "跨字段选项测试",
            "overload_value": 3,  # Use both fields
            "sname": b'\x0c\x40' + b'E' * 62,  # Start option 12 with length 64
            "file": b'F' * 64 + b'\x3c\x10' + b'G' * 54  # Continue option 12 and add option 60
        },
        {
            "name": "invalid_option_length",
            "description": "无效选项长度测试",
            "overload_value": 2,  # Use sname field
            "sname": b'\x0c\xff' + b'H' * 62,  # Option 12 with length 255 (impossible in sname)
            "file": b'\x00' * 128
        }
    ]
    
    # Run each test case
    for test_case in test_cases:
        result = run_overload_test(interface_name, test_case)
        results["tests_run"] += 1
        
        if result["status"] == "成功":
            results["tests_passed"] += 1
        else:
            results["vulnerabilities"].append({
                "test_name": test_case["name"],
                "description": test_case["description"],
                "details": result["reason"] if "reason" in result else "未知错误"
            })
    
    # Add a second test with a small delay to see if previous tests crashed the server
    time.sleep(2)
    recovery_test = perform_standard_dhcp_test(interface_name)
    
    if recovery_test["status"] != "成功":
        results["status"] = "发现漏洞"
        results["server_crashed"] = "是"
        results["crash_details"] = "服务器在溢出测试后无响应，可能已崩溃"
        results["security_risk"] = "极高 - 发现可能的拒绝服务漏洞"
    else:
        results["server_crashed"] = "否"
        
        if results["tests_passed"] == results["tests_run"]:
            results["status"] = "成功"
            results["security_assessment"] = "服务器对DHCP选项溢出攻击具有良好的防御能力"
            results["parser_robustness"] = "高"
        else:
            results["status"] = "发现异常"
            results["security_assessment"] = f"服务器在 {results['tests_run'] - results['tests_passed']}/{results['tests_run']} 个测试中表现出异常行为"
            results["parser_robustness"] = "中" if results["tests_passed"] >= results["tests_run"] / 2 else "低"
    
    return results

def run_overload_test(interface_name, test_case):
    """Run a specific overload corruption test case"""
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # Create DHCP discover with overload option
        discover_pkt = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(
                chaddr=mac2str(mac_addr),
                xid=xid,
                flags=0x8000,
                sname=test_case["sname"],
                file=test_case["file"]
            ) /
            DHCP(options=[
                ("message-type", "discover"),
                ("overload", test_case["overload_value"]),
                ("end")
            ])
        )
        
        socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=interface_name,
            filter="udp and (port 67 or port 68)"
        )
        
        # Send the packet
        sendp(discover_pkt, iface=interface_name, verbose=False)
        
        # Listen for responses
        start_time = time.time()
        timeout = 5
        offer_received = False
        
        while time.time() - start_time < timeout:
            packets = socket.sniff(timeout=1, count=10)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] == 2 for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        offer_received = True
                        break
            if offer_received:
                break
        
        if offer_received:
            return {
                "status": "成功",
                "test_name": test_case["name"],
                "response": "服务器正常响应，未发现漏洞"
            }
        else:
            return {
                "status": "失败",
                "reason": "服务器未响应畸形包",
                "test_name": test_case["name"],
                "response": "服务器可能过滤了畸形包或拒绝响应（这是安全的行为）"
            }
        
    except Exception as e:
        return {
            "status": "异常",
            "reason": str(e),
            "test_name": test_case["name"] if "name" in test_case else "未知测试"
        }
    finally:
        if socket:
            socket.close()

def perform_standard_dhcp_test(interface_name):
    """Perform a standard DHCP test to check if server is still operational"""
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
        
        return {"status": "成功", "assigned_ip": dhcp_offer[BOOTP].yiaddr}
        
    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        if socket:
            socket.close()

# For standalone testing
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface_name>")
        sys.exit(1)
    
    interface = sys.argv[1]
    result = test_overload_corruption(interface)
    
    print(f"Overload Corruption Test Results for {interface}:")
    print(f"Status: {result['status']}")
    print(f"Tests run: {result['tests_run']}")
    print(f"Tests passed: {result['tests_passed']}")
    
    if "vulnerabilities" in result and result["vulnerabilities"]:
        print("\nVulnerabilities found:")
        for vuln in result["vulnerabilities"]:
            print(f"- {vuln['test_name']}: {vuln['description']}")
            print(f"  Details: {vuln['details']}")
    
    if "security_assessment" in result:
        print(f"\nSecurity Assessment: {result['security_assessment']}")