from scapy.all import *
import logging
import random
import time
import sys
import os

# 添加模块目录到 Python 跄径
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "modules"))

# 导入我们的测试模块
from modules.option12_module import test_option12
from modules.option81_module import test_option81
from modules.option114_module import test_option114
from modules.option121_module import test_option121

# 导入新的测试模块
from modules.dhcp_robust_test import test_unknown_option, test_malformed_option
from modules.option61_module import test_option61
from modules.option60_module import test_option60
from modules.option43_module import test_option43
from modules.option42_module import test_option42
from modules.option66_67_module import test_option66_67

# 导入第四梯队的高级测试模块
from modules.option57_module import test_option57
from modules.option82_module import test_option82

# 导入第五梯队的状态机和安全测试模块
from modules.lease_manipulation_test import test_spurious_release_security
from modules.resource_exhaustion_test import test_dhcp_starvation
from modules.option50_test import test_option50_in_discover

# 导入第六梯队的探索性测试模块
from modules.option80_module import test_option80
from modules.option77_module import test_option77
from modules.option33_module import test_option33
from modules.option119_module import test_option119

# 导入第七梯队的时空维度测试模块
from modules.renewal_timing_test import test_renewal_timing
from modules.cross_subnet_request_test import test_cross_subnet_request

# 导入第八梯队的协议方言与结构完整性测试模块
from modules.bootp_legacy_test import test_bootp_legacy
from modules.overload_corruption_test import test_overload_corruption
from modules.fragmentation_test import test_ip_fragmentation

# --- 1. 配置中心 ---
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# 定义我们的测试目标：只测试当前VPS的DHCP服务
TARGETS = {
    "VPS DHCP": "eth0",
}

# --- 辅助函数 ---
def parse_dhcp_options(dhcp_packet):
    """从DHCP包中解析所有options，并返回一个易于阅读的字典。"""
    options_dict = {}
    if DHCP in dhcp_packet:
        for opt in dhcp_packet[DHCP].options:
            if isinstance(opt, tuple) and len(opt) == 2:
                options_dict[opt[0]] = opt[1]
    return options_dict

# --- 2. 测试用例 ---
def run_standard_dora_test(interface_name):
    """
    在一个指定的网络接口上执行一次标准的DORA流程。
    严格遵循 dhcp_full_interaction.py 的 L2listen + sniff 逻辑。
    """
    socket = None  # 初始化socket变量
    try:
        mac_addr = get_if_hwaddr(interface_name)
        xid = random.randint(1, 0xFFFFFFFF)

        # --- (D)iscover ---
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

        # --- 等待 (O)ffer ---
        dhcp_offer = None
        start_time = time.time()
        timeout = 10
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

        offered_ip = dhcp_offer[BOOTP].yiaddr
        server_ip = None
        for opt in dhcp_offer[DHCP].options:
            if opt[0] == 'server_id':
                server_ip = opt[1]
                break

        if server_ip is None:
            return {"status": "失败", "reason": "OFFER包中缺少Server ID"}

        # --- (R)equest ---
        request_pkt = (
            Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(mac_addr), xid=xid, flags=0x8000) /
            DHCP(options=[
                ("message-type", "request"),
                ("requested_addr", offered_ip),
                ("server_id", server_ip),
                ("end")
            ])
        )
        sendp(request_pkt, iface=interface_name, verbose=False)

        # --- 等待 (A)cknowledgment ---
        dhcp_ack = None
        start_time = time.time()
        while time.time() - start_time < timeout:
            packets = socket.sniff(timeout=1, count=10)
            for pkt in packets:
                if DHCP in pkt and BOOTP in pkt and pkt[BOOTP].xid == xid:
                    if any(opt[1] in [5, 6] for opt in pkt[DHCP].options if opt[0] == 'message-type'):
                        dhcp_ack = pkt
                        break
            if dhcp_ack:
                break

        if dhcp_ack is None:
            return {"status": "失败", "reason": "未收到DHCP ACK/NAK"}
            
        msg_type = None
        for opt in dhcp_ack[DHCP].options:
            if opt[0] == 'message-type':
                msg_type = opt[1]
                break
        
        if msg_type != 5:
            return {"status": "失败", "reason": f"收到DHCP NAK (类型 {msg_type})"}

        # --- 成功，解析并返回结果 ---
        final_ip = dhcp_ack[BOOTP].yiaddr
        parsed_options = parse_dhcp_options(dhcp_ack)

        # 扩展返回的结果，增加更多的字段
        result = {
            "status": "成功",
            "assigned_ip": final_ip,
            "server_ip": parsed_options.get("server_id", "N/A"),
            "lease_time": parsed_options.get("lease_time", "N/A"),
            "subnet_mask": parsed_options.get("subnet_mask", "N/A"),
            "router": parsed_options.get("router", "N/A"),
            "name_server": parsed_options.get("name_server", "N/A"),
        }
        
        # 额外分析核心DHCP选项的完整性
        analyze_dhcp_completeness(result)
        
        return result

    except Exception as e:
        return {"status": "异常", "reason": str(e)}
    finally:
        # 确保无论成功还是失败，socket都会被关闭
        if socket:
            socket.close()

def run_option12_test(interface_name):
    """执行 Option 12 (主机名) 测试"""
    return test_option12(interface_name)
    
def run_option81_test(interface_name):
    """执行 Option 81 (FQDN) 测试"""
    return test_option81(interface_name)
    
def run_option114_test(interface_name):
    """执行 Option 114 (Captive Portal) 测试"""
    return test_option114(interface_name)
    
def run_option121_test(interface_name):
    """执行 Option 121 (Classless Static Route) 测试"""
    return test_option121(interface_name)

def run_option57_test(interface_name):
    """执行 Option 57 (Maximum DHCP Message Size) 测试"""
    return test_option57(interface_name)
    
def run_option82_test(interface_name):
    """执行 Option 82 (Relay Agent Information) 测试"""
    return test_option82(interface_name)

def run_lease_security_test(interface_name):
    """执行租约释放安全性测试"""
    return test_spurious_release_security(interface_name)

def run_starvation_test(interface_name):
    """执行DHCP饥饿攻击抵抗力测试"""
    return test_dhcp_starvation(interface_name)

def run_option50_test(interface_name):
    """执行Option 50在Discover中的测试"""
    return test_option50_in_discover(interface_name)

def run_option80_test(interface_name):
    """执行 Option 80 (Rapid Commit) 测试"""
    return test_option80(interface_name)

def run_option77_test(interface_name):
    """执行 Option 77 (User Class) 测试"""
    return test_option77(interface_name)

def run_option33_test(interface_name):
    """执行 Option 33 (Static Route) 测试"""
    return test_option33(interface_name)

def run_option119_test(interface_name):
    """执行 Option 119 (Domain Search) 测试"""
    return test_option119(interface_name)

def run_renewal_timing_test(interface_name):
    """执行租约续订时序攻击测试"""
    return test_renewal_timing(interface_name)

def run_cross_subnet_test(interface_name):
    """执行跨子网IP请求测试"""
    return test_cross_subnet_request(interface_name)

# --- 4. 报告生成器 ---
def print_comparison_report(test_name, results):
    """以表格形式打印两个路由器的对比测试报告，考虑网络差异"""
    print("\n" + "="*80)
    print(f"DHCP 差分测试报告: {test_name}")
    print("="*80)
    
    router_names = list(results.keys())
    if len(router_names) != 2:
        print("[!] 报告生成错误：需要正好两个测试目标。")
        return

    r1_name, r2_name = router_names[0], router_names[1]
    r1_res, r2_res = results[r1_name], results[r2_name]
    
    # 首先执行行为特征分析
    behavior_analysis = analyze_behavior_difference(r1_name, r1_res, r2_name, r2_res)
    
    # 打印行为和策略差异分析
    if behavior_analysis:
        print("\n--- 行为与策略差异分析 ---")
        for category, findings in behavior_analysis.items():
            print(f"\n{category}:")
            for finding in findings:
                print(f"  - {finding}")
    
    # 继续打印常规的值对比
    all_keys = sorted(list(set(r1_res.keys()) | set(r2_res.keys())))
    
    # 定义网络位置相关的键（这些键的差异通常是由于不同网段而非路由器行为差异）
    network_location_keys = {
        'assigned_ip', 'subnet_mask', 'router', 'server_ip', 'name_server', 
        'resolved_ip', 'static_routes'
    }
    
    # 定义功能支持相关的键（这些键反映了路由器的功能差异）
    feature_support_keys = {
        'option12_support', 'option81_support', 'option114_support', 'option121_support',
        'option114_content', 'dns_registered', 'lease_time', 'status', 'option81_in_ack', 
        'option114_in_ack', 'option121_in_ack', 'completeness_score'
    }

    print("\n--- 详细值对比 ---")
    print(f"{'测试项目':<20} | {'结果 @ ' + r1_name:<30} | {'结果 @ ' + r2_name:<30} | {'差异类型':<12}")
    print("-"*100)

    for key in all_keys:
        val1 = str(r1_res.get(key, "N/A"))
        val2 = str(r2_res.get(key, "N/A"))
        
        # 确定差异类型
        if val1 == val2:
            diff_type = "无差异"
            marker = ""
        elif key in network_location_keys:
            diff_type = "网络差异"
            marker = " N"  # N for Network difference
        elif key in feature_support_keys:
            diff_type = "功能差异"
            marker = " F"  # F for Feature difference
        else:
            diff_type = "未知差异"
            marker = " ?"
        
        # 对于IP地址类值，检查它们是否在相同网段
        if key in ('assigned_ip', 'router', 'server_ip', 'name_server', 'resolved_ip') and val1 != "N/A" and val2 != "N/A":
            try:
                # 尝试提取IP地址的网段部分（前三个字节）进行比较
                subnet1 = '.'.join(val1.split('.')[:3])
                subnet2 = '.'.join(val2.split('.')[:3])
                if subnet1 != subnet2:
                    diff_type = "网络差异"
                    marker = " N"
            except:
                # 如果格式不是典型IP地址，则忽略
                pass
        
        print(f"{key:<20} | {val1:<30} | {val2:<30} | {diff_type:<12}{marker}")

    print("="*100)
    print("差异类型说明:")
    print("  无差异 - 两个路由器的行为完全相同")
    print("  网络差异 (N) - 由于不同网段配置导致的预期差异，通常不代表路由器行为差异")
    print("  功能差异 (F) - 反映路由器功能实现或配置的实质差异")
    print("  未知差异 (?) - 未分类的差异")

def analyze_behavior_difference(r1_name, r1_res, r2_name, r2_res):
    """分析两台路由器在行为和策略上的差异，并返回结构化的差异报告"""
    findings = {
        "规范性与完整性": [],
        "配置策略与性格": [],
        "功能支持与扩展": [],
        "客户端识别策略": [],  
        "厂商特定功能": [],
        "服务发现支持": [],     
        "安全处理与边界测试": [], 
        "状态机与资源管理": [], 
        "协议实现年代与完整性": [], 
        "时空维度安全性": [],    # 为第七梯队测试添加新类别
        "协议方言与结构完整性": [],  # 为第八梯队测试添加新类别
    }
    
    # 1. 分析规范性与完整性差异 - DHCP服务器提供的核心信息是否完整
    r1_completeness = analyze_dhcp_completeness(r1_res)
    r2_completeness = analyze_dhcp_completeness(r2_res)
    
    if r1_completeness != r2_completeness:
        findings["规范性与完整性"].append(
            f"{r1_name} 提供了 {r1_completeness} 分的DHCP核心信息，而 {r2_name} 提供了 {r2_completeness} 分 "
            f"(满分10分，包括IP地址、子网掩码、默认网关和DNS服务器)"
        )
    
    # 如果分数相同但有差异的缺失项
    r1_missing = r1_res.get("missing_options", [])
    r2_missing = r2_res.get("missing_options", [])
    if r1_missing != r2_missing:
        only_r1_missing = set(r1_missing) - set(r2_missing)
        only_r2_missing = set(r2_missing) - set(r1_missing)
        
        if only_r1_missing:
            findings["规范性与完整性"].append(f"{r1_name} 缺少了 {', '.join(only_r1_missing)} 选项")
        if only_r2_missing:
            findings["规范性与完整性"].append(f"{r2_name} 缺少了 {', '.join(only_r2_missing)} 选项")
    
    # 2. 分析配置策略与性格差异
    # 租约时间分析
    r1_lease = r1_res.get('lease_time', 'N/A')
    r2_lease = r2_res.get('lease_time', 'N/A')
    
    if r1_lease != 'N/A' and r2_lease != 'N/A':
        try:
            r1_lease_int = int(r1_lease)
            r2_lease_int = int(r2_lease)
            
            if r1_lease_int != r2_lease_int:
                # 解释租期差异的可能原因
                r1_style = lease_time_personality(r1_lease_int)
                r2_style = lease_time_personality(r2_lease_int)
                
                findings["配置策略与性格"].append(
                    f"{r1_name} 的默认租期为 {r1_lease} 秒 ({r1_style})，"
                    f"而 {r2_name} 的默认租期为 {r2_lease} 秒 ({r2_style})"
                )
        except:
            pass
    
    # 3. 分析功能支持差异
    # 主机名/FQDN注册支持
    for option_name, result_key, description in [
        ('DNS注册', 'dns_registered', '通过DHCP选项12(主机名)注册DNS'),
        ('FQDN支持', 'option81_support', '支持选项81(全限定域名)'),
        ('强制门户', 'option114_support', '支持选项114(强制门户URL)'),
        ('静态路由', 'option121_support', '支持选项121(无类静态路由)')
    ]:
        r1_support = r1_res.get(result_key, 'N/A') 
        r2_support = r2_res.get(result_key, 'N/A')
        
        if r1_support != r2_support and r1_support != 'N/A' and r2_support != 'N/A':
            if r1_support == '是' and r2_support == '否':
                findings["功能支持与扩展"].append(f"{r1_name} 支持{description}，但 {r2_name} 不支持")
            elif r1_support == '否' and r2_support == '是':
                findings["功能支持与扩展"].append(f"{r2_name} 支持{description}，但 {r1_name} 不支持")
    
    # 4. 分析客户端识别策略差异 (Option 61)
    for key, desc in [
        ('identification_policy', '客户端识别策略'),
        ('custom_id_support', '自定义客户端ID支持'),
        ('mac_change_handling', 'MAC地址变更处理')
    ]:
        r1_val = r1_res.get(key, 'N/A')
        r2_val = r2_res.get(key, 'N/A')
        
        if r1_val != r2_val and r1_val != 'N/A' and r2_val != 'N/A':
            findings["客户端识别策略"].append(f"{r1_name} 的{desc}为「{r1_val}」，而 {r2_name} 为「{r2_val}」")
    
    # 5. 分析厂商特定功能差异 (Option 60/43)
    for key, desc in [
        ('option43_support', '厂商特定信息支持'),
        ('special_vci_handling', '特殊厂商ID处理'),
        ('responsive_vcis', '响应特定厂商ID')
    ]:
        r1_val = r1_res.get(key, 'N/A')
        r2_val = r2_res.get(key, 'N/A')
        
        if key == 'responsive_vcis':
            # 特殊处理列表类型
            r1_list = r1_res.get(key, [])
            r2_list = r2_res.get(key, [])
            
            r1_only = set(r1_list) - set(r2_list)
            r2_only = set(r2_list) - set(r1_list)
            
            if r1_only:
                findings["厂商特定功能"].append(f"{r1_name} 对这些厂商ID有特殊响应，但 {r2_name} 没有: {', '.join(r1_only)}")
            if r2_only:
                findings["厂商特定功能"].append(f"{r2_name} 对这些厂商ID有特殊响应，但 {r1_name} 没有: {', '.join(r2_only)}")
        elif r1_val != r2_val and r1_val != 'N/A' and r2_val != 'N/A':
            findings["厂商特定功能"].append(f"{r1_name} 的{desc}为「{r1_val}」，而 {r2_name} 为「{r2_val}」")
    
    # 6. 分析服务发现支持差异 (Option 42/66/67)
    # NTP服务器支持
    if 'option42_support' in r1_res and 'option42_support' in r2_res:
        if r1_res['option42_support'] != r2_res['option42_support']:
            findings["服务发现支持"].append(
                f"{r1_name} {'提供' if r1_res['option42_support'] == '是' else '不提供'}NTP服务器，而 "
                f"{r2_name} {'提供' if r2_res['option42_support'] == '是' else '不提供'}NTP服务器"
            )
        elif r1_res['option42_support'] == '是' and r2_res['option42_support'] == '是':
            # 两者都支持NTP，但具体配置可能不同
            if 'ntp_analysis' in r1_res and 'ntp_analysis' in r2_res and r1_res['ntp_analysis'] != r2_res['ntp_analysis']:
                findings["服务发现支持"].append(
                    f"{r1_name} 的NTP配置为「{r1_res['ntp_analysis']}」，而 {r2_name} 为「{r2_res['ntp_analysis']}」"
                )
                
    # PXE引导支持
    if 'pxe_support_level' in r1_res and 'pxe_support_level' in r2_res:
        if r1_res['pxe_support_level'] != r2_res['pxe_support_level']:
            findings["服务发现支持"].append(
                f"{r1_name} 的PXE引导支持级别为「{r1_res['pxe_support_level']}」，而 "
                f"{r2_name} 为「{r2_res['pxe_support_level']}」"
            )
            
        # 对比TFTP服务器配置
        if ('tftp_server' in r1_res and 'tftp_server' in r2_res and 
            r1_res['tftp_server'] != 'N/A' and r2_res['tftp_server'] != 'N/A' and
            r1_res['tftp_server'] != r2_res['tftp_server']):
            findings["服务发现支持"].append(
                f"{r1_name} 提供的TFTP服务器地址为「{r1_res['tftp_server']}」，而 "
                f"{r2_name} 为「{r2_res['tftp_server']}」"
            )
    
    # 7. 分析安全处理与边界测试
    # Option 57 (最大消息大小)分析
    if 'option57_compliance' in r1_res and 'option57_compliance' in r2_res:
        if r1_res['option57_compliance'] != r2_res['option57_compliance']:
            findings["安全处理与边界测试"].append(
                f"{r1_name} 对最大消息大小限制的处理为「{r1_res['option57_compliance']}」，而 "
                f"{r2_name} 为「{r2_res['option57_compliance']}」"
            )
    
    # Option 82 (中继代理信息)分析
    if 'option82_handling' in r1_res and 'option82_handling' in r2_res:
        if r1_res['option82_handling'] != r2_res['option82_handling']:
            findings["安全处理与边界测试"].append(
                f"{r1_name} 对中继代理信息的处理为「{r1_res['option82_handling']}」，而 "
                f"{r2_name} 为「{r2_res['option82_handling']}」"
            )
    
    if 'security_score' in r1_res and 'security_score' in r2_res:
        r1_score = r1_res['security_score']
        r2_score = r2_res['security_score']
        if abs(r1_score - r2_score) >= 3:  # 如果安全分数相差较大
            findings["安全处理与边界测试"].append(
                f"{r1_name} 的安全评分为 {r1_score}，而 {r2_name} 为 {r2_score}，"
                f"{'前者更安全' if r1_score > r2_score else '后者更安全'}"
            )
    
    # 8. 分析状态机与资源管理安全性
    # 租约释放安全性分析
    if 'spoof_release_vulnerable' in r1_res and 'spoof_release_vulnerable' in r2_res:
        if r1_res['spoof_release_vulnerable'] != r2_res['spoof_release_vulnerable']:
            findings["状态机与资源管理"].append(
                f"{r1_name} {'容易' if r1_res['spoof_release_vulnerable'] == '是' else '不容易'}受到伪造释放攻击，而 "
                f"{r2_name} {'容易' if r2_res['spoof_release_vulnerable'] == '是' else '不容易'}受到伪造释放攻击"
            )
    
    # DHCP饥饿攻击抵抗力分析
    if 'starvation_resilience' in r1_res and 'starvation_resilience' in r2_res:
        if r1_res['starvation_resilience'] != r2_res['starvation_resilience']:
            findings["状态机与资源管理"].append(
                f"{r1_name} 对DHCP饥饿攻击的抵抗力为「{r1_res['starvation_resilience']}」，而 "
                f"{r2_name} 为「{r2_res['starvation_resilience']}」"
            )
    
    # Option 50政策分析
    if 'option50_policy' in r1_res and 'option50_policy' in r2_res:
        if r1_res['option50_policy'] != r2_res['option50_policy']:
            findings["状态机与资源管理"].append(
                f"{r1_name} 对客户端请求特定IP的策略为「{r1_res['option50_policy']}」，而 "
                f"{r2_name} 为「{r2_res['option50_policy']}」"
            )
    
    # 安全评分对比
    for key in ['security_score', 'resilience_score', 'policy_score']:
        if key in r1_res and key in r2_res:
            r1_score = r1_res[key]
            r2_score = r2_res[key]
            if abs(r1_score - r2_score) >= 3:  # 如果评分相差较大
                findings["状态机与资源管理"].append(
                    f"{r1_name} 的{key.replace('_score', '')}评分为 {r1_score}，而 {r2_name} 为 {r2_score}，"
                    f"{'前者更安全' if r1_score > r2_score else '后者更安全'}"
                )
    
    # 9. 分析协议实现年代与完整性
    # Option 80 (Rapid Commit)分析
    if 'option80_support' in r1_res and 'option80_support' in r2_res:
        if r1_res['option80_support'] != r2_res['option80_support']:
            findings["协议实现年代与完整性"].append(
                f"{r1_name} {'支持' if r1_res['option80_support'] == '是' else '不支持'}快速提交功能，而 "
                f"{r2_name} {'支持' if r2_res['option80_support'] == '是' else '不支持'}此功能"
            )
            
            if 'performance_rating' in r1_res and 'performance_rating' in r2_res:
                r1_perf = r1_res['performance_rating']
                r2_perf = r2_res['performance_rating']
                if abs(r1_perf - r2_perf) >= 3:
                    findings["协议实现年代与完整性"].append(
                        f"{r1_name} 的效率评分为 {r1_perf}，而 {r2_name} 为 {r2_perf}，"
                        f"{'前者效率更高' if r1_perf > r2_perf else '后者效率更高'}"
                    )
    
    # Option 77 (User Class)分析
    if 'user_class_sensitivity' in r1_res and 'user_class_sensitivity' in r2_res:
        if r1_res['user_class_sensitivity'] != r2_res['user_class_sensitivity']:
            findings["协议实现年代与完整性"].append(
                f"{r1_name} 对用户类别的敏感度为「{r1_res['user_class_sensitivity']}」，而 "
                f"{r2_name} 为「{r2_res['user_class_sensitivity']}」"
            )
            
        if 'special_policies_found' in r1_res and 'special_policies_found' in r2_res:
            r1_policies = r1_res.get('special_policies_found', 0)
            r2_policies = r2_res.get('special_policies_found', 0)
            
            if r1_policies > 0 or r2_policies > 0:
                if r1_policies > r2_policies:
                    findings["协议实现年代与完整性"].append(
                        f"{r1_name} 有更丰富的用户类别策略 ({r1_policies} 种)，可能适用于更复杂的网络环境"
                    )
                elif r2_policies > r1_policies:
                    findings["协议实现年代与完整性"].append(
                        f"{r2_name} 有更丰富的用户类别策略 ({r2_policies} 种)，可能适用于更复杂的网络环境"
                    )
    
    # Option 33 (Static Route)分析
    if 'code_age' in r1_res and 'code_age' in r2_res:
        if r1_res['code_age'] != r2_res['code_age']:
            findings["协议实现年代与完整性"].append(
                f"{r1_name} 的代码库特征为「{r1_res['code_age']}」，而 {r2_name} 为「{r2_res['code_age']}」"
            )
    
    # Option 119 (Domain Search)分析
    if 'dns_integration' in r1_res and 'dns_integration' in r2_res:
        if r1_res['dns_integration'] != r2_res['dns_integration']:
            findings["协议实现年代与完整性"].append(
                f"{r1_name} 的DNS集成度为「{r1_res['dns_integration']}」，而 {r2_name} 为「{r2_res['dns_integration']}」"
            )
    
    if 'multi_domain_support' in r1_res and 'multi_domain_support' in r2_res:
        if r1_res['multi_domain_support'] != r2_res['multi_domain_support']:
            findings["协议实现年代与完整性"].append(
                f"{r1_name} {'支持' if r1_res['multi_domain_support'] == '是' else '不支持'}多域名搜索，而 "
                f"{r2_name} {'支持' if r2_res['multi_domain_support'] == '是' else '不支持'}多域名搜索"
            )
    
    # 10. 分析时空维度安全性
    # 租约续订时序安全分析
    if 'time_validation' in r1_res and 'time_validation' in r2_res:
        if r1_res['time_validation'] != r2_res['time_validation']:
            findings["时空维度安全性"].append(
                f"{r1_name} {'执行' if r1_res['time_validation'] == '是' else '不执行'}租约续订时序验证，而 "
                f"{r2_name} {'执行' if r2_res['time_validation'] == '是' else '不执行'}租约续订时序验证"
            )
    
    if 'source_validation' in r1_res and 'source_validation' in r2_res:
        if r1_res['source_validation'] != r2_res['source_validation']:
            findings["时空维度安全性"].append(
                f"{r1_name} {'执行' if r1_res['source_validation'] == '是' else '不执行'}续订请求源验证，而 "
                f"{r2_name} {'执行' if r2_res['source_validation'] == '是' else '不执行'}续订请求源验证"
            )
    
    # 跨子网请求安全分析
    if 'subnet_leakage_detected' in r1_res and 'subnet_leakage_detected' in r2_res:
        if r1_res['subnet_leakage_detected'] != r2_res['subnet_leakage_detected']:
            vulnerable_router = r1_name if r1_res['subnet_leakage_detected'] == '是' else r2_name
            findings["时空维度安全性"].append(
                f"{vulnerable_router} 存在子网信息泄露风险，会向伪造的跨子网请求分配IP地址"
            )
    
    if 'topology_security_level' in r1_res and 'topology_security_level' in r2_res:
        r1_level = r1_res['topology_security_level']
        r2_level = r2_res['topology_security_level']
        if r1_level != r2_level:
            findings["时空维度安全性"].append(
                f"{r1_name} 的网络拓扑安全级别为「{r1_level}」，而 {r2_name} 为「{r2_level}」"
            )
    
    # 11. 分析协议方言与结构完整性
    # BOOTP遗留协议支持分析
    if 'bootp_support' in r1_res and 'bootp_support' in r2_res:
        if r1_res['bootp_support'] != r2_res['bootp_support']:
            findings["协议方言与结构完整性"].append(
                f"{r1_name} {'支持' if r1_res['bootp_support'] == '是' else '不支持'}BOOTP遗留协议，而 "
                f"{r2_name} {'支持' if r2_res['bootp_support'] == '是' else '不支持'}BOOTP遗留协议"
            )
            
        # 如果两个路由器都支持BOOTP，比较它们的代码年代
        if r1_res['bootp_support'] == '是' and r2_res['bootp_support'] == '是':
            if 'code_age' in r1_res and 'code_age' in r2_res and r1_res['code_age'] != r2_res['code_age']:
                findings["协议方言与结构完整性"].append(
                    f"{r1_name} 的BOOTP代码特征为「{r1_res['code_age']}」，而 {r2_name} 为「{r2_res['code_age']}」"
                )
    
    # BOOTP畸形包处理分析
    if 'validation_quality' in r1_res and 'validation_quality' in r2_res:
        if r1_res['validation_quality'] != r2_res['validation_quality']:
            findings["协议方言与结构完整性"].append(
                f"{r1_name} 的协议验证质量为「{r1_res['validation_quality']}」，而 {r2_name} 为「{r2_res['validation_quality']}」"
            )
    
    # 选项重载字段解析健壮性分析
    if 'parser_robustness' in r1_res and 'parser_robustness' in r2_res:
        if r1_res['parser_robustness'] != r2_res['parser_robustness']:
            findings["协议方言与结构完整性"].append(
                f"{r1_name} 的DHCP选项解析健壮性为「{r1_res['parser_robustness']}」，而 {r2_name} 为「{r2_res['parser_robustness']}」"
            )
            
        if 'server_crashed' in r1_res and r1_res.get('server_crashed') == '是':
            findings["协议方言与结构完整性"].append(
                f"{r1_name} 在选项重载测试中崩溃，存在严重的缓冲区溢出漏洞风险"
            )
        if 'server_crashed' in r2_res and r2_res.get('server_crashed') == '是':
            findings["协议方言与结构完整性"].append(
                f"{r2_name} 在选项重载测试中崩溃，存在严重的缓冲区溢出漏洞风险"
            )
    
    # IP分片处理健壮性分析
    if 'network_stack_robustness' in r1_res and 'network_stack_robustness' in r2_res:
        if r1_res['network_stack_robustness'] != r2_res['network_stack_robustness']:
            findings["协议方言与结构完整性"].append(
                f"{r1_name} 的网络栈健壮性为「{r1_res['network_stack_robustness']}」，而 {r2_name} 为「{r2_res['network_stack_robustness']}」"
            )
            
        # 分析是否有路由器在IP分片测试中崩溃
        if 'server_crashed' in r1_res and r1_res.get('server_crashed') == '是':
            recovery = "能自动恢复" if r1_res.get('router_recovered') == '是' else "无法自动恢复"
            findings["协议方言与结构完整性"].append(
                f"{r1_name} 在IP分片测试中崩溃（{recovery}），存在网络栈拒绝服务漏洞风险"
            )
        if 'server_crashed' in r2_res and r2_res.get('server_crashed') == '是':
            recovery = "能自动恢复" if r2_res.get('router_recovered') == '是' else "无法自动恢复"
            findings["协议方言与结构完整性"].append(
                f"{r2_name} 在IP分片测试中崩溃（{recovery}），存在网络栈拒绝服务漏洞风险"
            )
    
    # 如果某个类别没有发现差异，则移除该类别
    return {k: v for k, v in findings.items() if v}

def print_option_support_summary(all_test_results):
    """打印所有测试的选项支持情况摘要"""
    summary_table = {}
    
    for test_name, results in all_test_results.items():
        for router_name, result in results.items():
            if router_name not in summary_table:
                summary_table[router_name] = {
                    "option12_support": "否",
                    "option81_support": "否",
                    "option114_support": "否",
                    "option121_support": "否",
                    "dns_registered": "否",
                    "option42_support": "否",
                    "option66_support": "否",
                    "option67_support": "否",
                    "option57_compliance": "未测试",
                    "option82_handling": "未测试",
                    "spoof_release_vulnerable": "未测试",
                    "starvation_vulnerable": "未测试",
                    "option50_policy": "未测试",
                    "option80_support": "未测试",
                    "user_class_sensitivity": "未测试",
                    "option33_support": "未测试",
                    "option119_support": "未测试",
                    "time_validation": "未测试",
                    "source_validation": "未测试",
                    "subnet_leakage_detected": "未测试",
                    "topology_security_level": "未测试",
                    # 第八梯队测试结果
                    "bootp_support": "未测试",
                    "bootp_validation_quality": "未测试",
                    "parser_robustness": "未测试",
                    "network_stack_robustness": "未测试",
                }
            
            # 根据测试结果更新支持情况
            if result.get("status") == "成功":
                for opt_key in ["option12_support", "option81_support", "option114_support", 
                               "option121_support", "dns_registered", "option42_support",
                               "option66_support", "option67_support"]:
                    if result.get(opt_key) == "是":
                        summary_table[router_name][opt_key] = "是"
                
                # 特殊处理各种选项
                if "option57_compliance" in result:
                    summary_table[router_name]["option57_compliance"] = result["option57_compliance"]
                if "option82_handling" in result:
                    summary_table[router_name]["option82_handling"] = result["option82_handling"]
                    
                # 处理第五梯队测试结果
                if "spoof_release_vulnerable" in result:
                    summary_table[router_name]["spoof_release_vulnerable"] = result["spoof_release_vulnerable"]
                if "starvation_vulnerable" in result:
                    summary_table[router_name]["starvation_vulnerable"] = result["starvation_vulnerable"]
                if "option50_policy" in result:
                    summary_table[router_name]["option50_policy"] = result["option50_policy"]
                    
                # 处理第六梯队测试结果
                if "option80_support" in result:
                    summary_table[router_name]["option80_support"] = result["option80_support"]
                if "user_class_sensitivity" in result:
                    summary_table[router_name]["user_class_sensitivity"] = result["user_class_sensitivity"]
                if "option33_support" in result:
                    summary_table[router_name]["option33_support"] = result["option33_support"]
                if "option119_support" in result:
                    summary_table[router_name]["option119_support"] = result["option119_support"]
                
                # 处理第八梯队测试结果
                if "bootp_support" in result:
                    summary_table[router_name]["bootp_support"] = result["bootp_support"]
                if "validation_quality" in result:
                    summary_table[router_name]["bootp_validation_quality"] = result["validation_quality"]
                if "parser_robustness" in result:
                    summary_table[router_name]["parser_robustness"] = result["parser_robustness"]
                if "network_stack_robustness" in result:
                    summary_table[router_name]["network_stack_robustness"] = result["network_stack_robustness"]
    
    # 打印表头
    print("\n--- 选项支持情况汇总 ---")
    print(f"{'路由器名称':<15} | {'选项12':<10} | {'选项81':<10} | {'选项114':<10} | {'选项121':<10} | {'DNS注册':<10} | {'NTP服务':<10} | {'TFTP服务':<10} | {'引导文件':<10}")
    print("-"*110)
    
    # 打印每个路由器的支持情况
    for router_name, supports in summary_table.items():
        print(f"{router_name:<15} | {supports['option12_support']:<10} | {supports['option81_support']:<10} | "
              f"{supports['option114_support']:<10} | {supports['option121_support']:<10} | {supports['dns_registered']:<10} | "
              f"{supports['option42_support']:<10} | {supports['option66_support']:<10} | {supports['option67_support']:<10}")
    
    # 打印安全和边界测试结果
    print("\n--- 安全与边界测试结果 ---")
    print(f"{'路由器名称':<15} | {'最大消息大小(选项57)':<25} | {'中继代理信息(选项82)':<25}")
    print("-"*70)
    
    for router_name, supports in summary_table.items():
        print(f"{router_name:<15} | {supports['option57_compliance']:<25} | {supports['option82_handling']:<25}")
    
    # 打印状态机和资源管理测试结果
    print("\n--- 状态机与资源管理测试结果 ---")
    print(f"{'路由器名称':<15} | {'伪造释放攻击易受性':<20} | {'DHCP饥饿攻击抵抗力':<20} | {'客户端指定IP策略':<25}")
    print("-"*85)
    
    for router_name, supports in summary_table.items():
        print(f"{router_name:<15} | {supports['spoof_release_vulnerable']:<20} | {supports['starvation_vulnerable']:<20} | {supports['option50_policy']:<25}")
    
    # 打印协议实现年代与完整性测试结果
    print("\n--- 协议实现年代与完整性测试结果 ---")
    print(f"{'路由器名称':<15} | {'Rapid Commit':<15} | {'用户类别敏感度':<15} | {'静态路由(旧)':<15} | {'域名搜索列表':<15}")
    print("-"*80)
    
    for router_name, supports in summary_table.items():
        print(f"{router_name:<15} | {supports['option80_support']:<15} | {supports['user_class_sensitivity']:<15} | "
              f"{supports['option33_support']:<15} | {supports['option119_support']:<15}")
    
    # 打印时空维度测试结果
    print("\n--- 时空维度安全测试结果 ---")
    print(f"{'路由器名称':<15} | {'续约时序验证':<15} | {'续约源验证':<15} | {'子网信息泄露':<15} | {'拓扑安全级别':<15}")
    print("-"*80)
    
    for router_name, supports in summary_table.items():
        print(f"{router_name:<15} | {supports['time_validation']:<15} | {supports['source_validation']:<15} | "
              f"{supports['subnet_leakage_detected']:<15} | {supports['topology_security_level']:<15}")
              
    # 打印协议方言与结构完整性测试结果
    print("\n--- 协议方言与结构完整性测试结果 ---")
    print(f"{'路由器名称':<15} | {'BOOTP支持':<15} | {'协议验证质量':<15} | {'选项解析健壮性':<15} | {'网络栈健壮性':<15}")
    print("-"*80)
    
    for router_name, supports in summary_table.items():
        print(f"{router_name:<15} | {supports['bootp_support']:<15} | {supports['bootp_validation_quality']:<15} | "
              f"{supports['parser_robustness']:<15} | {supports['network_stack_robustness']:<15}")

def print_single_target_report(test_name, result):
    """打印单个目标的测试报告，无需对比"""
    print("\n" + "="*80)
    print(f"DHCP 测试报告: {test_name}")
    print("="*80)
    
    if result['status'] != '成功':
        print(f"测试状态: {result['status']}")
        print(f"失败原因: {result.get('reason', 'Unknown')}")
        return
        
    print(f"测试状态: {result['status']}")
    
    # 打印详细结果
    print("\n--- 详细测试结果 ---")
    for key, value in sorted(result.items()):
        # 跳过不需要显示的元数据
        if key in ['status', 'reason']:
            continue
            
        # 格式化输出
        print(f"{key:<25}: {value}")
    
    # 如果有完整性分析，单独显示
    if 'completeness_score' in result:
        print("\n--- DHCP服务完整性分析 ---")
        print(f"完整性得分: {result['completeness_score']}/10")
        if 'missing_options' in result and result['missing_options']:
            print(f"缺少选项: {', '.join(result['missing_options'])}")
        else:
            print("所有核心DHCP选项均已提供")
            
    # 如果有安全分析，单独显示
    if any(key in result for key in ['security_score', 'resilience_score', 'policy_score']):
        print("\n--- 安全性分析 ---")
        if 'security_score' in result:
            print(f"安全评分: {result['security_score']}/10")
        if 'resilience_score' in result:
            print(f"抵抗力评分: {result['resilience_score']}/10")
        if 'policy_score' in result:
            print(f"策略评分: {result['policy_score']}/10")
            
    print("="*80)

def analyze_dhcp_completeness(result):
    """
    分析DHCP服务器响应的完整性，返回一个0-10的分数
    评分标准：
    - 提供IP地址: +3分
    - 提供子网掩码: +2分
    - 提供默认网关: +3分
    - 提供DNS服务器: +2分
    """
    score = 0
    missing_options = []
    
    # IP地址检查 (必须项)
    if result.get('assigned_ip', 'N/A') != 'N/A':
        score += 3
    else:
        missing_options.append("IP地址")
    
    # 子网掩码检查
    if result.get('subnet_mask', 'N/A') != 'N/A':
        score += 2
    else:
        missing_options.append("子网掩码")
    
    # 默认网关检查
    if result.get('router', 'N/A') != 'N/A':
        score += 3
    else:
        missing_options.append("默认网关")
    
    # DNS服务器检查
    if result.get('name_server', 'N/A') != 'N/A':
        score += 2
    else:
        missing_options.append("DNS服务器")
    
    # 将结果存回字典中，方便后续使用
    result['completeness_score'] = score
    result['missing_options'] = missing_options
    
    return score

def lease_time_personality(lease_time):
    """根据租期时间推断路由器的"性格"或适用场景"""
    if lease_time <= 3600:  # 1小时或更短
        return "适合高流动性环境，如咖啡馆、会议室"
    elif lease_time <= 14400:  # 4小时
        return "适合中等流动性环境，如学校、图书馆"
    elif lease_time <= 43200:  # 12小时
        return "适合低流动性环境，如办公室"
    elif lease_time <= 86400:  # 24小时
        return "适合固定环境，如家庭网络"
    else:  # 超过24小时
        return "适合非常稳定的环境，如企业专用网络"

# --- 3. 主控制器 ---
if __name__ == "__main__":
    all_tests = {
        "标准DORA流程": run_standard_dora_test,
        "Option 12 主机名测试": run_option12_test,
        "Option 81 FQDN测试": run_option81_test,
        "Option 114 强制门户测试": run_option114_test,
        "Option 121 静态路由测试": run_option121_test,
        "健壮性-未知选项测试": test_unknown_option,
        "健壮性-畸形选项测试": test_malformed_option,
        "Option 61 客户端标识符测试": test_option61,
        "Option 60 厂商类型标识符测试": test_option60,
        "Option 43 厂商特定信息测试": test_option43,
        "Option 42 NTP服务器测试": test_option42,
        "Option 66/67 PXE引导测试": test_option66_67,
        "Option 57 最大消息大小测试": run_option57_test,
        "Option 82 中继代理信息测试": run_option82_test,
        "租约操纵-伪造释放测试": run_lease_security_test,
        "资源耗尽-DHCP饥饿攻击测试": run_starvation_test,
        "Option 50 客户端指定IP测试": run_option50_test,
        "Option 80 快速提交测试": run_option80_test,
        "Option 77 用户类别测试": run_option77_test,
        "Option 33 静态路由(旧)测试": run_option33_test,
        "Option 119 域名搜索列表测试": run_option119_test,
        "租约续订时序攻击测试": run_renewal_timing_test,
        "跨子网IP请求测试": run_cross_subnet_test,
        # 第八梯队测试
        "BOOTP遗留协议回退测试": test_bootp_legacy,
        "选项重载字段损坏攻击": test_overload_corruption,
        "IP分片攻击": test_ip_fragmentation,
    }

    # 创建一个字典来存储所有测试的结果
    all_test_results = {}
    target_name = list(TARGETS.keys())[0]  # 只有一个目标
    target_iface = TARGETS[target_name]

    print(f"\n[===] 开始测试目标: {target_name} (网卡: {target_iface}) [===]")
    
    for test_name, test_function in all_tests.items():
        print(f"\n[>>>] 正在执行测试套件: '{test_name}' [<<<]")
        
        result = test_function(target_iface)
        # 存储结果
        all_test_results[test_name] = {target_name: result}
        
        # 直接打印单一目标的结果报告
        print_single_target_report(test_name, result)
    
    # 打印所有测试的选项支持情况摘要
    print("\n\n[===] VPS DHCP服务器特性和安全分析摘要 [===]")
    print_option_support_summary(all_test_results)