from scapy.all import *
import logging
import random
import time
import sys

# 导入我们的两种攻击测试模块
from .dhcp_decline_attack import test_dhcp_decline_attack
from .rapid_release_attack import test_rapid_release_attack

def test_state_machine_security(interface_name, test_type="combined"):
    """
    执行DHCP服务器状态机安全测试
    :param interface_name: 要使用的网络接口名称
    :param test_type: 测试类型，可选 "decline", "rapid_release", "combined"
    :return: 测试结果字典
    """
    print(f"[*] 开始在接口 {interface_name} 上进行DHCP状态机安全测试...")
    
    # 初始化测试结果
    result = {
        "status": "成功",
        "security_score": 0,
        "resilience_score": 0,
        "vulnerability_detected": "否",
        "attack_vectors": [],
    }
    
    try:
        # 根据测试类型执行不同的攻击测试
        if test_type == "decline" or test_type == "combined":
            print("\n[*] 执行DHCP Decline攻击测试...")
            decline_result = test_dhcp_decline_attack(interface_name, num_attacks=3)
            
            if decline_result["status"] == "成功":
                # 分析测试结果
                if decline_result.get("exhaustion_level", 0) > 6:
                    result["vulnerability_detected"] = "是"
                    result["attack_vectors"].append("DHCP Decline攻击")
                
                # 将详细结果合并到主结果中
                result["decline_test"] = {
                    "declined_ips": decline_result.get("declined_ips", []),
                    "total_declined": decline_result.get("total_declined", 0),
                    "address_pool_exhausted": decline_result.get("address_pool_exhausted", False),
                    "server_recovery_time": decline_result.get("server_recovery_time", "N/A"),
                    "exhaustion_level": decline_result.get("exhaustion_level", 0),
                }
                
                # 更新安全评分
                result["security_score"] = max(0, 10 - decline_result.get("exhaustion_level", 0))
            else:
                print(f"[!] Decline攻击测试失败: {decline_result.get('reason', '未知错误')}")
        
        if test_type == "rapid_release" or test_type == "combined":
            print("\n[*] 执行快速释放与重申请测试...")
            release_result = test_rapid_release_attack(interface_name, num_cycles=5)
            
            if release_result["status"] == "成功":
                # 分析测试结果
                if release_result.get("state_machine_resilience", 10) < 5:
                    result["vulnerability_detected"] = "是"
                    result["attack_vectors"].append("快速释放与重申请攻击")
                
                # 将详细结果合并到主结果中
                result["rapid_release_test"] = {
                    "cycles_completed": release_result.get("cycles_completed", 0),
                    "unique_ips_assigned": release_result.get("unique_ips_assigned", 0),
                    "address_reuse_rate": release_result.get("address_reuse_rate", 0),
                    "avg_response_time": release_result.get("avg_response_time", 0),
                    "server_crashed": release_result.get("server_crashed", "否"),
                    "state_machine_resilience": release_result.get("state_machine_resilience", 0),
                }
                
                # 更新弹性评分
                result["resilience_score"] = release_result.get("state_machine_resilience", 0)
            else:
                print(f"[!] 快速释放与重申请测试失败: {release_result.get('reason', '未知错误')}")
        
        # 综合评估
        if test_type == "combined":
            # 计算综合安全评分
            combined_score = (result.get("security_score", 0) + result.get("resilience_score", 0)) / 2
            result["combined_security_score"] = round(combined_score, 1)
            
            # 生成安全评估结论
            if combined_score >= 8:
                result["security_assessment"] = "高安全性 - 服务器对状态机攻击具有很强的抵抗力"
            elif combined_score >= 6:
                result["security_assessment"] = "良好安全性 - 服务器可以抵抗一般的状态机攻击"
            elif combined_score >= 4:
                result["security_assessment"] = "中等安全性 - 服务器对状态机攻击的抵抗力有限"
            else:
                result["security_assessment"] = "低安全性 - 服务器容易受到状态机攻击的影响"
        
        return result
        
    except Exception as e:
        print(f"\n[!] 测试过程中发生异常: {e}")
        return {"status": "异常", "reason": str(e)}