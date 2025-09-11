"""
DHCP 差分测试工具的工具函数
"""

import ipaddress

def is_same_subnet(ip1, ip2, netmask=None):
    """
    判断两个IP地址是否在同一子网
    
    参数:
    ip1 (str): 第一个IP地址
    ip2 (str): 第二个IP地址
    netmask (str, 可选): 子网掩码，如果未提供则假定为 255.255.255.0
    
    返回:
    bool: 如果在同一子网则为True，否则为False
    """
    try:
        if netmask is None:
            netmask = "255.255.255.0"  # 默认 /24 子网
            
        ip1_obj = ipaddress.IPv4Address(ip1)
        ip2_obj = ipaddress.IPv4Address(ip2)
        netmask_obj = ipaddress.IPv4Address(netmask)
        
        # 计算网络部分
        network_bits = int(netmask_obj)
        ip1_network = int(ip1_obj) & network_bits
        ip2_network = int(ip2_obj) & network_bits
        
        return ip1_network == ip2_network
    except:
        # 如果输入格式有问题，返回False
        return False

def parse_classless_static_routes(route_bytes):
    """
    解析DHCP Option 121返回的无类静态路由数据
    
    参数:
    route_bytes (bytes): Option 121原始字节数据
    
    返回:
    list: 路由列表，每项包含 {destination, mask_length, gateway}
    """
    routes = []
    i = 0
    
    while i < len(route_bytes):
        # 第一个字节是掩码长度
        mask_length = route_bytes[i]
        i += 1
        
        # 根据掩码长度确定目标网络的字节数
        if mask_length > 0:
            significant_octets = (mask_length + 7) // 8
        else:
            significant_octets = 0  # 默认路由
            
        # 提取目标网络部分
        destination_bytes = bytearray([0, 0, 0, 0])
        for j in range(significant_octets):
            if i < len(route_bytes):
                destination_bytes[j] = route_bytes[i]
                i += 1
                
        # 目标网络字符串表示
        destination = ".".join(str(b) for b in destination_bytes)
        
        # 接下来4个字节是网关
        if i + 3 < len(route_bytes):
            gateway = ".".join(str(route_bytes[i+j]) for j in range(4))
            i += 4
        else:
            gateway = "不完整"
            break
            
        routes.append({
            "destination": destination,
            "mask_length": mask_length,
            "gateway": gateway
        })
        
    return routes

def compare_static_routes(routes1, routes2):
    """
    比较两组静态路由，忽略网络位置特定的差异
    
    参数:
    routes1, routes2: 两组路由数据（字符串或对象）
    
    返回:
    dict: 比较结果 {same_count, total_count, is_functionally_same}
    """
    # 简单情况：如果两者都是N/A或其他相同字符串
    if isinstance(routes1, str) and isinstance(routes2, str):
        if routes1 == routes2:
            return {
                "is_functionally_same": True,
                "same_count": 0 if routes1 == "N/A" else 1,
                "total_count": 0 if routes1 == "N/A" else 1
            }
    
    # 复杂情况：尝试解析并比较
    try:
        # 如果是字符串表示，尝试转换为bytes
        if isinstance(routes1, str) and routes1.startswith("b'"):
            routes1 = eval(routes1)  # 警告：仅在可信输入上使用
            
        if isinstance(routes2, str) and routes2.startswith("b'"):
            routes2 = eval(routes2)  # 警告：仅在可信输入上使用
            
        # 解析路由
        parsed_routes1 = parse_classless_static_routes(routes1)
        parsed_routes2 = parse_classless_static_routes(routes2)
        
        # 比较路由条目数量
        len_1 = len(parsed_routes1)
        len_2 = len(parsed_routes2)
        
        # 功能性相同：如果两者都有路由或都没有
        is_functionally_same = (len_1 > 0) == (len_2 > 0)
        
        return {
            "is_functionally_same": is_functionally_same,
            "same_count": min(len_1, len_2),
            "total_count": max(len_1, len_2),
            "routes1": parsed_routes1,
            "routes2": parsed_routes2
        }
    except:
        # 如果解析失败，返回不同
        return {
            "is_functionally_same": False,
            "same_count": 0,
            "total_count": 1,
            "error": "解析失败"
        }
