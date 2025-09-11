#!/usr/bin/env python3

from scapy.all import *
import logging

# 关闭 Scapy 的一些警告信息
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# 配置监听接口
INTERFACE_NAME = "ens37"
conf.iface = INTERFACE_NAME

print(f"[*] 开始在 {INTERFACE_NAME} 接口上监听 DHCP 流量...")
print("[*] 按 Ctrl+C 停止监听")

# 回调函数，用于处理捕获到的数据包
def packet_handler(pkt):
    if DHCP in pkt:
        message_type = None
        for opt in pkt[DHCP].options:
            if opt[0] == 'message-type':
                message_type = opt[1]
                break
        
        print("-" * 60)
        print(f"DHCP {get_message_type_name(message_type)} 包:")
        if BOOTP in pkt:
            print(f"XID: {hex(pkt[BOOTP].xid)}")
            print(f"Client IP: {pkt[BOOTP].ciaddr}")
            print(f"Your IP: {pkt[BOOTP].yiaddr}")
            print(f"Server IP: {pkt[BOOTP].siaddr}")
            print(f"Gateway IP: {pkt[BOOTP].giaddr}")
        if IP in pkt:
            print(f"Source IP: {pkt[IP].src}")
            print(f"Dest IP: {pkt[IP].dst}")
        if Ether in pkt:
            print(f"Source MAC: {pkt[Ether].src}")
            print(f"Dest MAC: {pkt[Ether].dst}")
        print("-" * 60)

# DHCP 消息类型的名称映射
def get_message_type_name(type_value):
    types = {
        1: "DISCOVER",
        2: "OFFER",
        3: "REQUEST",
        4: "DECLINE",
        5: "ACK",
        6: "NAK",
        7: "RELEASE",
        8: "INFORM"
    }
    return types.get(type_value, f"UNKNOWN({type_value})")

# 开始嗅探数据包
try:
    sniff(filter="udp and (port 67 or port 68)", prn=packet_handler, store=0)
except KeyboardInterrupt:
    print("\n[*] 监听已停止")
