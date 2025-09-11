# dhcp_fuzzer_robust.py

import logging
import random
import time
import sys
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.utils import mac2str

# --- 日志记录功能 (保持不变) ---
class Logger(object):
    def __init__(self, filename="fuzz.log"):
        self.terminal = sys.stdout
        self.log = open(filename, 'w', encoding='utf-8')

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()

sys.stdout = Logger('fuzz.log')
sys.stderr = sys.stdout
# ------------------------------------

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- 配置 ---
INTERFACE_NAME = "ens37" 
conf.iface = INTERFACE_NAME

print(f"[*] Fuzzing将在网卡 '{conf.iface}' 上进行。")
print("[!] 警告: 本脚本会发送大量畸形DHCP包，可能导致网络服务中断。")
print("[!] 请确保你已获得授权，并在隔离的测试环境中运行。")
print("[*] 5秒后开始 Fuzzing... 按 Ctrl+C 停止。")
time.sleep(5)


def generate_random_mac():
    return "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                        random.randint(0, 255),
                                        random.randint(0, 255))

def generate_fuzzed_payload():
    """
    【已修改】这个函数现在只生成畸形的TLV字节块作为原始负载。
    它不再关心message-type或其他合法options。
    """
    payload_len = random.randint(1, 255)
    fuzz_payload = b''.join(bytes([random.randint(0, 255)]) for _ in range(payload_len))

    if random.choice([True, False]):
        code = 55
        print(f"[*] Fuzzing 策略: 生成畸形 param_req_list (Code 55) 负载，长度 {payload_len}")
    else:
        code = random.randint(128, 254) # 使用一个更大的范围
        print(f"[*] Fuzzing 策略: 生成畸形自定义 Option (Code {code}) 负载，长度 {payload_len}")

    # 只返回手动构建的 TLV (Type-Length-Value) 字节串
    return bytes([code, payload_len]) + fuzz_payload

# ----------------------------------------------------------------------------------
# Fuzzing 主循环
# ----------------------------------------------------------------------------------
iteration = 0
while True:
    try:
        iteration += 1
        print(f"\n{'='*50}")
        print(f"[*] Fuzzing 迭代 #{iteration}")
        print(f"{'='*50}")

        MY_MAC = generate_random_mac()
        TRANSACTION_ID = random.randint(1, 0xFFFFFFFF)
        
        print(f"[*] 本轮使用 MAC: {MY_MAC}")
        print(f"[*] 本轮使用会话 ID (xid): {hex(TRANSACTION_ID)}")

        # --- (D)iscover: 【逻辑修正】永远发送标准的、合法的包 ---
        print("\n--- 步骤 1: 发送 标准 DHCP DISCOVER ---")
        dhcp_discover = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags=0x8000) /
            DHCP(options=[("message-type", "discover"), ("end")])
        )
        resp = srp1(dhcp_discover, iface=INTERFACE_NAME, timeout=5, verbose=False)

        # --- (O)ffer: 正常等待和解析 ---
        print("\n--- 步骤 2: 等待并解析 DHCP OFFER ---")
        if resp is None or not resp.haslayer(DHCP):
            print("[!] 未收到有效的 DHCP OFFER 响应。请检查网络环境或DHCP服务器是否正常运行。")
            time.sleep(2)
            continue

        if resp[BOOTP].xid != TRANSACTION_ID:
            print("[!] 收到的OFFER xid不匹配，忽略。")
            continue
            
        offered_ip = resp[BOOTP].yiaddr
        server_ip = resp[DHCP].get_option_by_name('server_id')
        
        if not server_ip:
            print("[!] OFFER包中未找到Server ID。")
            continue

        print(f"[+] 成功收到 DHCP OFFER! IP: {offered_ip}, Server: {server_ip}")

        # --- (R)equest: 发送一个携带Fuzzed负载的包 ---
        print("\n--- 步骤 3: 发送 Fuzzed DHCP REQUEST ---")
        
        # 1. 先构建一个包含所有合法options的DHCP层
        dhcp_options_base = DHCP(options=[
            ("message-type", "request"),
            ("requested_addr", offered_ip),
            ("server_id", server_ip),
            ("end")
        ])
        
        # 2. 生成畸形负载
        fuzzed_payload = generate_fuzzed_payload()
        
        # 3. 【代码修正】使用 / 操作符将畸形负载作为Raw()层附加在后面
        dhcp_request_packet = (
            Ether(src=MY_MAC, dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac2str(MY_MAC), xid=TRANSACTION_ID, flags=0x8000) /
            dhcp_options_base / Raw(fuzzed_payload)  # <--- 这是最关键的修复！
        )

        resp_ack = srp1(dhcp_request_packet, iface=INTERFACE_NAME, timeout=5, verbose=False)

        # --- (A)cknowledgment: 观察Fuzzing结果 ---
        print("\n--- 步骤 4: 等待并解析 DHCP ACK/NAK ---")
        if resp_ack is None:
            print("[!] 未收到 DHCP ACK/NAK 包。服务器可能在处理我们畸形的REQUEST时崩溃或超时！")
            print("[!] 这是一个非常重要的 Fuzzing 成功结果！")
            continue

        msg_type = resp_ack[DHCP].get_option_by_name('message-type')

        if msg_type == 5:
            print(f"[+] 收到 DHCP ACK! IP {resp_ack[BOOTP].yiaddr} 已确认。服务器在此次Fuzzing中幸存。")
        elif msg_type == 6:
            print("[!] 收到 DHCP NAK (拒绝)。服务器正常拒绝了我们的畸形请求。这也是一种成功防御。")
        else:
            print(f"[?] 收到未知的DHCP消息类型: {msg_type}。")

        time.sleep(0.5)

    except KeyboardInterrupt:
        print("\n[*] Fuzzing被用户手动停止。")
        sys.exit()
    except Exception as e:
        print(f"[!!!] 在迭代 #{iteration} 中发生未知错误: {e}")
        # 即使有错误，也打印分割线，保持日志清晰
        print(f"{'='*50}")
        continue