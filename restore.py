from scapy.all import *

DEFAULT_GATEWAY = "192.168.1.1"
TARGET_IP = "192.168.1.80"

def restore(destination_ip, source_ip):
    arp_reply = ARP(op = 2, pdst = destination_ip, hwdst = getmacbyip(destination_ip), psrc = source_ip, hwsrc = getmacbyip(source_ip))
    send(arp_reply, verbose = False)

restore(DEFAULT_GATEWAY, TARGET_IP)
restore(TARGET_IP, DEFAULT_GATEWAY)