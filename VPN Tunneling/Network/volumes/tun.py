#!/usr/bin/env python3

import fcntl
import struct
import os
import time
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_TAP   = 0x0002
IFF_NO_PI = 0x1000

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'C8677%d', IFF_TUN | IFF_NO_PI)
ifname_bytes  = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))


#CREATING TUNNEL INTERFACE
os.system("ip addr add 192.168.73.99/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

#Running the Router so that the Tunnel keeps running in back-end
while True:
  # Get a packet from the tun interface
  packet = os.read(tun, 2048)
  if packet:
    ipPkt = IP(packet)
    print("{}:".format(ifname), ipPkt.summary())
    
    # Sending Spoof packets through Tunnel Interface
    #newip = IP(src=’1.2.3.4’, dst=ip.src)
    #newpkt = newip/ip.payload
    #Improving the Code to check with the ICMP Sniff and Spoof
    if ICMP in ipPkt and ipPkt[ICMP].type == 8:
        print("Original Packet.........")
        print("Source ip address: ", ipPkt[IP].src)
        print("Destination ip address :", ipPkt[IP].dst)

        # spoof an icmp echo reply packet
        # swap srcip and dstip
        ip = IP(src=ipPkt[IP].dst, dst=ipPkt[IP].src, ihl=ipPkt[IP].ihl)
        icmp = ICMP(type=0, id=ipPkt[ICMP].id, seq=ipPkt[ICMP].seq)
        data = ipPkt[Raw].load
        newpkt = ip/icmp/data

        print("Spoofing Packet")
        print("Spoof Source ip address : ", newpkt[IP].src)
        print("Spoof Destination ip address :", newpkt[IP].dst)
	
	# Writing BInary Data to the Tunnel Interface 
        dumpData=b'This is Virtual PrivateNetwork'
        # os.write(tun, bytes(newpkt))
        os.write(tun, dumpData)



