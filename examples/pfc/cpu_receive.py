#!/usr/bin/env python


"""
CPU will always only act as a dumb buffer.
This means that any regular packets that come into the CPU will definitely be stored first.
CPU will also store each packet according to the egress port attribute.
We will define an additional control packet that will release all the packets for that egress port.
When CPU receives this control packet, it will then release.
"""

import sys
import struct
import os
import socket
import time

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption, Ether
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw, ls, TCP
from scapy.layers.inet import _IPOption_HDR

BUFFER_PAUSE_THRESHOLD = 10
BUFFER_RESUME_THRESHOLD = 0

TYPE_CUSTOM = 0x1010
TYPE_PAUSE = 0x1111
TYPE_RESUME = 0x1212

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField("ingress_port",0,16), BitField("egress_port",0,16)]

bind_layers(Ether, CpuHeader, type=TYPE_CUSTOM)
bind_layers(Ether, CpuHeader, type=TYPE_PAUSE)
bind_layers(Ether, CpuHeader, type=TYPE_RESUME)
bind_layers(CpuHeader, IP)
bind_layers(Ether, IP, type=TYPE_CUSTOM)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

# list of cpu interfaces
cpu_interfaces = ['s1-cpu-eth1', 's2-cpu-eth1', 's3-cpu-eth1']

# buffer stores mapping from port to array of packets
cpu_buffer_size = {}
cpu_buffer = {}
for iface in cpu_interfaces:
    cpu_buffer[iface] = {}
    cpu_buffer_size[iface] = 0

def show_cpu_buffer():
    global cpu_buffer
    print "buffer size:", cpu_buffer_size

def send_a_pause_packet(iface, ingress_port, egress_port):
    print "Sending a pause packet from {}, going out port {}".format(iface, ingress_port)
    pause_pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_PAUSE)
    pause_pkt = pause_pkt / CpuHeader(ingress_port=ingress_port, egress_port=egress_port) / IP(dst=socket.gethostbyname("10.0.1.1")) / UDP(dport=1234, sport=4321) / "pause"
    pause_pkt.show2()
    sendp(pause_pkt, iface=iface, verbose=False)

def send_a_resume_packet(iface, ingress_port, egress_port):
    print "Sending a resume packet from {}, going out port {}".format(iface, ingress_port)
    resume_pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_RESUME)
    resume_pkt = resume_pkt / CpuHeader(ingress_port=ingress_port, egress_port=egress_port) / IP(dst=socket.gethostbyname("10.0.1.1")) / UDP(dport=1234, sport=4321) / "resume"
    resume_pkt.show2()
    sendp(resume_pkt, iface=iface, verbose=False)

def handle_pkt(pkt):

    iface = pkt.sniffed_on
    print "Controller got a packet on {}".format(iface)

    if not pkt.haslayer(CpuHeader) or not pkt.haslayer(UDP) or pkt[Ether].src == get_if_hwaddr(iface):
        print "...but packet is rejected!!"
        return

    global cpu_buffer, cpu_buffer_size
    pkt.show2()
    sys.stdout.flush()

    portno = pkt[CpuHeader].egress_port
    if portno not in cpu_buffer[iface]:
        cpu_buffer[iface][portno] = []

    if pkt[Ether].type == TYPE_RESUME:
        for buffered_packet in cpu_buffer[iface][portno]:
            sendp(buffered_packet, iface=iface, verbose=False)
        cpu_buffer_size[iface] -= len(cpu_buffer[iface][portno])
        del cpu_buffer[iface][portno][:]
        show_cpu_buffer()

        if cpu_buffer_size[iface] <= BUFFER_RESUME_THRESHOLD:
            send_a_resume_packet(iface, pkt[CpuHeader].ingress_port, pkt[CpuHeader].egress_port)

    else:
        pkt2 = pkt.copy()
        pkt2[Ether].remove_payload()
        final_pkt = pkt2 / pkt[IP]
        cpu_buffer[iface][portno].append(final_pkt)
        cpu_buffer_size[iface] += 1
        show_cpu_buffer()

        if cpu_buffer_size[iface] >= BUFFER_PAUSE_THRESHOLD:
            send_a_pause_packet(iface, pkt[CpuHeader].ingress_port, pkt[CpuHeader].egress_port)


def main():

    

    global cpu_interfaces
    if len(sys.argv)>1:
        cpu_interfaces = sys.argv[1]
    print "sniffing on %s" % cpu_interfaces
    

    sys.stdout.flush()
    sniff(iface = cpu_interfaces,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
