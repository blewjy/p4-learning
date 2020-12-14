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
import time

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption, Ether
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw, ls, TCP
from scapy.layers.inet import _IPOption_HDR

BUFFER_PAUSE_THRESHOLD = 5
BUFFER_RESUME_THRESHOLD = 1

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
count = 0

# buffer stores mapping from port to array of packets
cpu_buffer_size = 0
cpu_buffer = {}

def show_cpu_buffer():
    global cpu_buffer
    print "buffer size:", cpu_buffer_size
    print cpu_buffer

def send_a_pause_packet(ingress_port, egress_port):
    pause_pkt = Ether(src=get_if_hwaddr('s1-cpu-eth1'), dst="ff:ff:ff:ff:ff:ff", type=TYPE_PAUSE)
    pause_pkt = pause_pkt / CpuHeader(ingress_port=ingress_port, egress_port=egress_port) / IP(dst="10.0.1.1") / UDP(dport=1234, sport=4321) / "pause"
    pause_pkt.show2()
    sendp(pause_pkt, iface='s1-cpu-eth1', verbose=False)

def send_a_resume_packet(ingress_port, egress_port):
    pause_pkt = Ether(src=get_if_hwaddr('s1-cpu-eth1'), dst="ff:ff:ff:ff:ff:ff", type=TYPE_RESUME)
    pause_pkt = pause_pkt / CpuHeader(ingress_port=ingress_port, egress_port=egress_port) / IP(dst="10.0.1.1") / UDP(dport=1234, sport=4321) / "resume"
    pause_pkt.show2()
    sendp(pause_pkt, iface='s1-cpu-eth1', verbose=False)

def handle_pkt(pkt):
    if not pkt.haslayer(CpuHeader) or not pkt.haslayer(UDP) or pkt[Ether].src == get_if_hwaddr('s1-cpu-eth1'):
        return

    global count, cpu_buffer, cpu_buffer_size
    print "Controller got a packet", count
    count += 1
    pkt.show2()
    sys.stdout.flush()

    portno = pkt[CpuHeader].egress_port
    if portno not in cpu_buffer:
        cpu_buffer[portno] = []

    if pkt[Ether].type == TYPE_RESUME:
        for buffered_packet in cpu_buffer[portno]:
            sendp(buffered_packet, iface='s1-cpu-eth1', verbose=False)
        cpu_buffer_size -= len(cpu_buffer[portno])
        del cpu_buffer[portno][:]
        show_cpu_buffer()

        if cpu_buffer_size <= BUFFER_RESUME_THRESHOLD:
            send_a_resume_packet(pkt[CpuHeader].ingress_port, pkt[CpuHeader].egress_port)

    else:
        pkt2 = pkt.copy()
        pkt2[Ether].remove_payload()
        final_pkt = pkt2 / pkt[IP]
        cpu_buffer[portno].append(final_pkt)
        cpu_buffer_size += 1
        show_cpu_buffer()

        if cpu_buffer_size >= BUFFER_PAUSE_THRESHOLD:
            send_a_pause_packet(pkt[CpuHeader].ingress_port, pkt[CpuHeader].egress_port)


def main():
    if len(sys.argv) < 2:
        iface = 's1-cpu-eth1'
    else:
        iface = sys.argv[1]

    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
