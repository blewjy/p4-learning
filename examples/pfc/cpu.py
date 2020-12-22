#!/usr/bin/env python


"""
CPU will always only act as a dumb buffer.
This means that any regular packets that come into the CPU will definitely be stored first.
CPU will also store each packet according to the ingress port attribute (i.e. ingress queue).
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

MAX_PORTS = 4

BUFFER_PAUSE_THRESHOLD = 10
BUFFER_RESUME_THRESHOLD = 0

TYPE_CUSTOM = 0x1010
TYPE_PAUSE = 0x1111
TYPE_RESUME = 0x1212

class CpuHeader(Packet):
    name = 'CpuPacket'
    fields_desc = [BitField("ingress_port",0,16), BitField("egress_port",0,16), BitField("is_final",0,8), BitField("from_cpu",0,8)]

bind_layers(Ether, CpuHeader, type=TYPE_CUSTOM)
bind_layers(Ether, CpuHeader, type=TYPE_PAUSE)
bind_layers(Ether, CpuHeader, type=TYPE_RESUME)
bind_layers(CpuHeader, IP)
bind_layers(Ether, IP, type=TYPE_CUSTOM)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

# list of cpu interfaces
cpu_interfaces = ['s1-cpu-eth1', 's2-cpu-eth1', 's3-cpu-eth1']

# mapping from IP to hostname (only for display purposes)
ip_to_hostname = {
    "10.0.1.1": "h1",
    "10.0.2.2": "h2",
    "10.0.3.3": "h3",
    "10.0.1.11": "h11",
    "10.0.2.22": "h22"
}

# buffer stores mapping from port to array of packets
cpu_buffer = {}
for iface in cpu_interfaces:
    cpu_buffer[iface] = {}

# this dict counts the ingress-egress pairs
cpu_ie_dict = {}
for iface in cpu_interfaces:
    cpu_ie_dict[iface] = {}

# this dict tracks if port is paused
is_switch_port_paused = {}
for iface in cpu_interfaces:
    is_switch_port_paused[iface] = {}
    for idx in range(MAX_PORTS):
        p = idx + 1
        is_switch_port_paused[iface][p] = False

# this dict tracks if port is blocked
is_switch_port_blocked = {}
for iface in cpu_interfaces:
    is_switch_port_blocked[iface] = {}
    for idx in range(MAX_PORTS):
        p = idx + 1
        is_switch_port_blocked[iface][p] = False

def show_cpu_state():
    global cpu_buffer, ip_to_hostname, is_switch_port_blocked, is_switch_port_paused
    for iface, value in cpu_buffer.items():
        print "{}:".format(iface)
        for i_port, buff in value.items():
            hostname_pkt_count = {}

            for p in buff:
                src_host = ip_to_hostname[p[IP].src]
                dst_host = ip_to_hostname[p[IP].dst]
                key = src_host + "->" + dst_host
                if key not in hostname_pkt_count:
                    hostname_pkt_count[key] = 1
                else:
                    hostname_pkt_count[key] += 1

            print "\tPort {}:".format(i_port)
            for k, v in hostname_pkt_count.items():
                print "\t\t{}: {}".format(k, v)

    print "Switch port paused states:"
    print is_switch_port_paused

    print "Switch port blocked states:"
    print is_switch_port_blocked

def send_a_pause_packet(iface, ingress_port, egress_port):
    print "Sending a pause packet from {}, going out port {}".format(iface, ingress_port)
    pause_pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_PAUSE)
    pause_pkt = pause_pkt / CpuHeader(ingress_port=ingress_port, egress_port=egress_port, from_cpu=1) / IP(dst=socket.gethostbyname("10.0.1.1")) / UDP(dport=1234, sport=4321) / "pause"
    pause_pkt.show2()
    sendp(pause_pkt, iface=iface, verbose=False)

def send_a_resume_packet(iface, ingress_port, egress_port):
    print "Sending a resume packet from {}, going out port {}".format(iface, ingress_port)
    resume_pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_RESUME)
    resume_pkt = resume_pkt / CpuHeader(ingress_port=ingress_port, egress_port=egress_port, from_cpu=1) / IP(dst=socket.gethostbyname("10.0.1.1")) / UDP(dport=1234, sport=4321) / "resume"
    resume_pkt.show2()
    sendp(resume_pkt, iface=iface, verbose=False)

def handle_pkt(pkt):
    iface = pkt.sniffed_on
    print "Controller got a packet on {}".format(iface)

    if not pkt.haslayer(CpuHeader) or pkt[CpuHeader].from_cpu == 1:
        print "...but packet is rejected!!"
        return

    global cpu_buffer, is_switch_port_blocked, is_switch_port_paused
    pkt.show2()
    sys.stdout.flush()

    i_port = pkt[CpuHeader].ingress_port
    e_port = pkt[CpuHeader].egress_port

    if pkt[Ether].type == TYPE_CUSTOM:
        # Create the queue if there is none
        if i_port not in cpu_buffer[iface]:
            cpu_buffer[iface][i_port] = []

        # Append the packet to the ingress queue
        cpu_buffer[iface][i_port].append(pkt)
        show_cpu_state()

        # If the ingress queue pass the threshold, we send pause packet upstream
        if len(cpu_buffer[iface][i_port]) >= BUFFER_PAUSE_THRESHOLD:
            send_a_pause_packet(iface, i_port, e_port)

    elif pkt[Ether].type == TYPE_PAUSE:
        """
        If pause packet is forwarded to CPU from a switch, it is just to inform the CPU that this particular port has been paused.
        Just note it down, then ignore packet.
        """

        # The paused port is the ingress port of the pause packet
        paused_port = pkt[CpuHeader].ingress_port

        # Simply mark as paused on our dict
        is_switch_port_paused[iface][paused_port] = True

    elif pkt[Ether].type == TYPE_RESUME:
        """
        Each resume packet is for a particular egress port.
        However, our queues are ingress queues.
        This means that we have to loop through all the ingress queues, 
        then release packets sequentially from the front if their egress port is not paused
        """

        # The resumed port is the ingress port of the resume packet
        resumed_port = pkt[CpuHeader].ingress_port

        # Mark the port as resumed
        is_switch_port_paused[iface][resumed_port] = False

        # Loop through each ingress queue
        for port, buff in cpu_buffer[iface].items():
            while len(buff) > 0:
                next_pkt = buff[0]
                target_egress_port = buff[0][CpuHeader].egress_port
                if not is_switch_port_paused[iface][target_egress_port]:
                    resumed_pkt = buff.pop(0)
                    resumed_pkt[CpuHeader].from_cpu = 1;
                    if len(buff) <= 0:
                        resumed_pkt[CpuHeader].is_final = 1;
                    else:
                        resumed_pkt[CpuHeader].is_final = 0;
                    sendp(resumed_pkt, iface=iface, verbose=False)

                    show_cpu_state()
                else:
                    break

            if len(buff) <= BUFFER_RESUME_THRESHOLD:
                send_a_resume_packet(iface, port, resumed_port)

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
