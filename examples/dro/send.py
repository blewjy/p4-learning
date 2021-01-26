#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, BitField
from scapy.all import Ether, IP, UDP, TCP


class DcfitHeader(Packet):
    name = 'DcfitPacket'
    fields_desc = [BitField("switch_id",0,6), BitField("port_id",0,6), BitField("sequence_id",0,4)]

TYPE_CUSTOM = 0x1010
TYPE_PAUSE = 0x1111
TYPE_RESUME = 0x1212
bind_layers(Ether, IP, type=TYPE_CUSTOM)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

bind_layers(Ether, DcfitHeader, type=TYPE_PAUSE)
bind_layers(DcfitHeader, IP)

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def main():

    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> "<message>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print "sending on interface %s to %s" % (iface, str(addr))

    if sys.argv[2] == "pause":
        ethertype = TYPE_PAUSE
        pkt =  Ether(src=get_if_hwaddr(iface),dst = "00:00:00:00:01:12", type=ethertype)
        pkt = pkt / DcfitHeader(switch_id=2, port_id=2, sequence_id=1) / IP(dst=addr)/ UDP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    else:
        if sys.argv[2] == "resume":
            ethertype = TYPE_RESUME
        else:
            ethertype = TYPE_CUSTOM
        pkt =  Ether(src=get_if_hwaddr(iface),dst = "00:00:00:00:01:12", type=ethertype)
        pkt = pkt /IP(dst=addr)/ UDP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
