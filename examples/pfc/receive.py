#!/usr/bin/env python
import sys
import struct
import os

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, IPOption, Ether
from scapy.all import ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.layers.inet import _IPOption_HDR

TYPE_CUSTOM = 0x1010
TYPE_PAUSE = 0x1111
TYPE_RESUME = 0x1212
bind_layers(Ether, IP, type=TYPE_CUSTOM)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

count = 0 

def handle_pkt(pkt):
    global count
    print "got a packet", count
    count += 1
    pkt.show2()
    sys.stdout.flush()


def main():
    ifaces = filter(lambda i: 'eth' in i, os.listdir('/sys/class/net/'))
    iface = ifaces[0]
    print "sniffing on %s" % iface
    sys.stdout.flush()
    sniff(filter = "ether proto {} or ether proto {} or ether proto {}".format(TYPE_CUSTOM, TYPE_PAUSE, TYPE_RESUME), iface = iface,
          prn = lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()