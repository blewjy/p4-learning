#!/usr/bin/env python

import threading
import time
import argparse
import sys
import socket
import random
import struct

from scapy.all import bind_layers
from scapy.all import sniff, sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP, TCP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField
from scapy.layers.inet import _IPOption_HDR

TYPE_CUSTOM = 0x1010
TYPE_PAUSE = 0x1111
TYPE_RESUME = 0x1212

bind_layers(Ether, IP, type=TYPE_CUSTOM)
bind_layers(Ether, IP, type=TYPE_PAUSE)
bind_layers(Ether, IP, type=TYPE_RESUME)

num_pkts_sent = 0

paused = False

def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface


def print_state():
   global num_pkts_sent
   print "pkts_sent: {}\t".format(num_pkts_sent)


class Sender(threading.Thread):

    def __init__(self, dest_ip, num_pkts):
        threading.Thread.__init__(self)
        self.dest_ip = dest_ip
        self.num_pkts = num_pkts

    def run(self):
        addr = socket.gethostbyname(self.dest_ip)
        iface = get_if()

        i = 1
        while i <= int(self.num_pkts):
            global paused, num_pkts_sent
            if not paused:
                pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff", type=TYPE_CUSTOM) 
                pkt = pkt / IP(dst=addr) 
                pkt = pkt / UDP(dport=4321, sport=1234)
                pkt = pkt / "Message {}".format(i)

                sendp(pkt, iface=iface, verbose=False)
                num_pkts_sent += 1
                i += 1
                print_state()
                time.sleep(0.1)
            else:
                print "Sending is paused"
                time.sleep(3)

    
class Receiver(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)

    def run(self):
        iface = get_if()
        print "sniffing on %s" % iface
        sniff(iface = iface, prn = lambda x: self.handle_pkt(x, iface))

    def handle_pkt(self, pkt, iface):
        global paused
        if Ether in pkt:
            if pkt[Ether].src != get_if_hwaddr(iface):
                if pkt[Ether].type == TYPE_CUSTOM:
                    print "Normal packet received!"
                    pkt.show2()
                elif pkt[Ether].type == TYPE_PAUSE:
                    print "Pause packet received!"
                    paused = True
                elif pkt[Ether].type == TYPE_RESUME:
                    print "Resume packet received!"
                    paused = False
                else:
                    print "Weird packet received..."
                    pkt.show2()
                    sys.stdout.flush()
        

def main():
    if len(sys.argv)<3:
        print 'pass 2 arguments: <destination> <no. of packets>'
        exit(1)

    sender = Sender(sys.argv[1], sys.argv[2])
    sender.daemon = True
    sender.start()

    receiver = Receiver()
    receiver.daemon = True
    receiver.start()

    try:
        while True:
            time.sleep(500) # main thread needs to stay alive...
    except KeyboardInterrupt:
        raise
    finally:
        print "Exiting Main Thread"


if __name__ == '__main__':
   main()