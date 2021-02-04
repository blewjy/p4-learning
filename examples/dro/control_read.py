"""
Running this script will only read the registers once across all switches.
"""

from p4utils.utils.topology import Topology
from p4utils.utils.sswitch_API import SimpleSwitchAPI
import sys
import time
import threading

class Reader(object):
    def __init__(self):
        self.topo = Topology(db="topology.db")
        self.switches = ["s1", "s2", "s3", "s4"]
        self.registers = ["debugger"]
        self.controllers = {}

        self.init_controllers()

    def init_controllers(self):
        for s in self.switches:
            self.controllers[s] = SimpleSwitchAPI(self.topo.get_thrift_port(s))
    
    def read(self):
        print "\t",
        for r in self.registers:
            print "{}\t".format(r),
        print ""
        for s in self.switches:
            print "pro-debug", s,
            for r in self.registers:
                res = self.controllers[s].register_read(r);
                print "\t{}".format(res),
            print ""

if __name__ == "__main__":
    Reader().read()