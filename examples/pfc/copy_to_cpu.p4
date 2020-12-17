/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CPU_PORT  24
#define MAX_PORTS 4

const bit<16> TYPE_IPV4   = 0x800;
const bit<16> TYPE_CUSTOM = 0x1010;
const bit<16> TYPE_PAUSE  = 0x1111;
const bit<16> TYPE_RESUME = 0x1212;

register<bit<1>>(MAX_PORTS)           is_port_paused;
register<bit<1>>(MAX_PORTS)           is_upstream_paused;
register<bit<32>>(5)                  deq_qdepth;
register<bit<1>>(MAX_PORTS*MAX_PORTS) traffic_map;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
  macAddr_t dstAddr;
  macAddr_t srcAddr;
  bit<16>   etherType;
}

header ipv4_t {
  bit<4>    version;
  bit<4>    ihl;
  bit<8>    tos;
  bit<16>   totalLen;
  bit<16>   identification;
  bit<3>    flags;
  bit<13>   fragOffset;
  bit<8>    ttl;
  bit<8>    protocol;
  bit<16>   hdrChecksum;
  ip4Addr_t srcAddr;
  ip4Addr_t dstAddr;
}

// only packets that are exchanged with CPU have this header.
header cpu_t {
  bit<16> ingress_port;
  bit<16> egress_port;
  bit<8>  is_final;
  bit<8>  from_cpu;
}

struct metadata {
  /* empty */
}

struct headers {
  ethernet_t   ethernet;
  cpu_t        cpu;
  ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: ipv4;
            TYPE_CUSTOM: check_if_cpu;
            TYPE_RESUME: check_if_cpu;
            TYPE_PAUSE: check_if_cpu;
            default: accept;
        }
    }

    state check_if_cpu {
      transition select(standard_metadata.ingress_port) {
        CPU_PORT: cpu;
        default: ipv4;
      }
    }

    state cpu {
      packet.extract(hdr.cpu);
      transition ipv4;
    }

    state ipv4 {
      packet.extract(hdr.ipv4);
      transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();

            if (hdr.ethernet.etherType == TYPE_PAUSE) {
              // If you receive a pause packet, first check where it was from

              if (standard_metadata.ingress_port == CPU_PORT) {
                // If it's from CPU port, we forward it to specified port
                standard_metadata.egress_spec = (bit<9>)hdr.cpu.ingress_port;
                hdr.cpu.setInvalid();
                is_upstream_paused.write((bit<32>)standard_metadata.egress_spec - 1, (bit<1>)1);
              } else {
                // If it's from non-CPU port, we mark the ingress port as paused, then drop the packet
                is_port_paused.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);
                drop();
              }

            } else if (hdr.ethernet.etherType == TYPE_RESUME) {
              // If you receive a resume packet, first check where it was from

              if (standard_metadata.ingress_port == CPU_PORT) {
                // If it's from CPU port, we multicast it
                standard_metadata.mcast_grp = 1;
              } else {
                // If it's from a non-CPU port, you should mark the ingress port as unpaused, then forward to CPU to release buffer.
                is_port_paused.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)0);
                hdr.cpu.setValid();
                hdr.cpu.ingress_port = (bit<16>)standard_metadata.ingress_port;
                hdr.cpu.egress_port = (bit<16>)standard_metadata.ingress_port;
                hdr.cpu.from_cpu = (bit<8>)0;
                standard_metadata.egress_spec = CPU_PORT;
              }

            } else if (hdr.ethernet.etherType == TYPE_CUSTOM) {
              // If you receive a custom packet, you should check if port is paused first.
              bit<1> paused;
              is_port_paused.read(paused, (bit<32>)standard_metadata.egress_spec - 1);
              if (paused == (bit<1>)1) {
                // If paused, we prep cpu header to send to CPU.
                hdr.cpu.setValid();
                hdr.cpu.ingress_port = (bit<16>)standard_metadata.ingress_port;
                hdr.cpu.egress_port = (bit<16>)standard_metadata.egress_spec;
                hdr.cpu.from_cpu = (bit<8>)0;

                // Also, we need to mark on traffic map (DCFIT)
                bit<32> traffic_map_index = (4 * (bit<32>)standard_metadata.egress_spec) + (bit<32>)standard_metadata.ingress_port - 1;
                traffic_map.write(traffic_map_index, (bit<1>)1);
                deq_qdepth.write(0, (bit<32>)standard_metadata.egress_spec);
                deq_qdepth.write(1, (bit<32>)standard_metadata.ingress_port);

                // Send to CPU
                standard_metadata.egress_spec = CPU_PORT;

              } else {
                // If not paused, we need to unmark the traffic map if it is last packet

                // First check if it has the cpu header.
                if (standard_metadata.ingress_port == CPU_PORT && hdr.cpu.isValid()) {
                  // If it does, then check if is_final is marked.
                  if (hdr.cpu.is_final == (bit<8>)1) {
                    // If is_final is marked, we need to unmark on the traffic map
                    bit<32> traffic_map_index = (4 * (bit<32>)hdr.cpu.egress_port) + (bit<32>)hdr.cpu.ingress_port - 1;
                    traffic_map.write(traffic_map_index, (bit<1>)0);

                  }
                  // Remember to set cpu header invalid
                  hdr.cpu.setInvalid();
                }
              }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
  
    action drop() {
      mark_to_drop(standard_metadata);
    }

    apply {
      if (hdr.ethernet.isValid() && hdr.ethernet.etherType == TYPE_RESUME && standard_metadata.egress_port != CPU_PORT) {
        if (standard_metadata.egress_port == (bit<9>)hdr.cpu.ingress_port) {
          // If it's going out the same way the original resume came in, drop it.
          drop();

        } else {
          // Otherwise, first unset the cpu header.
          hdr.cpu.setInvalid();

          // Then, send out resume packet to only paused upstreams
          bit<1> paused;
          is_upstream_paused.read(paused, (bit<32>)standard_metadata.egress_port - 1);
          if (paused == (bit<1>)1) {
            is_upstream_paused.write((bit<32>)standard_metadata.egress_port - 1, (bit<1>)0);
          } else {
            drop();
          }
          

        }
      }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {

        //parsed headers have to be added again into the packet.
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
        packet.emit(hdr.ipv4);

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
  MyParser(),
  MyVerifyChecksum(),
  MyIngress(),
  MyEgress(),
  MyComputeChecksum(),
  MyDeparser()
) main;
