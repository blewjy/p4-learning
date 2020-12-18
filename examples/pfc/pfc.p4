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
register<bit<1>>(MAX_PORTS)           is_ingress_buffering;
register<bit<1>>(MAX_PORTS*MAX_PORTS) traffic_map;
register<bit<6>>(MAX_PORTS)           switch_id_store;
register<bit<6>>(MAX_PORTS)           port_id_store;
register<bit<4>>(MAX_PORTS)           sequence_id_store;
register<bit<32>>(1)                  debugger;

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

// only pause packets may have this header
header dcfit_t {
  bit<6>  switch_id;
  bit<6>  port_id;
  bit<4>  sequence_id;
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
  dcfit_t      dcfit;
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
            TYPE_PAUSE: check_if_dcfit;
            default: accept;
        }
    }

    // Pause frames will only contain dcfit header if they did not come from CPU
    state check_if_dcfit {
      transition select(standard_metadata.ingress_port) {
        CPU_PORT: cpu;
        default: dcfit;
      }
    }

    state dcfit {
      packet.extract(hdr.dcfit);
      transition check_if_cpu;
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

  action send_to_cpu() {
    // All packets going to CPU will need the header
    hdr.cpu.setValid();
    hdr.cpu.ingress_port = (bit<16>)standard_metadata.ingress_port;
    hdr.cpu.egress_port = (bit<16>)standard_metadata.egress_spec;
    hdr.cpu.from_cpu = (bit<8>)0;

    // Set the egress port
    standard_metadata.egress_spec = CPU_PORT;
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
        // If you receive a pause frame, first check where was it from.

        if (standard_metadata.ingress_port == CPU_PORT) {
          // If it's from CPU_PORT, then we simply propagate to specified port
          standard_metadata.egress_spec = (bit<9>)hdr.cpu.ingress_port;

          // Mark that we have paused the upstream
          is_upstream_paused.write((bit<32>)hdr.cpu.ingress_port, (bit<1>)1);

          // Deactivate the cpu header
          hdr.cpu.setInvalid();

        } else {
          // If it's not from CPU_PORT, then we mark this egress as paused and drop the packet. 
          is_port_paused.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);
          drop();
        }    
        
      } else if (hdr.ethernet.etherType == TYPE_RESUME) {
        // If you receive a resume packet, first check where it was from

        if (standard_metadata.ingress_port == CPU_PORT) {
          // If it's from CPU_PORT, then we simply propagate to specified port
          standard_metadata.egress_spec = (bit<9>)hdr.cpu.ingress_port;

          // Mark that we have un-paused the upstream
          is_upstream_paused.write((bit<32>)hdr.cpu.ingress_port, (bit<1>)0);

          // Deactivate the cpu header
          hdr.cpu.setInvalid();

        } else {
          // If packet did not come from CPU, then we should mark this ingress as unpaused.
          is_port_paused.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)0); 

          // Then forward this packet to CPU to release buffer
          send_to_cpu();
        }

        

      } else if (hdr.ethernet.etherType == TYPE_CUSTOM) {

        // Everytime we receive a normal packet, it can come from either CPU (buffer), or another node.
        // We must handle these two cases separately.

        if (standard_metadata.ingress_port == CPU_PORT) {
          // If come from CPU_PORT, we should check if it is the final packet in that ingress buffer

          if (hdr.cpu.is_final == (bit<8>)1) {
            // If it is final, then we should mark the ingress as no longer buffering
            is_ingress_buffering.write((bit<32>)hdr.cpu.ingress_port, (bit<1>)0);
          }

          // Also, we should deactivate the cpu header
          hdr.cpu.setInvalid();

        } else {
          // Everytime we receive a normal packet from another node, we have to first check if the ingress is buffering.
          // If the ingress is buffering, we basically almost don't need to do anything else -- just append to the ingress buffer.
          /*
             Explanation:
             We are trying to do like a ingress queueing mechanism here. So no matter where your egress port is,
             you have to first respect the ingress buffer. This means that if there are some packets that came
             before you which are still stuck in the ingress buffer, you have to queue up before you can be processed.
          */

          // So first, we check if the ingress is buffering.
          bit<1> buffering;
          is_ingress_buffering.read(buffering, (bit<32>)standard_metadata.ingress_port);
          if (buffering == (bit<1>)1) {
            // If it is buffering, then we send to the CPU buffer.
            send_to_cpu();  

            // Everytime we send a normal packet to CPU, CPU will add it to the ingress buffer.
            // So we need to note the ingress port that is buffering
            is_ingress_buffering.write((bit<32>)standard_metadata.ingress_port, (bit<1>)1);
          } else {
            // If it is not buffering (means there is no other packets in front of it), then we can handle normally.

            // To handle normally, we first check if the intended egress is paused
            bit<1> paused;
            is_port_paused.read(paused, (bit<32>)standard_metadata.egress_spec - 1);
            if (paused == (bit<1>)1) {
              // If the egress is paused, then we also send to CPU to buffer.
              send_to_cpu();

              // Same thing here, note down that the ingress port is buffering
              is_ingress_buffering.write((bit<32>)standard_metadata.ingress_port, (bit<1>)1);
            }
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
  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
  apply {
    update_checksum(
	    hdr.ipv4.isValid(),
      { 
        hdr.ipv4.version,
	      hdr.ipv4.ihl,
        hdr.ipv4.tos,
        hdr.ipv4.totalLen,
        hdr.ipv4.identification,
        hdr.ipv4.flags,
        hdr.ipv4.fragOffset,
        hdr.ipv4.ttl,
        hdr.ipv4.protocol,
        hdr.ipv4.srcAddr,
        hdr.ipv4.dstAddr
      },
      hdr.ipv4.hdrChecksum,
      HashAlgorithm.csum16
    );
  }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
  apply {
    packet.emit(hdr.ethernet);
    packet.emit(hdr.dcfit);
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
