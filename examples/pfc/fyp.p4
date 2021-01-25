/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

#define CPU_PORT  24
#define MAX_PORTS 4

const bit<16> TYPE_IPV4    = 0x800;
const bit<16> TYPE_CUSTOM  = 0x1010;
const bit<16> TYPE_PAUSE   = 0x1111;
const bit<16> TYPE_RESUME  = 0x1212;
const bit<16> TYPE_BLOCK   = 0x1313;
const bit<16> TYPE_RELEASE = 0x1414;

register<bit<1>>(MAX_PORTS)           is_port_paused;
register<bit<1>>(MAX_PORTS)           is_upstream_paused;
register<bit<1>>(MAX_PORTS)           is_ingress_buffering;
register<bit<1>>(MAX_PORTS)           is_port_blocked;
register<bit<1>>(MAX_PORTS*MAX_PORTS) traffic_map;
register<bit<4>>(MAX_PORTS*MAX_PORTS) flow_counter;
register<bit<4>>(MAX_PORTS)           buffer_counter;
register<bit<48>>(2)                  debugger;

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
header fyp_t {
  bit<4>  switch_id;
  bit<4>  port_id;
}

// only packets that are exchanged with CPU have this header.
header cpu_t {
  bit<16> ingress_port;
  bit<16> egress_port;
  bit<8>  from_cpu;
}

struct metadata {
  bit<4> switch_id;
}

struct headers {
  ethernet_t  ethernet;
  fyp_t       fyp;
  cpu_t       cpu;
  ipv4_t      ipv4;
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
            TYPE_IPV4:    ipv4;
            TYPE_CUSTOM:  check_if_cpu;
            TYPE_RESUME:  check_if_cpu;
            TYPE_PAUSE:   check_if_fyp;
            TYPE_BLOCK:   check_if_cpu;
            TYPE_RELEASE: check_if_cpu;
            default:      accept;
        }
    }

    // Pause frames will only contain fyp header if they did not come from CPU
    state check_if_fyp {
      transition select(standard_metadata.ingress_port) {
        CPU_PORT: cpu;
        default: fyp;
      }
    }

    state fyp {
      packet.extract(hdr.fyp);
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

  // [FYP]
  action get_switch_id(bit<4> switch_id) {
    meta.switch_id = switch_id;
  }

  table get_switch_id_table {
    key = {
      hdr.fyp.isValid(): exact;
    }
    actions = {
      get_switch_id;
    }
  }
  // [FYP]


  apply {
    if (hdr.ipv4.isValid()) {
      ipv4_lpm.apply();

      if (hdr.ethernet.etherType == TYPE_PAUSE) {

        // First, we get the ID of this switch into our metadata
        get_switch_id_table.apply();

        // If you receive a pause frame, first check where was it from.
        if (standard_metadata.ingress_port == CPU_PORT) {
          // If it's from CPU_PORT, then we simply propagate to specified port
          standard_metadata.egress_spec = (bit<9>)hdr.cpu.ingress_port;

          // Mark that we have paused the upstream
          is_upstream_paused.write((bit<32>)hdr.cpu.ingress_port - 1, (bit<1>)1);

          // Deactivate the cpu header
          hdr.cpu.setInvalid();

          // [FYP]
          // Now, we need to append our custom header to this pause packet.
          // This custom header was triggered from the CPU, which means that it originates from this particular switch.
          // So, the switch ID we need to append is this exact switch's ID.
          // Port ID will be the intended egress port of this pause packet.

          // First, we activate the header.
          hdr.fyp.setValid();

          // Then we attach our switch ID to the header.
          hdr.fyp.switch_id = meta.switch_id;

          // Then we attach the egress port ID.
          hdr.fyp.port_id = (bit<4>)standard_metadata.egress_spec;

          // [TEMP]
          // This could be the final pause packet that causes the deadlock.
          // If it is, this would also be the switch that detects the deadlock.
          // We mark a timing here.
          debugger.write(0, standard_metadata.ingress_global_timestamp);
          // [TEMP]
          
          // [FYP]

        } else {
          // If it's not from CPU_PORT, then we mark this egress as paused. 
          is_port_paused.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);

          // [FYP]
          // Each time we receive a pause packet from a neighbouring switch, we have to do some checks.
          // One of the following 3 cases will occur:
          // (a) - received switch_id does not belong to this switch, and this switch has not paused any upstream --> ignore this pause packet (i.e. just send to CPU)
          // (b) - received switch_id does not belong to this switch, but this switch has paused some upstream(s) --> forward this pause packet to paused upstreams (and CPU) with same info
          // (c) - received switch_id belongs to this switch --> deadlock has been detected

          // First we check if the received switch_id is the ID of this switch.
          if (hdr.fyp.switch_id == meta.switch_id) {
            // If it the same, that means this pause packet originated from here and it's now back.
            // Then we must check for any relation with the original port to confirm a CBD.
            // The ingress of packet flow is the port_id in the pause packet.
            // The egress of the packet flow is the receive port of this pause packet.
            bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)standard_metadata.ingress_port - 1)) + (bit<32>)hdr.fyp.port_id - 1;
            bit<1> marked;
            traffic_map.read(marked, traffic_map_index);
            if (marked == (bit<1>)1) {
              // There is a deadlock detected!
              debugger.write(1, standard_metadata.ingress_global_timestamp);

              drop();
            } else {
              // If there's no relation, then there shouldn't be any CBD along this checking message path.
              // Proceed as a regular pause packet and multicast
              standard_metadata.mcast_grp = 1;

            }
          
          } else {
            // If the received switch_id is not the same as the ID of this current switch, then we must check if any upstreams have been paused.
            // But we can't do loops here, so we have to multicast this to check at each egress port.
            standard_metadata.mcast_grp = 1;
          }
          // [FYP]


        }    
        
      } else if (hdr.ethernet.etherType == TYPE_RESUME) {
        // If you receive a resume packet, first check where it was from

        if (standard_metadata.ingress_port == CPU_PORT) {
          // If it's from CPU_PORT, then we simply propagate to specified port
          standard_metadata.egress_spec = (bit<9>)hdr.cpu.ingress_port;

          // Mark that we have un-paused the upstream
          is_upstream_paused.write((bit<32>)hdr.cpu.ingress_port - 1, (bit<1>)0);

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

          // If come from CPU_PORT, we need to first decrement the counters
          
          // Decrement the buffer counter
          bit<4> buffer_count;
          buffer_counter.read(buffer_count, (bit<32>)hdr.cpu.ingress_port - 1);
          buffer_count = buffer_count - 1;
          buffer_counter.write((bit<32>)hdr.cpu.ingress_port - 1, buffer_count);

          // Decrement the flow counter
          bit<32> flow_counter_index = (MAX_PORTS * ((bit<32>)hdr.cpu.egress_port - 1)) + (bit<32>)hdr.cpu.ingress_port - 1;
          bit<4> flow_count;
          flow_counter.read(flow_count, flow_counter_index);
          flow_count = flow_count - 1;
          flow_counter.write(flow_counter_index, flow_count);

          // Update traffic map
          bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)hdr.cpu.egress_port - 1)) + (bit<32>)hdr.cpu.ingress_port - 1;
          if (flow_count <= 0) {
            traffic_map.write(traffic_map_index, (bit<1>)0);
          } else {
            traffic_map.write(traffic_map_index, (bit<1>)1);
          }

          // Then we check if this was the final packet in the buffer.
          if (buffer_count <= (bit<4>)0) {
            // If this was the final packet, then we should mark the ingress as no longer buffering.
            is_ingress_buffering.write((bit<32>)hdr.cpu.ingress_port - 1, (bit<1>)0);
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
          is_ingress_buffering.read(buffering, (bit<32>)standard_metadata.ingress_port - 1);
          if (buffering == (bit<1>)1) {
            // If it is buffering, we increment our counters

            // Increment the buffer counter
            bit<4> buffer_count;
            buffer_counter.read(buffer_count, (bit<32>)standard_metadata.ingress_port - 1);
            buffer_count = buffer_count + 1;
            buffer_counter.write((bit<32>)standard_metadata.ingress_port - 1, buffer_count);

            // Increment the flow counter
            bit<32> flow_counter_index = (MAX_PORTS * ((bit<32>)standard_metadata.egress_spec - 1)) + (bit<32>)standard_metadata.ingress_port - 1;
            bit<4> flow_count;
            flow_counter.read(flow_count, flow_counter_index);
            flow_count = flow_count + 1;
            flow_counter.write(flow_counter_index, flow_count);

            // Update traffic map
            bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)hdr.cpu.egress_port - 1)) + (bit<32>)hdr.cpu.ingress_port - 1;
            if (flow_count <= 0) {
              traffic_map.write(traffic_map_index, (bit<1>)0);
            } else {
              traffic_map.write(traffic_map_index, (bit<1>)1);
            }

            // Then we send to the CPU buffer.  
            send_to_cpu();

          } else {
            // If it is not buffering (means there is no other packets in front of it), then we can handle normally.

            // To handle normally, we first check if the intended egress is paused
            bit<1> paused;
            is_port_paused.read(paused, (bit<32>)standard_metadata.egress_spec - 1);
            if (paused == (bit<1>)1) {
              // If the egress is paused, then we also send to CPU to buffer.

              // Same thing here, note down that the ingress port is buffering
              is_ingress_buffering.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);

              // Increment the buffer counter
              bit<4> buffer_count;
              buffer_counter.read(buffer_count, (bit<32>)standard_metadata.ingress_port - 1);
              buffer_count = buffer_count + 1;
              buffer_counter.write((bit<32>)standard_metadata.ingress_port - 1, buffer_count);

              // Increment the flow counter
              bit<32> flow_counter_index = (MAX_PORTS * ((bit<32>)standard_metadata.egress_spec - 1)) + (bit<32>)standard_metadata.ingress_port - 1;
              bit<4> flow_count;
              flow_counter.read(flow_count, flow_counter_index);
              flow_count = flow_count + 1;
              flow_counter.write(flow_counter_index, flow_count);

              // Update traffic map
              bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)hdr.cpu.egress_port - 1)) + (bit<32>)hdr.cpu.ingress_port - 1;
              if (flow_count <= 0) {
                traffic_map.write(traffic_map_index, (bit<1>)0);
              } else {
                traffic_map.write(traffic_map_index, (bit<1>)1);
              }

              // Finally, send to cpu
              send_to_cpu();

            } else {
              // If the egress is not paused, then we must check if the egress is blocked.
              bit<1> blocked;
              is_port_blocked.read(blocked, (bit<32>)standard_metadata.egress_spec - 1);
              
              if (blocked == (bit<1>)1) {
                // If the egress is blocked, we also send to CPU to buffer.

                // Same thing here, note down that the ingress port is buffering
                is_ingress_buffering.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);

                // Increment the buffer counter
                bit<4> buffer_count;
                buffer_counter.read(buffer_count, (bit<32>)standard_metadata.ingress_port - 1);
                buffer_count = buffer_count + 1;
                buffer_counter.write((bit<32>)standard_metadata.ingress_port - 1, buffer_count);

                // Increment the flow counter
                bit<32> flow_counter_index = (MAX_PORTS * ((bit<32>)standard_metadata.egress_spec - 1)) + (bit<32>)standard_metadata.ingress_port - 1;
                bit<4> flow_count;
                flow_counter.read(flow_count, flow_counter_index);
                flow_count = flow_count + 1;
                flow_counter.write(flow_counter_index, flow_count);

                // Update traffic map
                bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)hdr.cpu.egress_port - 1)) + (bit<32>)hdr.cpu.ingress_port - 1;
                if (flow_count <= 0) {
                  traffic_map.write(traffic_map_index, (bit<1>)0);
                } else {
                  traffic_map.write(traffic_map_index, (bit<1>)1);
                }

                // Finally, send to cpu
                send_to_cpu();
              }
            }
          } 
        }
      } else if (hdr.ethernet.etherType == TYPE_BLOCK) {
        // If it is a block packet, we just set our port blocked state (the target port is either hdr.cpu.ingress_port or hdr.cpu.egress_port, both same)
        is_port_blocked.write((bit<32>)hdr.cpu.ingress_port - 1, (bit<1>)1);

        // Then drop the packet
        drop();

      } else if (hdr.ethernet.etherType == TYPE_RELEASE) {
        // If it is a release packet, we just unset our port blocked state (the target port is either hdr.cpu.ingress_port or hdr.cpu.egress_port, both same)
        is_port_blocked.write((bit<32>)hdr.cpu.ingress_port - 1, (bit<1>)0);

        // Then drop the packet
        drop();
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
    if (hdr.ethernet.isValid() && hdr.ethernet.etherType == TYPE_PAUSE && standard_metadata.ingress_port != CPU_PORT && standard_metadata.mcast_grp == 1) {

      // Out of all these multicasted pause frames, one of them is going to the CPU. We just let that one go
      if (standard_metadata.egress_port == CPU_PORT) {
        // All packets going to CPU will need the header
        hdr.cpu.setValid();
        hdr.cpu.ingress_port = (bit<16>)standard_metadata.ingress_port;
        hdr.cpu.egress_port = (bit<16>)standard_metadata.egress_port;
        hdr.cpu.from_cpu = (bit<8>)0;

      } else {
        // For the rest of each of these multicasted pause frames, we need to check if there are any relations with it.
        // The standard_metadata.ingress_port (where the pause frame came into this switch), is the egress port of the actual flow.
        // So we need to find if the current multicasted packet's egress port (i.e. standard_metadata.egress_port) is an ingress flow in this switch with egress of standard_metadata.ingress_port.
        // Basically, the ports are kinda reversed.
        bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)standard_metadata.ingress_port-1)) + (bit<32>)standard_metadata.egress_port - 1;
        bit<1> marked;
        traffic_map.read(marked, traffic_map_index);
        if (marked == (bit<1>)1) {
          // If there are related flows for this ingress-egress pair, then we need to check if upstream has been paused
          bit<1> paused;
          is_upstream_paused.read(paused, (bit<32>)standard_metadata.egress_port - 1);
          if (paused == (bit<1>)0) {
            // If upstream has not been paused, we drop the packet
            drop();
          }
          // Otherwise, the pause packet will just be forwarded out this port.

        } else {
          // If there are no related flows for this ingress-egress pair, we just drop the packet.
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
    packet.emit(hdr.fyp);
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
