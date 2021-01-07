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
register<bit<6>>(MAX_PORTS)           switch_id_store;
register<bit<6>>(MAX_PORTS)           port_id_store;
register<bit<4>>(MAX_PORTS)           sequence_id_store;
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
header dcfit_t {
  bit<6>  switch_id;
  bit<6>  port_id;
  bit<4>  sequence_id;
  bit<8>  is_second_round;
}

// only packets that are exchanged with CPU have this header.
header cpu_t {
  bit<16> ingress_port;
  bit<16> egress_port;
  bit<8>  is_final_buffer;
  bit<8>  is_final_flow;
  bit<8>  from_cpu;
}

struct metadata {
  /* empty */
  bit<6> switch_id;
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
            TYPE_IPV4:    ipv4;
            TYPE_CUSTOM:  check_if_cpu;
            TYPE_RESUME:  check_if_cpu;
            TYPE_PAUSE:   check_if_dcfit;
            TYPE_BLOCK:   check_if_cpu;
            TYPE_RELEASE: check_if_cpu;
            default:      accept;
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

  // [DCFIT]
  action mark_on_traffic_map(bit<32> i_port, bit<32> e_port, bit<1> mark) {
    bit<32> traffic_map_index = (MAX_PORTS * (e_port - 1)) + i_port - 1;
    traffic_map.write(traffic_map_index, mark);
  }
  // [DCFIT]

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

  action dcfit_attach_switch_id(bit<6> switch_id) {
    hdr.dcfit.switch_id = switch_id;
  }

  table dcfit_attach_switch_id_table {
    key = {
      hdr.dcfit.isValid(): exact;
    }
    actions = {
      dcfit_attach_switch_id;
    }
  }

  action dcfit_check_switch_id(bit<6> switch_id) {
    meta.switch_id = switch_id;
  } 

  table dcfit_check_switch_id_table {
    key = {
      hdr.dcfit.isValid(): exact;
    }
    actions = {
      dcfit_check_switch_id;
    }
  }

  apply {
    if (hdr.ipv4.isValid()) {
      ipv4_lpm.apply();

      if (hdr.ethernet.etherType == TYPE_PAUSE) {
        // If you receive a pause frame, first check where was it from.

        if (standard_metadata.ingress_port == CPU_PORT) {
          // If it's from CPU_PORT, then we simply propagate to specified port
          standard_metadata.egress_spec = (bit<9>)hdr.cpu.ingress_port;

          // Mark that we have paused the upstream
          is_upstream_paused.write((bit<32>)hdr.cpu.ingress_port - 1, (bit<1>)1);

          // Deactivate the cpu header
          hdr.cpu.setInvalid();

          // [DCFIT] Here, we need to append the DCFIT header.
          // What goes into this DCFIT header will depend on the flow that triggered this pause packet, 
          // i.e. that exact packet that crossed the buffer threshold and triggered this pause packet.
          // We access this information via the CPU header, which contains the ingress and egress port information about that packet.

          // First we activate the header.
          hdr.dcfit.setValid();

          // Then we should check if there is any stored information at that intended egress port of the packet.
          bit<6> stored_switch_id;
          switch_id_store.read(stored_switch_id, (bit<32>)hdr.cpu.egress_port - 1);
          bit<6> stored_port_id;
          port_id_store.read(stored_port_id, (bit<32>)hdr.cpu.egress_port - 1);
          bit<4> stored_sequence_id;
          sequence_id_store.read(stored_sequence_id, (bit<32>)hdr.cpu.egress_port - 1);

          // If there is, we use it in our pause packet here.
          // NOTE: The assumption here is that our switch and port ids will never be 0
          if (stored_switch_id != (bit<6>)0 && stored_port_id != (bit<6>)0) {
            hdr.dcfit.switch_id = stored_switch_id;
            hdr.dcfit.port_id = stored_port_id;
            hdr.dcfit.sequence_id = stored_sequence_id;
            hdr.dcfit.is_second_round = (bit<8>)0;
          } else {
            // Otherwise, we generate new information.
            dcfit_attach_switch_id_table.apply(); // This will attach switch ID
            hdr.dcfit.port_id = (bit<6>)hdr.cpu.ingress_port; // This port ID is the port which the pause packet is sent out of.
            hdr.dcfit.sequence_id = (bit<4>)1;
            hdr.dcfit.is_second_round = (bit<8>)0;
          }

          // [DCFIT]

        } else {
          // If it's not from CPU_PORT, then we mark this egress as paused. 
          is_port_paused.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);
          

          // [DCFIT]
          // Whenever we receive a pause packet from a neighbouring switch, we have to do some checks.
          // First, we must check if the switch ID received is the same switch ID as this switch.
          // If it is the same, it means that this checking message was originated from here and is now back.
          //   Then, we must check if the checking message's port number has any relation with the receive port.
          //   If there is relation, then there's a potential deadlock.
          // If the switch ID is not the same, then we first store this checking message at this receive port. 
          //   Next, we must check which ports have relation with this port.
          //   To do so, we need to use multicast
          //   On the egress pipeline, if there is relation, then we must forward this packet.
          dcfit_check_switch_id_table.apply();

          if (meta.switch_id == (bit<6>)3 && standard_metadata.ingress_port == 2 && hdr.dcfit.is_second_round == (bit<8>)0) {
            debugger.write(0, standard_metadata.ingress_global_timestamp);
          }


          if (hdr.dcfit.is_second_round == (bit<8>)1) {

            // For all second round packets, first we check if the switch ID is the same
            if (hdr.dcfit.switch_id == meta.switch_id) {
              // If same switch, then do the same relation check
              bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)standard_metadata.ingress_port - 1)) + (bit<32>)hdr.dcfit.port_id - 1;
              bit<1> marked;
              traffic_map.read(marked, traffic_map_index);
              if (marked == (bit<1>)1) {
                // Deadlock is confirmed
                debugger.write(1, standard_metadata.ingress_global_timestamp);

                drop();

              } else {
                standard_metadata.mcast_grp = 1;
              }

            } else {
              // If different switch, just multicast
              standard_metadata.mcast_grp = 1;
            }

            

          } else {


            if (hdr.dcfit.switch_id == meta.switch_id) {
              // If it is the same, it means that this checking message was originated from here and is now back.
              // Then, we must check if the checking message's port number has any relation with the receive port.
              // If there is relation, then there's a potential deadlock.
              // The relation is: this checking message's port is the ingress, and the receive port is the egress
              bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)standard_metadata.ingress_port - 1)) + (bit<32>)hdr.dcfit.port_id - 1;
              bit<1> marked;
              traffic_map.read(marked, traffic_map_index);
              if (marked == (bit<1>)1) {
                // There is potential deadlock detected!
                // debugger.write(1, standard_metadata.ingress_global_timestamp);

                // Now we use this packet to do the second round check.
                standard_metadata.egress_spec = (bit<9>)hdr.dcfit.port_id;
                hdr.dcfit.is_second_round = (bit<8>)1;

              } else {
                // If there's no relation, then there shouldn't be any CBD along this checking message path.
                // I think here we should proceed as a regular pause packet and forward to related ports like as if the switch_id is different?

                switch_id_store.write((bit<32>)standard_metadata.ingress_port - 1, hdr.dcfit.switch_id);
                port_id_store.write((bit<32>)standard_metadata.ingress_port - 1, hdr.dcfit.port_id);
                sequence_id_store.write((bit<32>)standard_metadata.ingress_port - 1, hdr.dcfit.sequence_id);
                standard_metadata.mcast_grp = 1;
              }
            } else {
              // If the switch ID is not the same, then we first store this checking message at this receive port. 
              switch_id_store.write((bit<32>)standard_metadata.ingress_port - 1, hdr.dcfit.switch_id);
              port_id_store.write((bit<32>)standard_metadata.ingress_port - 1, hdr.dcfit.port_id);
              sequence_id_store.write((bit<32>)standard_metadata.ingress_port - 1, hdr.dcfit.sequence_id);

              // Next, we must check which ports have relation with this port.
              // To do so, we need to use multicast
              // On the egress pipeline, if there is relation, then we must forward this packet.
              standard_metadata.mcast_grp = 1;
            }
          }

          // [DCFIT]

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
          // If come from CPU_PORT, we should check if it is the final packet in that ingress buffer

          if (hdr.cpu.is_final_buffer == (bit<8>)1) {
            // If it is final, then we should mark the ingress as no longer buffering
            is_ingress_buffering.write((bit<32>)hdr.cpu.ingress_port - 1, (bit<1>)0);
          }

          // [DCFIT] Also, we should check if this packet is the last packet for this ingress-egress pair
          if (hdr.cpu.is_final_flow == (bit<8>)1) {
            // If it is final, we should unmark in the traffic map.
            mark_on_traffic_map((bit<32>)hdr.cpu.ingress_port, (bit<32>)hdr.cpu.egress_port, (bit<1>)0);
          }
          // [DCFIT]

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
            // If it is buffering, then we send to the CPU buffer.  

            // Everytime we send a normal packet to CPU, CPU will add it to the ingress buffer.
            // So we need to note the ingress port that is buffering
            is_ingress_buffering.write((bit<32>)standard_metadata.ingress_port - 1, (bit<1>)1);

            // [DCFIT] Mark on the traffic map
            mark_on_traffic_map((bit<32>)standard_metadata.ingress_port, (bit<32>)standard_metadata.egress_spec, (bit<1>)1);
            // [DCFIT]

            // Finally, send to cpu
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

              // [DCFIT] Mark on the traffic map
              mark_on_traffic_map((bit<32>)standard_metadata.ingress_port, (bit<32>)standard_metadata.egress_spec, (bit<1>)1);
              // [DCFIT]

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

                // [DCFIT] Mark on the traffic map
                mark_on_traffic_map((bit<32>)standard_metadata.ingress_port, (bit<32>)standard_metadata.egress_spec, (bit<1>)1);
                // [DCFIT]

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
    // [DCFIT]
    if (hdr.ethernet.isValid() && hdr.ethernet.etherType == TYPE_PAUSE && standard_metadata.ingress_port != CPU_PORT && standard_metadata.mcast_grp == 1) {

      if (hdr.dcfit.is_second_round == (bit<8>)1) {

        // For all second round pause packets, we just check if there is relation and if its paused
        bit<32> traffic_map_index = (MAX_PORTS * ((bit<32>)standard_metadata.ingress_port-1)) + (bit<32>)standard_metadata.egress_port - 1;
        bit<1> traffic_map_mark;
        traffic_map.read(traffic_map_mark, traffic_map_index);
        if (traffic_map_mark == (bit<1>)1) {
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


      } else {



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
          bit<1> traffic_map_mark;
          traffic_map.read(traffic_map_mark, traffic_map_index);
          if (traffic_map_mark == (bit<1>)1) {
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
    // [DCFIT]
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
