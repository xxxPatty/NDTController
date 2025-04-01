from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet

# VLAN and inter-switch link mapping
VLAN_GROUPS = {
    1: [1, 2, 3, 4, 5],    # VLAN 1 (S1)
    2: [7, 8, 9, 10, 11],  # VLAN 2 (S2)
    3: [13, 14, 15, 16, 17],  # VLAN 3 (S3)
    4: [19, 20, 21, 22, 23],  # VLAN 4 (S4)
    5: [25, 26, 27, 28, 29],  # VLAN 5 (S5)
    6: [31, 32, 33, 34, 35],  # VLAN 6 (S6)
    7: [37, 38, 39, 40, 41],  # VLAN 7 (S7)
    8: [43, 44, 45, 46, 47],  # VLAN 8 (S8)
}

INTER_SWITCH_LINKS = {
    1: [6],   # S1 → S2
    2: [6, 12],  # S2 → S1, S3
    3: [12, 18], # S3 → S2, S4
    4: [18, 24], # S4 → S3, S5
    5: [24, 30], # S5 → S4, S6
    6: [30, 36], # S6 → S5, S7
    7: [36, 42], # S7 → S6, S8
    8: [42]   # S8 → S7
}

class VLANAwareSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(VLANAwareSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # MAC learning table

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        in_port = msg.match['in_port']

        # Determine VLAN based on input port
        vlan_id = None
        for vlan, ports in VLAN_GROUPS.items():
            if in_port in ports:
                vlan_id = vlan
                break

        if vlan_id is None:
            self.logger.info("Port %s not assigned to any VLAN!", in_port)
            return

        self.logger.info("Packet in: src=%s, dst=%s, in_port=%s, VLAN=%s",
                         eth.src, eth.dst, in_port, vlan_id)

        # Learn MAC address
        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port

        # If destination MAC is known
        if eth.dst in self.mac_to_port[datapath.id]:
            out_port = self.mac_to_port[datapath.id][eth.dst]

            # Allow intra-VLAN forwarding
            if out_port in VLAN_GROUPS[vlan_id]:
                actions = [parser.OFPActionOutput(out_port)]
            elif out_port in INTER_SWITCH_LINKS[vlan_id]:  # Allow inter-switch forwarding
                actions = [parser.OFPActionOutput(out_port)]
            else:
                self.logger.info("Dropping packet: VLAN Isolation between %s and %s", in_port, out_port)
                return  # Drop packet
        else:
            # If destination unknown, flood within VLAN and inter-switch links
            actions = [parser.OFPActionOutput(p) for p in VLAN_GROUPS[vlan_id] if p != in_port]  # Intra-VLAN Flood
            actions += [parser.OFPActionOutput(p) for p in INTER_SWITCH_LINKS[vlan_id]]  # Send to inter-switch link

        # Install flow rule
        match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        flow_mod = parser.OFPFlowMod(datapath=datapath, priority=1, match=match, instructions=inst)
        datapath.send_msg(flow_mod)

        # Send packet out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=msg.data)
        datapath.send_msg(out)
