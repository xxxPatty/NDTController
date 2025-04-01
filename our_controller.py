from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.controller import dpset
import time


class PortForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"dpset": dpset.DPSet, "topology_api_app": switches.Switches}

    def __init__(self, *args, **kwargs):
        super(PortForwarding, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = kwargs["topology_api_app"]  # Ensure topology module is initialized

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        dpid = datapath.id  # Get the switch's unique identifier
        self.logger.info("Switch connected: DPID=%s", dpid)

    
        #=======================================================
        # Clear all existing flows from the switch.
        #match = parser.OFPMatch()  # matches all flows
        #mod = parser.OFPFlowMod(datapath=datapath,
        #                        command=ofproto.OFPFC_DELETE,
        #                        out_port=ofproto.OFPP_ANY,
        #                        out_group=ofproto.OFPG_ANY,
        #                        match=match)
        #datapath.send_msg(mod)
        #=======================================================

        # Optionally, install a table-miss rule here
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


        if dpid == 14721744660103168000:
            self.logger.info("Connected to SW1")

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.18")
            actions = [parser.OFPActionOutput(47)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.16")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)


            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.17")
            actions = [parser.OFPActionOutput(47)]
            actions2 = [parser.OFPActionOutput(48)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)
            #self.mod_flow(datapath, priority=10, match=match, actions=actions2)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.15")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)
        elif dpid == 14721744659231801344:
            self.logger.info("Connected to SW2")

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.17")
            actions = [parser.OFPActionOutput(47)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.15")
            actions = [parser.OFPActionOutput(48)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)
        elif dpid == 106225808402492:
            self.logger.info("Connected to SW3")
            
            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.18")
            actions = [parser.OFPActionOutput(2)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.16")
            actions = [parser.OFPActionOutput(23)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.17")
            actions = [parser.OFPActionOutput(1)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.15")
            actions = [parser.OFPActionOutput(23)]
            actions2 = [parser.OFPActionOutput(24)]
            self.add_flow(datapath, priority=10, match=match, actions=actions)
            #self.mod_flow(datapath, priority=10, match=match, actions=actions2)


       
    def mod_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
             mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_MODIFY_STRICT, priority=priority,
                                     buffer_id=buffer_id, match=match,
                                     instructions=inst)
        else:
             mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_MODIFY_STRICT, priority=priority,
                                     match=match, instructions=inst)
        
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    buffer_id=buffer_id, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)        

        datapath.send_msg(mod)

       
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ensure LLDP packets are processed
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # self.logger.info("LLDP received on switch %s, port %s", datapath.id, in_port)

            # Forward LLDP packets to all ports except the incoming port
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=msg.data
            )
            datapath.send_msg(out)
            return

        

        """# learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                #self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                pass
                #self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)"""
