from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls, MAIN_DISPATCHER
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4

class PortForwarding(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
  
    def __init__(self, *args, **kwargs):
        super(PortForwarding, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser


        # TODO
        dpid = datapath.id  # Get the switch's unique identifier
        self.logger.info("Switch connected: DPID=%s", dpid)

        if dpid != 14721744659231801344:
            self.logger.info("failed")
            return
        else:
            self.logger.info("succeed")

        #=======================================================
        # Clear all existing flows from the switch.
        match = parser.OFPMatch()  # matches all flows
        mod = parser.OFPFlowMod(datapath=datapath,
                                command=ofproto.OFPFC_DELETE,
                                out_port=ofproto.OFPP_ANY,
                                out_group=ofproto.OFPG_ANY,
                                match=match)
        datapath.send_msg(mod)
        #=======================================================

        # Optionally, install a table-miss rule here
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        # Install a flow rule: if packet comes in on port 20, output to port 13.
        # TODO
        # match = parser.OFPMatch(in_port=1)
        # actions = [parser.OFPActionOutput(13)]
        # # TODO
        # self.add_flow(datapath, 3, match, actions)
        # # TODO
        # match = parser.OFPMatch(in_port=13)
        # actions = [parser.OFPActionOutput(1)]
        # # TODO
        # self.add_flow(datapath, 3, match, actions)


        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.17")
        actions = [parser.OFPActionOutput(47)]
        self.add_flow(datapath, priority=10, match=match, actions=actions)

        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.15")
        actions = [parser.OFPActionOutput(48)]
        self.add_flow(datapath, priority=10, match=match, actions=actions)

       

       

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        # if buffer_id:
        #     mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_MODIFY_STRICT, priority=priority,
        #                             buffer_id=buffer_id, match=match,
        #                             instructions=inst)
        # else:
        #     mod = parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_MODIFY_STRICT, priority=priority,
        #                             match=match, instructions=inst)

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
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
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
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
