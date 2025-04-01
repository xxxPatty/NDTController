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

        #if dpid != 106225808402492:
        #    self.logger.info("failed")
        #    return
        #else:
        #    self.logger.info("succeed")

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
        #match = parser.OFPMatch()
        #actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        #self.add_flow(datapath, 0, match, actions)


        #match = parser.OFPMatch(eth_type=0x0800, ipv4_dst="10.10.10.18")
        #actions = [parser.OFPActionOutput(2)]
        #self.add_flow(datapath, priority=10, match=match, actions=actions)

       
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
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

        # if buffer_id:
        #     mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
        #                             buffer_id=buffer_id, match=match,
        #                             instructions=inst)
        # else:
        #     mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
        #                             match=match, instructions=inst)

        datapath.send_msg(mod)

