from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib.packet import ether_types
import networkx as nx
from time import sleep 
from ryu.controller import dpset

class OSPFLiteRyu(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"dpset": dpset.DPSet, "topology_api_app": switches.Switches}

    def __init__(self, *args, **kwargs):
        super(OSPFLiteRyu, self).__init__(*args, **kwargs)
        self.topology_api_app = self
        self.net = nx.DiGraph()
        # self.mac_to_port = {}  # {dpid: {mac: port}}
        self.switches = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        # Install table-miss flow entry
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        sleep(2)  # Give LLDP time to stabilize

        self.logger.info("Topology update triggered")

        # Update switches
        switch_list = get_switch(self.topology_api_app, None)
        self.switches = {sw.dp.id: sw.dp for sw in switch_list}

        for sw in switch_list:
            if not self.net.has_node(sw.dp.id):
                self.net.add_node(sw.dp.id)

        # Update links
        links_list = get_link(self.topology_api_app, None)
        for link in links_list:
            src = link.src.dpid
            dst = link.dst.dpid
            src_port = link.src.port_no
            dst_port = link.dst.port_no

            if not self.net.has_edge(src, dst):
                self.net.add_edge(src, dst, port=src_port)

            if not self.net.has_edge(dst, src):
                self.net.add_edge(dst, src, port=dst_port)

        # Update hosts
        hosts = get_host(self.topology_api_app, None)
        for host in hosts:
            mac = host.mac
            dpid = host.port.dpid
            port_no = host.port.port_no

            if not self.net.has_node(mac):
                self.net.add_node(mac)

            if not self.net.has_edge(dpid, mac):
                self.net.add_edge(dpid, mac, port=port_no)

            if not self.net.has_edge(mac, dpid):
                self.net.add_edge(mac, dpid)

        # Debug: Print the current topology
        print("\n[Current Topology]")
        print("Switches:", list(self.switches.keys()))
        print("Nodes in Graph:", list(self.net.nodes))
        print("Edges in Graph:")
        for u, v, attr in self.net.edges(data=True):
            print(f"  {u} -> {v} with {attr}")
        print()



    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            return  # Only process IPv4 packets

        ip_dst = ip_pkt.dst

        # self.mac_to_port.setdefault(dpid, {})
        # Learn MAC address
        # self.mac_to_port[dpid][src] = in_port


        if dst not in self.net:
            return  # Destination unknown

        try:
            path = nx.shortest_path(self.net, dpid, dst)
            # self.logger.info("Path from %s to %s: %s", src, dst, path)
        except nx.NetworkXNoPath:
            self.logger.warning("No path from %s to %s", src, dst)
            return

        # Install flow along the path
        for i in range(len(path) - 1):
            src_node = path[i]
            dst_node = path[i + 1]

            port = self.net[src_node][dst_node]['port']
            dp = self.switches[src_node]

            match = dp.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip_dst)
            actions = [dp.ofproto_parser.OFPActionOutput(port)]
            self.add_flow(dp, 10, match, actions)


        # Send packet out directly
        out_port = self.net[path[0]][path[1]]['port']
        actions = [parser.OFPActionOutput(out_port)]

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
        datapath.send_msg(out)
