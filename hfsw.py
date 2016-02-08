from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib.packet import packet, ethernet, arp
import copy
import networkx as nx
from ryu.lib import stplib, dpid as dpid_lib
import policy_manager
links = []
switch_list = []
datapaths = {}

class HFsw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(HFsw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.stp = kwargs['stplib']

        config = {dpid_lib.str_to_dpid('0000000000000001'):
                {'bridge': {'priority': 0x8000}},
            dpid_lib.str_to_dpid('0000000000000002'):
                {'bridge': {'priority': 0x9000}},
            dpid_lib.str_to_dpid('0000000000000003'):
                      {'bridge': {'priority': 0xa000}}}
        self.stp.set_config(config)


    #Listens for incoming packets to the controller
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        global datapaths
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        dp = msg.datapath
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = dp.id
        datapaths[dp.id] = msg.datapath
        dst = eth.dst
        src = eth.src
        in_port = msg.match['in_port']
        ofp_parser = dp.ofproto_parser
        arp_pkt = pkt.get_protocol(arp.arp)

        if arp_pkt:
            if src not in self.net: #Learn it
                self.net.add_node(src) # Add a node to the graph
                self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
                self.net.add_edge(dpid,src,{'port':in_port})  # Add link from switch to node and make sure you are identifying the output port.
                print "Node added to grap, Src:", src, " connected to Sw:", dpid, " on port: ",in_port

            if dst in self.net:
                if nx.has_path(self.net, src, dst):
                    try:
                        path=nx.shortest_path(self.net,src,dst) # get shortest path
                        self.install_flows(path, dp)
                        #next=path[path.index(dpid)+1] #get next hop
                        #out_port=self.net[dpid][next]['port'] #get output port

                    except nx.NetworkXNoPath:
                        print "Could not create flow path"
                else:
                    print "No path found between ", src, " and ", dst

            else:
                link_ports = []
                for node in switch_list:
                    for l in links:
                        if l[0] == node.dp.id:
                            link_ports.append(l[2]['port'])
                            #print "link appended: ", l[2]['port']
                    for n in node.ports:
                        if n.port_no not in link_ports:
                            actions = [ofp_parser.OFPActionOutput(n.port_no)]
                            out = ofp_parser.OFPPacketOut(datapath=node.dp, buffer_id=msg.buffer_id, in_port=ofproto_v1_3.OFPP_CONTROLLER,actions=actions)
                            node.dp.send_msg(out)
                            print "ARP forwarded on sw: ", node.dp.id, " out port: ", n.port_no
                    del link_ports[:]


                    #TODO: Remove the broadcast to the port where the ARP request is sent from
                    #TODO: FIX the broadcast. The switches dosent get the packets.!

                #Flooding ARP packet, beacause dst is not found!
                #print "Flooding ARP from: ",src, " to ", dst
                #out_port = ofproto_v1_3.OFPP_FLOOD
                #actions = [ofp_parser.OFPActionOutput(out_port)]
                #out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,actions=actions)
                #dp.send_msg(out)


    #Listens for connecting switches (ConnectionUp)
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global links, switch_list
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

        #Updates graph every time we get topology data
        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)
        print "Switch oppdaget: ", switches


    #Add hosts to hosts_list, but only works at initiation
    @set_ev_cls(event.EventHostAdd)
    def get_host_data(self, ev):
        hosts_list = get_host(self.topology_api_app, None)
        print ev


    #Able to detect link changes immideatly.
    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        link = ev.link
        #print "Link discovered between sw:", link.src.dpid, " and sw:", link.dst.dpid, ". Total number of active links: ",len(links_list)/2
        #TODO: Rerouting prosedure

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        link = ev.link
        #print "Link disconnected between sw:", link.src.dpid, " and sw:", link.dst.dpid, ". Total number of active links: ",len(links_list)/2
        #TODO: Rerouting prosedure




    def install_flows(self, path, dp):
        print "Installing flow rules in one path direction"

        #Sorts path to install flow rules in oposite direction
        path = path[::-1]
        mac_src=path[-1]
        mac_dst=path[0]

        #Installing host rules when directly connected
        if len(path) == 2:
            out_port = self.net[mac_src][mac_dst]['port']
            self.flow_rule(mac_src, mac_dst, out_port, mac_src)
            #TODO: CHECK THIS RULE

        else:
            #Install final destination (host to switch)
            try:
                out_port= self.net[path[1]][mac_dst]['port']
                self.flow_rule(mac_src, mac_dst, out_port, path[1])
                #print "To DST:", mac_dst, "go by switch: ", path[1], " and use port: ", out_port, " when SRC is: ", mac_src

            except KeyError:
               print "Error creating source flow rules"

            #Install intermediate path
            for node in range(len(path)):
                for l in links:
                    try:
                        if node+2 < (len(path)-1) and l[0] == path[node+2] and l[1] == path[node+1]:
                            out_port = l[2]['port']
                            self.flow_rule(mac_src, mac_dst, out_port, path[node+2])
                            #print "To DST:", mac_dst, "go by switch: ", path[node+2], " and use port: ", out_port, " when SRC is: ", mac_src
                    except IndexError:
                        print "Iterating function out of range"




    def flow_rule(self,src, dst, out_port, sw):
        print "Installing rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, ". Action: out_port =  ", out_port
        self.src = src
        self.dst = dst
        self.out_port = out_port
        self.sw = sw

        for node in switch_list:
            if node.dp.id == sw:
                dp = datapaths.get(node.dp.id)
                ofp_parser = dp.ofproto_parser
                actions = [ofp_parser.OFPActionOutput(port=out_port)]
                match = dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                inst = [ofp_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
                mod = dp.ofproto_parser.OFPFlowMod(datapath=dp, match=match, cookie=0,command=ofproto_v1_3.OFPFC_ADD, idle_timeout=0, hard_timeout=0,priority=ofproto_v1_3.OFP_DEFAULT_PRIORITY, instructions=inst)
                dp.send_msg(mod)

