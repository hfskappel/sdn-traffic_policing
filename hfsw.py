from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib.packet import packet, ethernet, ipv6, vlan, ipv4, packet_base, arp
import copy
import networkx as nx

switch_list, links_list = [],[]


class HFsw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HFsw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()

    #Listens for incoming packets to the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        dp = msg.datapath
        eth = pkt.get_protocols(ethernet.ethernet)[0]            #Must be added behind eth in order to execute this.
        dpid = dp.id
        dst = eth.dst
        src = eth.src
        in_port = msg.match['in_port']
        ofp_parser = dp.ofproto_parser

        #print "Source: ", src, " Dest: ", dst

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            if src not in self.net: #Learn it
                self.net.add_node(src) # Add a node to the graph
                self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
                self.net.add_edge(dpid,src,{'port':in_port})  # Add link from switch to node and make sure you are identifying the output port.
                print "Node added, src:", src, " connected to sw:", dpid, " on port: ",in_port

            if dst in self.net:
                try:
                    path=nx.shortest_path(self.net,src,dst) # get shortest path
                    #next=path[path.index(dpid)+1] #get next hop
                    #out_port=self.net[dpid][next]['port'] #get output port
                    print "PATH: ", path

                except nx.NetworkXNoPath:
                    print "No path found"
            print dst
            #else:
            #    out_port = ofproto_v1_3.OFPP_FLOOD
            #    actions = [ofp_parser.OFPActionOutput(out_port)]
             #   out = ofp_parser.OFPPacketOut(
             #   datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,actions=actions)
            #    dp.send_msg(out)





        #ip6 = pkt.get_protocols(ipv6.ipv6)
        #ip4 = pkt.get_protocols(ipv4.ipv4)
        #vlans = pkt.get_protocols(vlan.vlan)
        #print eth




    #Listens for connecting switches (ConnectionUp)
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global  switch_list, links_list
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

        #Updates graph every time we get topology data
        self.net.add_nodes_from(switches)
        self.net.add_edges_from(links)

        #print "Links funnet: ", links
        #print "Switcher funnet: ", switches

        for h in ev.switch.ports:
            print h, type(h)

        #ENDED HERE. GOING TO FIND EVERY PORT WHICH IS NOT A LINK-PORT IN ORDER TO IMPROVE ARP!




    #Add hosts to hosts_list, but only works at initiation
    @set_ev_cls(event.EventHostAdd)
    def get_host_data(self, ev):
        hosts_list = get_host(self.topology_api_app, None)

        for h in hosts_list:
            print h




    #Able to detect link changes immideatly.
    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        link = ev.link
        print "Link discovered between sw:", link.src.dpid, " and sw:", link.dst.dpid, ". Total number of active links: ",len(links_list)/2
        #TODO: Rerouting prosedure

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        link = ev.link
        print "Link disconnected between sw:", link.src.dpid, " and sw:", link.dst.dpid, ". Total number of active links: ",len(links_list)/2
        #TODO: Rerouting prosedure



#In Link-event: create a method that adds/removes detected links and adds them into links_lis
#Iterating function to ARP without needing to broadcast

