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
from ryu.lib import stplib
import policy_manager
links = []

class HFsw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'stplib': stplib.Stp}

    def __init__(self, *args, **kwargs):
        super(HFsw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.stp = kwargs['stplib']

    #Listens for incoming packets to the controller
    @set_ev_cls(stplib.EventPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        dp = msg.datapath
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dpid = dp.id
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
                #Flooding ARP packet, beacause dst is not found!
                print "Flooding ARP from: ",src, " to ", dst
                out_port = ofproto_v1_3.OFPP_FLOOD
                actions = [ofp_parser.OFPActionOutput(out_port)]
                out = ofp_parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,actions=actions)
                dp.send_msg(out)


    #Listens for connecting switches (ConnectionUp)
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global links
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
        print "Install_flows executed"
        mac_src=path[0]
        mac_dst=path[-1]

        #Installing host rules
        if len(path) == 2:
            out_port = self.net[mac_dst][mac_src]['port']
            #Mac_dst will be the switch
            self.flow_rule(mac_src, mac_dst, out_port, mac_dst)

        else:
            #Install src
            try:
                out_port= self.net[path[-2]][mac_dst]['port']
                #self.flow_rule(mac_src, mac_dst, out_port, path[-2])
                print "From: SRC:", mac_src, "to DST:", mac_dst, " by switch: ", path[-2], " connected on port: ", out_port

            except KeyError:
                print "Error creating source flow rules"

           #Install dst
            try:
                out_port = self.net[path[1]][mac_src]['port']
                #self.flow_rule(mac_src, mac_dst, out_port, path[1])
                print "From: SRC:", mac_dst, "to DST:", mac_src, " by switch: ", path[1], " connected on port: ", out_port

            except KeyError:
                print "Error creating destination flow rules"


            #Install intermediate switch path. Removes the edges (hosts mac) from the list.
            path = path[1:-1:1]
            print path

            for node in range(len(path)):
                for l in links:
                    try:
                        if node+1 < len(path) and l[0] == path[node] and l[1] == path[node+1]:
                            print "Out_port for link found: ", l[2]['port']
                            out_port = l[2]['port']
                            #self.flow_rule(mac_src, mac_dst, out_port, path[node])
                            print "From: SRC:", mac_dst, "to DST:", mac_src, " by switch: ", path[node], " connected on port: ", out_port
                    except IndexError:
                        print "Iterating function out of range"




                    #ENDED HERE. MAKE SURE TO ITERATE THROUGH LINKS TO FIND A PATH



                   # print "DETTE DA?", links[int(path[node])][int(path[node+1])]['port']


                    #print links[int(node)][int(node)+1]['port']
                    #if links[int(node)][int(next)]['port'] != None:
                        #print "Found the fucking port"

                    #print "COMOOON", links[int(node)][int(path[path.index(node)+1])]['port']
                    #if links[node][path[path.index(node)+1]]['port'] != None:
                        #print "Port found",links[node][path[path.index(node)+1]]['port']


                #for link in links:
                    #if link.src.dpid == node and link.dst.dipd == path[path.index(node)+1]:
                        #Finds the output port to send the packet
                        #out_port=link[link.src.dpid][link.dst.dpid]['port']
                        #self.flow_rule(mac_src, mac_dst, out_port)





    def flow_rule(self,src, dst, inst, sw):
        self.src = src
        self.dst = dst
        self.inst = inst


        ofproto = dp.ofproto
        parser = dp.ofproto_parser

        match = parser.OFPMatch(eth_src=mac_src, eth_dst=mac_dst)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]


        #if buffer_id:
            #mod = parser.OFPFlowMod(datapath=dp, buffer_id=buffer_id,priority=priority, match=match,instructions=inst)
        #else:
        mod = parser.OFPFlowMod(datapath=dp,match=match, instructions=inst)

        dp.send_msg(mod)




#In Link-event: create a method that adds/removes detected links and adds them into links_lis
#Iterating function to ARP without needing to broadcast

#SLUTTET VED INSTALL FLOWS. SLUTTFORE DENNE

