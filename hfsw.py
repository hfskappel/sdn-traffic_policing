from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib.packet import packet, ethernet, arp, ipv4
import networkx as nx
import policy_manager
from policy_inputs import generate_policies

links = []
switch_list = []
links_list = []


class HFsw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HFsw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        #Executes the policies at initiation
        #generate_policies()
        global policy_list
        policy_list=generate_policies()


    #Listens for incoming packets to the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
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
            print "ARP request received at sw:",dpid
            if src not in self.net: #Learn it
                self.net.add_node(src) # Add a node to the graph
                self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
                self.net.add_edge(dpid,src,{'port':in_port})  # Add link from switch to node and make sure you are identifying the output port.
                print "Node added to grap, Src:", src, " connected to Sw:", dpid, " on port: ",in_port

            if dst in self.net:
                if nx.has_path(self.net, src, dst):
                    try:
                        #Find policies
                        policy_manager.policy_finder(pkt, policy_list)
                        #Gets the shortest path
                        path=nx.shortest_path(self.net,src,dst)
                        self.install_flows(path)

                    except nx.NetworkXNoPath:
                        print "Could not create flow path"
                else:
                    print "No path found between ", src, " and ", dst

            else:
                #Iterates over the switches and sends ARP requests on all ports, except links connecting other switches.
                #(In order to avoid arp broadcast loops).
                print "Flooding ARP"

                for node in switch_list:
                            for n in node.ports:
                                host_port = True
                                for l in links:
                                    #If it is a link connecting two switches
                                    if l[0] == node.dp.id and l[2]['port'] == n.port_no:
                                        host_port = False
                                        break
                                    #If it is the port where the request is sent from
                                    elif node.dp.id == dpid and n.port_no == in_port:
                                        host_port = False
                                        break

                                if host_port:
                                    actions = [ofp_parser.OFPActionOutput(port=n.port_no)]
                                    out = ofp_parser.OFPPacketOut(datapath=node.dp, buffer_id=0xffffffff, in_port=in_port, actions=actions, data=msg.data)
                                    node.dp.send_msg(out)
                                    print "ARP forwarded on sw:", node.dp.id, " out port: ", n.port_no





    #Listens for connecting switches (ConnectionUp)
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global links, switch_list, links_list
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)
        #links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]

        #Updates graph every time we get topology data
        self.net.add_nodes_from(switches)
        #self.net.add_edges_from(links)
        print "Switch oppdaget: ", switches
        print "Link oppdaget", links


    #Add hosts to hosts_list, but only works at initiation
    @set_ev_cls(event.EventHostAdd)
    def get_host_data(self, ev):
        hosts_list = get_host(self.topology_api_app, None)
        print ev


    #Detects new links
    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        global links
        link = ev.link
        links.append((link.src.dpid,link.dst.dpid,{'port':link.src.port_no}))
        print "Link discovered between sw:", link.src.dpid, " and sw:", link.dst.dpid, ". Total number of active links: ",len(links_list)/2
        self.net.add_edges_from(links)


    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        link = ev.link
        for l in links:
            if l[0] == link.src.dpid and l[1] == link.dst.dpid:
                links.pop(links.index(l))
            elif l[0] == link.dst.dpid and l[1] == link.src.dpid:
                links.pop(links.index(l))

        print "Link disconnected between sw:", link.src.dpid, " and sw:", link.dst.dpid, ". Total number of active links: ",len(links_list)/2
        #TODO: Rerouting prosedure




    def install_flows(self, path):
        print "Installing flow rules in one path direction"

        #Sorts path to install flow rules in oposite direction
        path = path[::-1]
        mac_src=path[-1]
        mac_dst=path[0]

            #Install final destination (host to switch)
        try:
            out_port= self.net[path[1]][mac_dst]['port']
            self.send_flow_rule(mac_src, mac_dst, out_port, path[1])

        except KeyError:
            print "Error creating source flow rules"

            #Install intermediate path
        for node in range(len(path)):
            for l in links:
                try:
                    if node+2 < (len(path)-1) and l[0] == path[node+2] and l[1] == path[node+1]:
                        out_port = l[2]['port']
                        self.send_flow_rule(mac_src, mac_dst, out_port, path[node+2])
                except IndexError:
                    print "Iterating function out of range"





    #Function to send a flow rule to a switch
    def send_flow_rule(self,src, dst, out_port, sw):
        print "Installing rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, ". Action: out_port =  ", out_port
        self.src = src
        self.dst = dst
        self.out_port = out_port
        self.sw = sw

        for node in switch_list:
            if node.dp.id == sw:
                ofp_parser = node.dp.ofproto_parser
                actions = [ofp_parser.OFPActionOutput(port=out_port)]
                match = node.dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                inst = [ofp_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
                mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, cookie=0,command=ofproto_v1_3.OFPFC_ADD, idle_timeout=0, hard_timeout=0,priority=ofproto_v1_3.OFP_DEFAULT_PRIORITY, instructions=inst)
                node.dp.send_msg(mod)




    #Function to group rule to a switch
    def send_group_rule(self, src, dst, sw):
        self.src = src
        self.dst = dst
        self.sw = sw

        for node in switch_list:
            if node.dp.id == sw:
                ofp_parser = node.dp.ofproto_parser
                port = 1
                max_len = 2000
                actions = [ofp_parser.OFPActionOutput(port, max_len)]

                weight = 100
                watch_port = 0
                watch_group = 0
                buckets = [ofp_parser.OFPBucket(weight, watch_port, watch_group,actions)]

                group_id = 1
                req = ofp_parser.OFPGroupMod(datapath=node.dp, command=ofproto_v1_3.OFPGC_ADD, type=ofproto_v1_3.OFPGT_SELECT, group_id=group_id, buckets=buckets)
                node.dp.send_msg(req)















#TODO: Check why it is so slow. Due to loss at ARP reply?
#TODO: Add group_mod function and test it
#TODO: Is it possible to add more actions to the flow rules. Look at how we can send a flow through multiple group tables
# http://csie.nqu.edu.tw/smallko/sdn/ryu_multipath_13.htm
#http://ryu-zhdoc.readthedocs.org/en/latest/ofproto_v1_3_ref.html
#
#
#
#
