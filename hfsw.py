from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_switch, get_link, get_host
from ryu.lib.packet import packet, ethernet, arp, ether_types
import networkx as nx
import policy_manager
from policy_inputs import generate_policies
from ryu.lib import hub
from operator import attrgetter
from collections import defaultdict
import random

links = []
limited_links = []
switch_list = []
links_list = []
running_policies = []
running_flows = []
sleeptime = 10
port_status = defaultdict(lambda:defaultdict(lambda:None))
old_src_rxtx_bytes = defaultdict(lambda:defaultdict(lambda:None))
old_dst_rxtx_bytes = defaultdict(lambda:defaultdict(lambda:None))
old_src_rxtx_packets = defaultdict(lambda:defaultdict(lambda:None))
old_dst_rxtx_packets = defaultdict(lambda:defaultdict(lambda:None))
link_bandwidths = defaultdict(lambda:defaultdict(lambda:None))
link_bandwidths_ma = defaultdict(lambda:defaultdict(lambda:None))
link_bandwidths_original = defaultdict(lambda:defaultdict(lambda:None))
dropped = defaultdict(lambda:defaultdict(lambda:None))

class HFsw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HFsw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        self.monitor_thread = hub.spawn(self._network_monitor)
        self.new_flow_stats = 0

        #Executes the policies at initiation
        global policy_list
        policy_list=generate_policies()


    #Listens for incoming packets to the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dp = msg.datapath
        dpid = dp.id
        dst = eth.dst
        src = eth.src
        in_port = msg.match['in_port']
        ofp_parser = dp.ofproto_parser
        self.logger.info("Packet in sw %s %s to %s port %s", dpid, src, dst, in_port)

        if src not in self.net: #Learn it
            self.net.add_node(src) # Add a node to the graph
            self.net.add_edge(src,dpid) # Add a link from the node to it's edge switch
            self.net.add_edge(dpid,src,{'port':in_port})  # Add link from switch to node and make sure you are identifying the output port.
            print "Node added to grap, Src:", src, " connected to Sw:", dpid, " on port: ",in_port

        if dst in self.net:
            if nx.has_path(self.net, src, dst):
                try:
                    #Finds policies
                    policy_match = policy_manager.policy_finder(pkt, policy_list)

                    #If an attatched policy is found.
                    if len(policy_match) is not 0:
                        self.packet_handler(src, dst, policy_match)
                    else:
                        print "No policy found"
                        #If no policy is found, use random path.
                        path = nx.shortest_path(self.net,src,dst)

                        #Installs flows and saves the flows
                        self.flow_rule_crawler(path,"install", True)
                        running_flows.append(path)
                        #TODO: create a policy object for this!

                    #Forwards the ARP response after path is created
                    for running in running_policies:
                        if running[0][-1] == dst and dropped[src][dst] is None:
                            for node in switch_list:
                                if running[0][-2] == node.dp.id:
                                    port = self.net[running[0][-2]][dst]['port']
                                    actions = [ofp_parser.OFPActionOutput(port=port)]
                                    out = ofp_parser.OFPPacketOut(datapath=node.dp, buffer_id=0xffffffff, in_port=in_port, actions=actions, data=msg.data)
                                    node.dp.send_msg(out)
                                    print "ARP reply forwarded on sw:", node.dp.id, " out port: ", port
                                    break

                except nx.NetworkXNoPath:
                    print "Could not create flow path"
            else:
                print "No path found between ", src, " and ", dst

        else:
            #Iterates over the switches and sends ARP requests on all ports, except links connecting other switches.
            #(In order to avoid arp broadcast loops).
            pkt_arp = pkt.get_protocol(arp.arp)

            if pkt_arp:
                pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,dst=dst, src=src))
                pkt.add_protocol(arp.arp(opcode=arp.ARP_REQUEST, src_mac=pkt_arp.src_mac, src_ip=pkt_arp.src_ip, dst_mac=pkt_arp.dst_mac, dst_ip=pkt_arp.dst_ip))

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
                            self._send_packet(node.dp, n.port_no, pkt)
                            print "ARP request forwarded on sw: ", node.dp.id, " out port: ", n.port_no
            else:
                print "Waiting for the host's local ARP cache to reset"


    #Listens for connecting switches (ConnectionUp)
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        global links, switch_list, links_list
        switch_list = get_switch(self.topology_api_app, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self.topology_api_app, None)

        #Updates graph every time we get topology data
        self.net.add_nodes_from(switches)
        #self.net.add_edges_from(links)

        #Installs rules to forward arp requests to the controller.
        for switch in switch_list:
            ofp_parser = switch.dp.ofproto_parser
            actions = [ofp_parser.OFPActionOutput(ofproto_v1_3.OFPP_CONTROLLER)]
            match = switch.dp.ofproto_parser.OFPMatch(ofproto_v1_3.OFPR_NO_MATCH)
            inst = [ofp_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
            mod = switch.dp.ofproto_parser.OFPFlowMod(datapath=switch.dp, match=match, cookie=0,command=ofproto_v1_3.OFPFC_ADD, idle_timeout=0, hard_timeout=0,priority=0, instructions=inst)
            switch.dp.send_msg(mod)

        #Generating random link speeds, for simulation purposes
        hub.sleep(0.1)
        for link in links_list:
            linkspeed = random.randint(20,20)
            if link_bandwidths[link.src.dpid][link.src.port_no] is None and link_bandwidths[link.dst.dpid][link.dst.port_no] is None:
                link_bandwidths[link.src.dpid][link.src.port_no] = linkspeed
                link_bandwidths[link.dst.dpid][link.dst.port_no] = linkspeed
                link_bandwidths_original[link.src.dpid][link.src.port_no] = linkspeed
                link_bandwidths_original[link.dst.dpid][link.dst.port_no] = linkspeed
                print "Linkspeed detected: ", link, " speed = ", linkspeed



    #Add hosts to hosts_list, but only works at initiation
    @set_ev_cls(event.EventHostAdd)
    def get_host_data(self, ev):
        hosts_list = get_host(self.topology_api_app, None)


    #Detects new links
    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        global links
        link = ev.link
        links.append((link.src.dpid,link.dst.dpid,{'port':link.src.port_no}))
        #print "Link discovered between sw:", link.src.dpid, " and sw:", link.dst.dpid, ". Total number of active links: ",len(links_list)/2
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


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        try:
            for stat in sorted([flow for flow in body if flow.priority == 1],key=lambda flow: (flow.match['in_port'],flow.match['eth_dst'])):
                self.logger.info('%016x %8x %17s %8x %8d %8d',
                ev.msg.datapath.id,
                stat.match['in_port'], stat.match['eth_dst'],
                stat.instructions[0].actions[0].port,
                stat.packet_count, stat.byte_count)

        except KeyError:
            print "Error!"


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        #Adding the port information to a global list
        global port_status
        port_status[ev.msg.datapath.id] = ev.msg.body



################ CUSTOM FUNCTIONS ######################################################################################

    #Packet handling function
    def packet_handler(self, src, dst, policy_match):
        global link_bandwidths
        #bandwidth_requirement = [[path,link_bandwidth, value, policy]] (traffic load)
        #bandwidth_requirement = [path, policy, value] (single_path)
        #bandwidth_requirement = [policy] (no path found)
        #bandwidth_requirement = 0

        bandwidth_requirement = self.bandwidth_checker(src, dst, policy_match)

        #If no path is found
        if bandwidth_requirement is not 0:

            #If a accepted path is found: install it
            if len(bandwidth_requirement) is 3:    #One path is found

                self.flow_rule_crawler(bandwidth_requirement[0],"install", True)

                #Saves the policy and the path to the running policy list
                running_policies.append([bandwidth_requirement[0], bandwidth_requirement[1]])

                #Update link-bandwidth
                self.update_path_bandwidth(bandwidth_requirement[0], bandwidth_requirement[2])


            elif len(bandwidth_requirement) is 2:
                #If paths are found, but traffic loading is needed. Iterates over the first path and compairs all the other paths with it
                #flow = [path, link_bandwidth, value, policy]
                group_rules_created = []
                for first in bandwidth_requirement:
                    for f in range(len(first[0])-1):
                        group_rule = []
                        for second in bandwidth_requirement:
                            port1 = 0
                            for s in range(len(second[0])-1):
                                #Checks for multiple paths, and that a group rule is not created on the node allready.
                                if first[0][f] == second[0][s] and first[0][f+1] != second[0][s+1] and first[0][f] not in group_rules_created:

                                    if port1 == 0:
                                        port1 = self.find_out_port(first[0][f], first[0][f+1])

                                        #If link capacity is less than policy limit:
                                        if first[1] <= first[2]:
                                            #Weight is policy requirement - link bandwith
                                            rest = first[2] - first[1]
                                            weight = float("{0:.1f}".format(float(first[1])/float(first[2])*100))

                                            group_rule.append([port1, weight])

                                            #Update the link bandwidth
                                            self.update_path_bandwidth(first[0],first[1])
                                            running_policies.append([first[0], first[3]])

                                    port2 = self.find_out_port(first[0][f], second[0][s+1])

                                    weight = 100-weight
                                    group_rule.append([port2, weight])
                                    self.update_path_bandwidth(second[0],rest)
                                    running_policies.append([second[0], second[3]])


                        #If ports has been appended, we know that a group rule must be created
                        if len(group_rule) > 0:

                            #Create a groupID
                            group_id = random.randint(1,99999)

                            #Creates a group rule
                            self.send_group_rule(src, dst, first[0][f], group_rule, group_id)

                            #Creates a flowrule linking to the group rule
                            self.send_flow_rule_install(src,dst,group_id, first[0][f], "group")

                            #Saves the group_rule to a list, to prevent creating two copies
                            group_rules_created.append(first[0][f])

                        else:
                            #Send a flow rule to that switch (ensure its not to the clients)
                            if first[0][f] != first[0][0] and first[0][f+1] != first[0][-1] and first[0][f] not in group_rules_created:

                                #Finds the next port
                                port = self.find_out_port(first[0][f], first[0][f+1])

                                #Installs flow rule to the switch
                                self.send_flow_rule_install(src, dst, port, first[0][f], "port")

                            #Installs flow rule to the host
                            elif first[0][f+1] == first[0][-1]:
                                port = self.net[first[0][f]][first[0][f+1]]['port']
                                self.send_flow_rule_install(src, dst, port, first[0][f], "port")


            elif len(bandwidth_requirement) is 1:
                #running_policies = [path, policy]
                print "Link capacity is filled up! Using moving average to get realistic view of flows"
                possible_paths = nx.all_shortest_paths(self.net, src, dst)
                ma_path = []

                for p in possible_paths:
                    flow_count = 0
                    average_path = 0
                    average_flow = 0
                    full_path = 0

                    #Counts the running flows down a specific path
                    for r in running_policies:
                        if p ==r[0]:
                            flow_count = flow_count+1

                    #Finds average flowing traffic
                    if flow_count is not 0:
                        try:
                            for path in range(len(p)-1):
                                if p[path] != p[0] and p[path+1] != p[-1]:
                                    port = self.find_out_port(p[path], p[path+1])
                                    average_path = average_path + link_bandwidths_ma[p[path]][port]
                                    full_path = full_path + link_bandwidths_original[p[path]][port]

                            #Average flowing traffic, full link capacity and flowing per-flow
                            average_path = average_path/(len(p)-3)
                            full_path = full_path/(len(p)-3)
                            average_flow = average_path/flow_count
                            capacity = full_path - (average_path + average_flow)

                            print "Average per flow :", average_flow, "Average per path ", average_path, "Full path bandwidth", full_path, "with remaining capacity ", capacity

                            req = self.policy_action_fetcher(bandwidth_requirement[0],"bandwidth_requirement")
                            #If less than half of the link capacity is in use by adding the new flow
                            #and the capacity is higher that the policy requirement

                            if capacity >= full_path/2 and capacity >= req:
                                ma_path.append([capacity, p])

                        except TypeError:
                            print "No flow path statistics available: no update yet"
                            ma_path = []

                if len(ma_path) > 0:
                    #Sorts by capacity
                    sorted(ma_path)
                    for ma in ma_path:
                        print ma
                        self.flow_rule_crawler(ma[1],"install", True)
                        running_policies.append([ma[1], p])
                        break

                else:
                    #lower_policies = priority and path
                    print "No possible paths. Trying to move policies!"
                    possible_paths = nx.all_shortest_paths(self.net, src, dst)

                    #For every policy, check if there are lower policies using the same path
                    for p in policy_match:
                        lower_policies = self.find_lower_policies(possible_paths, p)

                        for lower in lower_policies:
                            self.policy_deleter(lower)

                            #Checks if we get a match
                            bandwidth_requirement = self.bandwidth_checker(src, dst, policy_match)

                            if bandwidth_requirement is not 0:
                                print "Ending iteration, found a path"
                                return

                    print "Policy moving executed, and still no path available!"
                    self.logger.info("Packet %s to %s",src, dst)
                    dropped[src][dst] = True

                    #possible_paths = nx.all_shortest_paths(self.net, src, dst)
                    #for p in possible_paths:
                        #self.send_flow_rule_drop(p[-1], p[0], p[-2])
                        #break

        else:
            print "No bandwidth requirements"



    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        #self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


    #Iterates through network data and checks if network parameters is accepted by the policy.
    def bandwidth_checker(self, src, dst, policy_match):
        sorted_actions = []
        flow_rule_policies = []
        single_path = []

        for policy in policy_match:
            #Fetches the sorted policies
            actions = [policy.get_actions()]
            for action in actions:
                for key, value in action.iteritems():
                    if value != 0 or value is True:

                        if key == "bandwidth_requirement":
                            print "Policy_action", key, value
                            traffic_load_bol = True

                            #Gets the possible paths in the network
                            possible_paths = nx.all_shortest_paths(self.net, src, dst)

                            # Filters out the bad links
                            bad_links = self.check_path_bandwidth(possible_paths, value)

                            for l in bad_links:
                                try:
                                    self.net.remove_edge(l.src.dpid, l.dst.dpid)
                                    self.net.remove_edge(l.dst.dpid, l.src.dpid)
                                except nx.NetworkXError:
                                    print "Link is already deleted"

                            #Tries to find a path among the filtred links
                            if nx.has_path(self.net, src, dst):

                                #If a path is available, take the shortest path.
                                possible_paths = nx.shortest_path(self.net,src,dst)
                                print "Found a path which matches requirements: ", possible_paths

                                #Skip traffic loading,due to a path is found
                                traffic_load_bol = False

                                #Adds the bad links back in top routing pool
                                for l in bad_links:
                                    try:
                                        self.net.add_edge(l.src.dpid, l.dst.dpid)
                                        self.net.add_edge(l.dst.dpid, l.src.dpid)
                                    except nx.NetworkXError:
                                        print "Link is already added"

                                #Install flow rules
                                return [possible_paths, policy, value]

                                #Adds the bad links back in top routing pool
                            for l in bad_links:
                                try:
                                    self.net.add_edge(l.src.dpid, l.dst.dpid)
                                    self.net.add_edge(l.dst.dpid, l.src.dpid)
                                except nx.NetworkXError:
                                    print "Link is already added"

                            if traffic_load_bol:
                                #If no paths is found
                                print "Trying traffic loading"
                                traffic_load_paths = []
                                traffic_load_limit = value

                                #Find all possible physical paths
                                possible_paths = nx.all_shortest_paths(self.net, src, dst)

                                for p in possible_paths:
                                    link_bandwidth = 999
                                    #Iterate through path to find the weakest link
                                    for nodes in range(len(p)-1):
                                        #If a link in the path is weak, fetch the weakest link.
                                        for link in limited_links:
                                            if p[nodes] == link[1].src.dpid and p[nodes+1] == link[1].dst.dpid:
                                                if link_bandwidth > link[0]:
                                                    link_bandwidth = link[0]
                                            elif p[nodes] == link[1].dst.dpid and p[nodes+1] == link[1].src.dpid:
                                                if link_bandwidth > link[0]:
                                                    link_bandwidth = link[0]

                                    #Appends the path to a traffic_load_path
                                    traffic_load_paths.append([p,link_bandwidth, value, policy])

                                    for nodez in range(len(p)-1):
                                        for chosen in limited_links:
                                            if p[nodez] == chosen[1].src.dpid and p[nodez+1] == chosen[1].dst.dpid:
                                                chosen[0] = chosen[0]-link_bandwidth
                                    traffic_load_limit = traffic_load_limit - link_bandwidth

                                    #Only use traffic load to split the traffic using two paths
                                    if traffic_load_limit <= 0 and len(traffic_load_paths) <= 2:
                                        for p in traffic_load_paths:
                                            print "Bandwidth limit achieved, using ", p

                                        #Returns the list of the possible paths!
                                        return traffic_load_paths

                                if value > 0 or len(traffic_load_paths) > 2:
                                    return [policy]

                        else:
                            #No bandwith requirements
                            return 0



    #Finds the output port from src to dst.
    def find_out_port(self, src,dst):
        for link in links_list:
            if link.src.dpid == src and link.dst.dpid == dst:
                return link.src.port_no


    #Finds the link capasity (bandwidth) for a link
    def find_link_capacity(self, src, port_no):
        try:
            return link_bandwidths[src][port_no]

        except IndexError:
            return 0


    def policy_deleter(self, lower_policy):

        #lower_policy = running_policies
        #running_policies = [[possible_paths], policy]
        remove = []
        action = lower_policy[1].get_actions()

        for key, value in action.iteritems():
            if value != 0 or value is True:
                if key == "bandwidth_requirement":
                    print "Found a weaker policy with requirement:", key, value, "on path: ", lower_policy[0]

                    #Removes the policy from the running list
                    for r in range(len(running_policies)):
                        print len(running_policies)
                        if running_policies[r] == lower_policy:
                            remove.append(r)

                            #Deletes the whole path in both directions!
                            self.flow_rule_crawler(lower_policy[0], "delete", True)

                            self.flow_rule_crawler(lower_policy[0], "delete", False)

                            #Update the link bandwidths:
                            for node in range(len(lower_policy[0])-1):
                                if lower_policy[0][node] != lower_policy[0][0] and lower_policy[0][node+1] != lower_policy[0][-1]:

                                    #Update path bandwidth in both directions
                                    port1 = self.find_out_port(lower_policy[0][node], lower_policy[0][node+1])
                                    link_bandwidths[lower_policy[0][node]][port1] = link_bandwidths[lower_policy[0][node]][port1] + value

                                    port2 = self.find_out_port(lower_policy[0][node+1], lower_policy[0][node])
                                    link_bandwidths[lower_policy[0][node+1]][port2] = link_bandwidths[lower_policy[0][node+1]][port2] + value

                                    print "[POLICY DELETER] Link bandwidths updated on link connecting sw:",lower_policy[0][node], " and sw:",lower_policy[0][node+1], " with capasity ", link_bandwidths[lower_policy[0][node]][port1]
                                    print "[POLICY DELETER] Link bandwidths updated on link connecting sw:",lower_policy[0][node+1], " and sw:",lower_policy[0][node], " with capasity ", link_bandwidths[lower_policy[0][node+1]][port2]

                    try:
                        for pop in remove:
                            running_policies.pop(pop)
                    except IndexError:
                        self.logger("Iterating error due to remove items from running policies")


    #Checks policy_lists for key value, based on priority. Returns a list of lower policies!
    def find_lower_policies(self, paths, policy):
        lower_policies = []
        # running_policies[path, policy] other policies and the chosen paths
        # paths = possible paths for this policy
        # policy = this policy

        for p in running_policies:
            #If a running policy has weaker priority: seek to find bandwidth requirements. Higher number means a lower priority
            for path in paths:
                #Check if this policy is higher than other. And ensure that it is not checked against itself
                if p[1].priority > policy.priority and (p[0][0]+p[0][-1] != path[0]+path[-1]):
                    lower_policies.append(p)


        #Removing the policy from lower_policies if there excists a higher policy for the same flow.
        for l in lower_policies:
            for p in running_policies:
                if p[0][0] == l[0][0] and p[0][-1] == l[0][-1] and p[1].priority < policy.priority:
                    lower_policies.pop(l)
        return lower_policies


    def find_lowest_policy_on_link(self, link):
        lowest = []
        for r in running_policies:
            for l in range(len(r[0])-1):
                if r[0][l] != r[0][0] and r[0][l+1]!= r[0][-1]:
                    if r[0][l]==link.src.dpid and r[0][l+1] == link.dst.dpid:
                        lowest.append([r[1].priority, r])

                    elif r[0][l]==link.dst.dpid and r[0][l+1] == link.src.dpid:
                        lowest.append([r[1].priority, r])

        for low in sorted(lowest):
            return low[1]



    #Checks a the path for bandwidth and compair it with policy requirements
    def check_path_bandwidth(self, possible_paths, limit):
        bad = []
        del limited_links[:]
        #Path crawler
        for p in possible_paths:
            for node in range(len(p)):
                for l in links_list:
                    try:
                        if node+2 < (len(p)-1) and l.src.dpid == p[node+2] and l.dst.dpid == p[node+1]:

                            if link_bandwidths[l.src.dpid][l.src.port_no] < limit:
                                print "Error! " , l, " bandwidth is :", link_bandwidths[l.src.dpid][l.src.port_no], " while policy needs ", limit

                                #Appends the bad link and the bandwidth to the limited_links list
                                bad.append(l)
                                limited_links.append([link_bandwidths[l.src.dpid][l.src.port_no], l])

                    except IndexError:
                        print "Iterating function out of range"
        return bad


    #For a given path; substracts the policy_requirement bandwidth from the link_bandwidth
    def update_path_bandwidth(self, path, policy_requirement):
        for node in range(len(path)):
            for link in links_list:
                try:
                    if node+2 < (len(path)-1) and link.src.dpid == path[node+2] and link.dst.dpid == path[node+1]:
                        link_bandwidths[link.src.dpid][link.src.port_no] = link_bandwidths[link.src.dpid][link.src.port_no] - policy_requirement
                        link_bandwidths[link.dst.dpid][link.dst.port_no] = link_bandwidths[link.dst.dpid][link.dst.port_no] - policy_requirement
                        print "Link bandwidths updated on link connecting sw: ", link.src.dpid, " and ", link.dst.dpid, " with capacity: ", link_bandwidths[link.src.dpid][link.src.port_no]
                        print "Link bandwidths updated on link connecting sw: ", link.dst.dpid, " and ", link.src.dpid, " with capasity: ", link_bandwidths[link.dst.dpid][link.dst.port_no]

                except IndexError:
                    print "Iterating function out of range"




    #Iterate through flow tables based on path and action. Action is install or delete flow rules
    def flow_rule_crawler(self, path, action, reverse):

        if reverse:
            path = path[::-1]

        mac_src=path[-1]
        mac_dst=path[0]

        try:
            out_port= self.net[path[1]][mac_dst]['port']
            if action == "install":
                self.send_flow_rule_install(mac_src, mac_dst, out_port, path[1], "port")

            elif action == "delete":
                self.send_flow_rule_delete(mac_src, mac_dst, out_port, path[1], "port")

        except KeyError:
            print "Error creating source flow rules"

        #Install intermediate path
        for node in range(len(path)):
            for l in links_list:
                try:
                    if node+2 < (len(path)-1) and l.src.dpid == path[node+2] and l.dst.dpid == path[node+1]:
                        out_port = l.src.port_no
                        if action == "install":
                            self.send_flow_rule_install(mac_src, mac_dst, out_port, path[node+2], "port")

                        elif action == "delete":
                            self.send_flow_rule_delete(mac_src, mac_dst, out_port, path[node+2],"port")

                except IndexError:
                    print "Iterating function out of range"



    #Returns the action value
    def policy_action_fetcher(self, policy, condition):
        actions = [policy.get_actions()]
        for action in actions:
            for key, value in action.iteritems():
                if value != 0 or value is True:
                    if key == condition:
                        return value



    def _network_monitor(self):
        ma = 1
        while True:
            for node in switch_list:
                self.send_stats_request(node.dp)
                hub.sleep(1)

            for link in links_list:
                #Checks flowing traffic
                flowing = self.check_link(link, True, True)

                if link_bandwidths_ma[link.src.dpid][link.src.port_no] is not None:
                    link_bandwidths_ma[link.src.dpid][link.src.port_no] = ((link_bandwidths_ma[link.src.dpid][link.src.port_no]*(ma-1))+flowing[1])/ma

                else:
                    link_bandwidths_ma[link.src.dpid][link.src.port_no] = flowing[1]

                print "Link average on link, SW", link.src.dpid, " to SW ",link.dst.dpid, " is ", link_bandwidths_ma[link.src.dpid][link.src.port_no], "Packet loss", flowing[0]

                #If the controller notifies dropped packets on a used link:
                if link_bandwidths_ma[link.src.dpid][link.src.port_no] >= 1 and flowing[0] > 0.2:
                    print "Notifing dropped packets on link SW", link.src.dpid, " to ", " SW", link.dst.dpid, ". Deleting the lowest policy to free bandwidth"
                    #lowest_policy = self.find_lowest_policy_on_link(link)
                    #self.policy_deleter(lowest_policy)

            if ma < 20:
                ma = ma+1
            else:
                ma = 1
                link_bandwidths_ma.clear()
                #Clears blocked src-dst pairs
                dropped.clear()
            hub.sleep(sleeptime)


    #Iterating function to inspect a given link for packet loss and transmitting traffic
    def check_link(self, link, measure_loss, measure_bandwidth):
        global old_dst_rxtx_bytes, old_src_rxtx_bytes, old_dst_rxtx_packets, old_src_rxtx_packets
        src_rxtx_bytes = 0
        dst_rxtx_bytes = 0
        src_tx_pkts = 0
        dst_rx_pkts = 0


        for stat in port_status[link.src.dpid]:
            if link.src.port_no == stat.port_no:
                src_rxtx_bytes = stat.rx_bytes + stat.tx_bytes
                src_tx_pkts = stat.tx_packets

        for stat in port_status[link.dst.dpid]:
            if link.dst.port_no == stat.port_no:
                dst_rxtx_bytes = stat.rx_bytes + stat.tx_bytes
                dst_rx_pkts = stat.rx_packets

        if old_src_rxtx_bytes[link.src.dpid][link.src.port_no] is None:
            old_src_rxtx_bytes[link.src.dpid][link.src.port_no] = src_rxtx_bytes
            old_dst_rxtx_bytes[link.dst.dpid][link.dst.port_no] = dst_rxtx_bytes

        if old_src_rxtx_packets[link.src.dpid][link.src.port_no] is None:
            old_src_rxtx_packets[link.src.dpid][link.src.port_no] = src_tx_pkts

        if old_dst_rxtx_packets[link.dst.dpid][link.dst.port_no] is None:
                old_dst_rxtx_packets[link.dst.dpid][link.dst.port_no] = dst_rx_pkts

        pkt_sent = float(abs(src_tx_pkts - old_src_rxtx_packets[link.src.dpid][link.src.port_no]))

        pkt_rec = float(abs(dst_rx_pkts - old_dst_rxtx_packets[link.dst.dpid][link.dst.port_no]))

        if pkt_sent == 0 or pkt_rec == 0 or pkt_sent == pkt_rec or pkt_rec > pkt_sent:
            pathloss = 0.0

        else:
            pathloss = float("{0:.1f}".format(1-(pkt_rec/pkt_sent)))

        old_traffic = (old_src_rxtx_bytes[link.src.dpid][link.src.port_no] + old_dst_rxtx_bytes[link.dst.dpid][link.dst.port_no])

        traffic = float("{0:.1f}".format(abs((8*float(old_traffic - (src_rxtx_bytes+dst_rxtx_bytes))/4/1000000)/sleeptime)))

        old_src_rxtx_bytes[link.src.dpid][link.src.port_no] = src_rxtx_bytes
        old_dst_rxtx_bytes[link.dst.dpid][link.dst.port_no] = dst_rxtx_bytes
        old_src_rxtx_packets[link.src.dpid][link.src.port_no] = src_tx_pkts
        old_dst_rxtx_packets[link.dst.dpid][link.dst.port_no] = dst_rx_pkts

        if measure_bandwidth and measure_loss:
            #print traffic, " mbit/s and with packet loss of ", dropped, "the last ", sleeptime, "seconds at link:", link.src.dpid, "-", link.dst.dpid
            return [pathloss, traffic]

        elif measure_loss:
            #print dropped, "bytes lost the last ", sleeptime, "  seconds at link ", link.src.dpid, " - ", link.dst.dpid
            return pathloss

        elif measure_bandwidth:
            #print traffic, " mbit/s at link:", link.src.dpid, " - ", link.dst.dpid
            return traffic



################ OPENFLOW MESSAGE FUNCTIONS ############################################################################


    #Function to send a flow rule to a switch
    def send_flow_rule_install(self,src, dst, out_port, sw, action):
        print "Installing flow rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, ". Action: out_port =  ", out_port
        hard_timeout = 0

        for node in switch_list:
            if node.dp.id == sw:
                ofp_parser = node.dp.ofproto_parser
                hard_timeout = 0
                if action == "port":
                    actions = [ofp_parser.OFPActionOutput(port=out_port)]
                if action == "group":
                    actions = [ofp_parser.OFPActionGroup(out_port)]
                if action == "drop":
                    actions = [ofp_parser.OFPActionOutput()]
                    hard_timeout = 30

                match = node.dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                inst = [ofp_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
                mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, cookie=0, command=ofproto_v1_3.OFPFC_ADD, idle_timeout=100, hard_timeout=hard_timeout,priority=100, instructions=inst)
                node.dp.send_msg(mod)


    def send_flow_rule_drop(self, src, dst, sw):
        print "################################################################################################################"
        print "# Drop rule created on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, " #"
        print "################################################################################################################"

        for node in switch_list:
            if node.dp.id == sw:
                match = node.dp.ofproto_parser.OFPMatch(eth_src=src)
                mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, cookie=0, command=ofproto_v1_3.OFPFC_ADD, hard_timeout=30,priority=2, instructions=[])
                node.dp.send_msg(mod)


    def send_flow_rule_delete(self,src, dst, out_port, sw, action):
        print "Deleting flow rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, ". Action: out_port/group =  ", out_port
        for node in switch_list:

            if node.dp.id == sw:
                match = node.dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                if action == "port":
                    mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, command=ofproto_v1_3.OFPFC_DELETE, out_port=ofproto_v1_3.OFPP_ANY, out_group=ofproto_v1_3.OFPP_ANY, buffer_id=ofproto_v1_3.OFP_NO_BUFFER)
                if action == "group":
                    #Group id must be specified
                    mod = node.dp.ofproto_parser.OFPFlowMod(atapath=node.dp, match=match, command=ofproto_v1_3.OFPFC_DELETE, out_port=ofproto_v1_3.OFPP_ANY, out_group=out_port, buffer_id=ofproto_v1_3.OFP_NO_BUFFER)

                node.dp.send_msg(mod)



    #Function to send a group rule to a switch based on a list with ports and weights
    def send_group_rule(self, src, dst, sw, port_weight_list, group_id):
        self.src = src
        self.dst = dst
        self.sw = sw
        buckets = []
        ports = []
        weights = []
        for node in switch_list:
            if node.dp.id == sw:
                ofp_parser = node.dp.ofproto_parser

                for pw in port_weight_list:
                    port = pw[0]
                    weight = pw[1]
                    queue = ofp_parser.OFPActionSetQueue(0)
                    actions = [queue, ofp_parser.OFPActionOutput(port)]
                    watch_port = ofproto_v1_3.OFPP_ANY
                    watch_group = ofproto_v1_3.OFPQ_ALL
                    buckets.extend([ofp_parser.OFPBucket(weight, watch_port, watch_group, actions)])
                    ports.append(port)
                    weights.append(weight)

                req = ofp_parser.OFPGroupMod(node.dp, ofproto_v1_3.OFPFC_ADD, ofproto_v1_3.OFPGT_SELECT, group_id, buckets)
                node.dp.send_msg(req)

                print "Installing group rule on :", sw, " Group ID = ", group_id, "Ports used = ", ports, " weights = ", weights



    #Function to send a stats requests to a switch
    def send_stats_request(self,datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #Sends a Flow Stats Request
        #req = parser.OFPFlowStatsRequest(datapath)
        #datapath.send_msg(req)

        #Sends a Port_Stats_Request
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        #Sends a Group_Stats_Request
        #req = parser.OFPGroupStatsRequest(datapath,0, ofproto.OFPG_ALL,None)
        #datapath.send_msg(req)

# TODO: 1 Add traffic classes based on best links
# TODO: 2 Add more parameters to the policy; strict, elastic etc.

# TODO: Look at how to police/throttle the bandwidth. Per-flow meters
# TODO: Look at queue options
# TODO: FIX create a policy object for running flows which does not have a policy
# TODO: FIX What happends to a running policy when traffic loading is applied? It needs to be splitted