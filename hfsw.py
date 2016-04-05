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
from collections import defaultdict
import random
import paramiko

sleeptime = 10
real_time_limit = 3
links, limited_links,switch_list, links_list, running_policies, running_flows, real_time_pool = [],[],[],[],[],[], []
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
        self.ssh_thread = hub.spawn(self._queue_class_generator)
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
            print "Node added to graph, Src:", src, " connected to Sw:", dpid, " on port: ",in_port

        if dst in self.net:
            if nx.has_path(self.net, src, dst):
                try:
                    #Finds policies
                    policy_match = policy_manager.policy_finder(pkt, policy_list)

                    #If an attatched policy is found.
                    if len(policy_match) is not 0:
                        self.packet_handler(src, dst, policy_match)

                    else:
                        for running in running_policies:
                            if (running[0][0] == src and running[0][-1] == dst) or (running[0][0] == dst and running[0][-1] == src):
                                print "An existing flow policy is applied for opposite direction of the flow."
                                path = nx.shortest_path(self.net,src,dst)
                                self.flow_rule_crawler_install(path,True, 0)
                                return

                        print "No policy found"
                        #If no policy is found, use random path.
                        paths = nx.all_simple_paths(self.net,src,dst)

                        #Finds the weakest path, due to a low priority flow.
                        low_paths = self.calculate_traffic_class(paths,3)

                        if low_paths[-1][1] not in running_flows:
                            running_flows.append(low_paths[-1][1])

                            #Installs flows using queue 1 and saves the flows
                            self.flow_rule_crawler_install(low_paths[-1][1], True, 1)

                except nx.NetworkXNoPath:
                    print "Could not create flow path"
            else:
                print "No path found between ", src, " and ", dst

        else:
            #Iterates over the switches and sends ARP requests on all ports, except links connecting other switches. (In order to avoid arp broadcast loops).
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
        global switch_list, links_list
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

        #Generation of link speeds, for simulation purposes
        hub.sleep(0.1)
        for link in links_list:

            #linkspeed = random.randint(3,3)
            #if link_bandwidths[link.src.dpid][link.src.port_no] is None and link_bandwidths[link.dst.dpid][link.dst.port_no] is None:
            #    link_bandwidths[link.src.dpid][link.src.port_no] = linkspeed
            #    link_bandwidths[link.dst.dpid][link.dst.port_no] = linkspeed
            #    link_bandwidths_original[link.src.dpid][link.src.port_no] = linkspeed
            #    link_bandwidths_original[link.dst.dpid][link.dst.port_no] = linkspeed
            #    print "Link capacity detected: ", link, " speed = ", linkspeed

            if link_bandwidths[link.src.dpid][link.src.port_no] is None and link_bandwidths[link.dst.dpid][link.dst.port_no] is None:

                if (link.src.dpid == 1 and link.dst.dpid == 2) or (link.src.dpid == 2 and link.dst.dpid == 4)\
                        or (link.src.dpid == 1 and link.dst.dpid == 3) or (link.src.dpid == 3 and link.dst.dpid == 4):
                    link_bandwidths[link.src.dpid][link.src.port_no] = 2
                    link_bandwidths[link.dst.dpid][link.dst.port_no] = 2
                    link_bandwidths_original[link.src.dpid][link.src.port_no] = 2
                    link_bandwidths_original[link.dst.dpid][link.dst.port_no] = 2

                if link.src.dpid == 1 and link.dst.dpid == 4:
                    link_bandwidths[link.src.dpid][link.src.port_no] = 4
                    link_bandwidths[link.dst.dpid][link.dst.port_no] = 4
                    link_bandwidths_original[link.src.dpid][link.src.port_no] = 4
                    link_bandwidths_original[link.dst.dpid][link.dst.port_no] = 4

     #Detects new links
    @set_ev_cls(event.EventLinkAdd)
    def _event_link_add_handler(self, ev):
        global links
        link = ev.link
        links.append((link.src.dpid,link.dst.dpid,{'port':link.src.port_no}))
        self.net.add_edges_from(links)

        if link_bandwidths[link.src.dpid][link.src.port_no] is not None:
            link_bandwidths[link.src.dpid][link.src.port_no] = link_bandwidths_original[link.src.dpid][link.src.port_no]
            print "Link capacity detected: ", link, " speed = ", link_bandwidths[link.src.dpid][link.src.port_no]

        else:
            linkspeed = random.randint(3,3)
            link_bandwidths[link.src.dpid][link.src.port_no] = linkspeed
            link_bandwidths_original[link.src.dpid][link.src.port_no] = linkspeed
            print "[New] Link capacity detected: ", link, " speed = ", linkspeed

    @set_ev_cls(event.EventLinkDelete)
    def _event_link_delete_handler(self, ev):
        link = ev.link
        for l in links:
            if l[0] == link.src.dpid and l[1] == link.dst.dpid:
                links.pop(links.index(l))
            elif l[0] == link.dst.dpid and l[1] == link.src.dpid:
                links.pop(links.index(l))

        link_bandwidths[link.src.dpid][link.src.port_no] = link_bandwidths_original[link.src.dpid][link.src.port_no]
        print "[LINK FAILURE] Link bandwidths updated on link connecting sw:",link.src.dpid, " and sw:", link.dst.dpid, " with capasity ", link_bandwidths[link.src.dpid][link.src.port_no]

        try:
            self.net.remove_edge(link.src.dpid, link.dst.dpid)

        except nx.NetworkXError:
            print "Link already deleted!"

        #Iterating over running policies to see if any are using the disconnected link. Delete it if it does.
        for running_policy in running_policies:
            for node in range(len(running_policy[0])-1):
                if running_policy[0][node] != running_policy[0][0] and running_policy[0][node+1] != running_policy[0][-1]:
                    if running_policy[0][node] == link.src.dpid and running_policy[0][node+1] == link.dst.dpid:
                        #Deletes the policy from the toal path and updates link bandwidths
                        self.policy_deleter(running_policy)

        #Iterating over the best-effort flows to see if any are using the disconnected link. Delete it if it does.
        for running_flow in running_flows:
            for node in range(len(running_flow)-1):
                if running_flow[node] != running_flow[0] and running_flow[node+1] != running_flow[-1]:
                    if running_flow[node] == link.src.dpid and running_flow[node+1] == link.dst.dpid:

                        #Removing flows and update the controller
                        running_flows.pop(running_flows.index(running_flow))
                        self.flow_rule_crawler_delete(running_flow, True)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        #Adding the port information to a global list, used for traffic measurements
        global port_status
        port_status[ev.msg.datapath.id] = ev.msg.body

    @set_ev_cls(ofp_event.EventOFPFlowRemoved)
    #Used to update the controller when a flow rule times out. Ensure concistency.
    def _flow_removed(self, ev):
        index = 0
        remove = []
        for running in running_policies:
            if running[0][0] == ev.msg.match['eth_src'] and running[0][-1] == ev.msg.match['eth_dst'] and ev.msg.datapath.id in running[0][2:-2]:
                print "Flow with policy timed out"
                bw = self.policy_action_fetcher(running[1], "bandwidth_requirement")
                self.update_path_bandwidth(running[0], bw, False)
                remove.append(index)
            index = index+1

        if len(remove) > 0:
            for pop in remove:
                running_policies.pop(pop)
                return

        index = 0
        for flow in running_flows:
            if (flow[0] == ev.msg.match['eth_src'] and flow[-1] == ev.msg.match['eth_dst']):
                remove.append(index)
                print "Flow without policy timed out"
            index = index+1

        if len(remove) > 0:
            for pop in remove:
                running_flows.pop(pop)
                return

################ CUSTOM FUNCTIONS ######################################################################################

    #Packet handling function
    def packet_handler(self, src, dst, policy_match):
        global link_bandwidths
        #bandwidth_requirement = [[path,link_bandwidth, value, policy]] (traffic load)
        #bandwidth_requirement = [path, policy, value] (single_path)
        #bandwidth_requirement = [policy] (no path found)
        #bandwidth_requirement = 0

        for running in running_policies:
            if running[0][0] == src and running[0][-1] == dst:
                print "Policy already added"
                return

        bw_req = False
        for match in policy_match:
            block = self.policy_action_fetcher(match, "block")
            if block is True:
                possible_paths = nx.all_simple_paths(self.net, src, dst)
                for p in possible_paths:
                    self.send_flow_rule_drop(p[0], p[-1], p[1])
                    self.send_flow_rule_drop(p[-1], p[-0], p[-2])
                    return

            if bw_req is False:
                bw = self.policy_action_fetcher(match, "bandwidth_requirement")
                if bw is not None:
                    bw_policy = match
                    bw_req = True
                    real_time = self.policy_action_fetcher(match, "real-time")
                    if real_time is not None:
                        rt_links = self.real_time_pool()
                        for rt in rt_links:
                            try:
                                self.net.remove_edge(rt.src.dpid, rt.dst.dpid)
                                self.net.remove_edge(rt.dst.dpid, rt.src.dpid)
                            except nx.NetworkXError:
                                "Link already removed"

        if bw_req is True:

            bandwidth_requirement = self.bandwidth_checker(src, dst, bw_policy)

            if real_time is not None:
                for rt in rt_links:
                    try:
                        self.net.add_edge(rt.src.dpid, rt.dst.dpid)
                        self.net.add_edge(rt.dst.dpid, rt.src.dpid)
                    except nx.NetworkXError:
                        "Link already added"

            #If a single path is found
            if len(bandwidth_requirement) is 3:
                traffic_class = None
                random_routing = False
                for match in policy_match:
                    if random_routing == False:
                        random_routing = self.policy_action_fetcher(match, "random_routing")
                    if traffic_class is None:
                        traffic_class = self.policy_action_fetcher(match, "traffic_class")
                        print "Traffic class ", traffic_class
                        if traffic_class is not None:
                            #Finds the best paths within the approved paths
                            weighted_paths = self.calculate_traffic_class(bandwidth_requirement[0], traffic_class)

                #If random routing and traffic class is applied to flow: choose randomly in the traffic class pool
                if random_routing is True and traffic_class is not 0:
                    route = random.randint(0,len(weighted_paths)-1)
                    self.flow_rule_crawler_install(weighted_paths[route][1], True, 0)
                    running_policies.append([weighted_paths[route][1], bandwidth_requirement[1]])
                    self.update_path_bandwidth(weighted_paths[route][1], bandwidth_requirement[2], True)

                #If random routing is applied to flow: choose randomly in the path pool
                elif random_routing is True and traffic_class is 0:
                    route = random.randint(0,len(bandwidth_requirement[0])-1)
                    self.flow_rule_crawler_install(bandwidth_requirement[0][route], True, 0)
                    running_policies.append([bandwidth_requirement[0][route], bandwidth_requirement[1]])
                    self.update_path_bandwidth(bandwidth_requirement[0][route], bandwidth_requirement[2], True)

                #If traffic class is applied to flow, but no randomess, choose the best path.
                elif traffic_class is not None and random_routing is not True:
                    self.flow_rule_crawler_install(weighted_paths[0][1], True, 0)
                    running_policies.append([weighted_paths[0][1], bandwidth_requirement[1]])
                    self.update_path_bandwidth(weighted_paths[0][1], bandwidth_requirement[2], True)

                else: #If nothing; choose the first from the path pool (shortest path) and update the controller.
                    self.flow_rule_crawler_install(bandwidth_requirement[0][0], True, 0)
                    running_policies.append([bandwidth_requirement[0][0], bandwidth_requirement[1]])
                    self.update_path_bandwidth(bandwidth_requirement[0][0], bandwidth_requirement[2], True)

                return

            #If paths are found, but traffic loading is needed to obtain the bandwidth requirement.
            elif len(bandwidth_requirement) is 2:
                loadbalance = False
                #Iterates over the first path and compairs all the other paths with it
                for match in policy_match:
                    loadbalance = self.policy_action_fetcher(match, "allow_load_balance")
                    if loadbalance is True:
                        group_rules_created = []
                        for first in bandwidth_requirement:
                            for f in range(len(first[0])-1):
                                group_rule = []
                                for second in bandwidth_requirement:
                                    port1 = 0
                                    for s in range(len(second[0])-1):
                                        #Checks for multiple paths, and that a group rule is not created on the node already.
                                        if first[0][f] == second[0][s] and first[0][f+1] != second[0][s+1] and first[0][f] not in group_rules_created:

                                            if port1 == 0:
                                                port1 = self.find_out_port(first[0][f], first[0][f+1])

                                                #If link capacity is less than policy limit:
                                                if first[1] <= first[2]:
                                                    #Weight is calculated as a percentage.
                                                    rest = first[2] - first[1]
                                                    weight = float("{0:.1f}".format(float(first[1])/float(first[2])*100))

                                                    group_rule.append([port1, weight])

                                                    #Update the link bandwidth
                                                    self.update_path_bandwidth(first[0],first[1], True)
                                                    splitted_policy1 = policy_manager.Policy()
                                                    splitted_policy1.priority = bandwidth_requirement[0][3].priority
                                                    splitted_policy1.action(bandwidth_requirement=first[1])
                                                    running_policies.append([first[0], splitted_policy1])

                                            port2 = self.find_out_port(first[0][f], second[0][s+1])

                                            weight = 100-weight
                                            group_rule.append([port2, weight])
                                            self.update_path_bandwidth(second[0],rest, True)
                                            splitted_policy2 = policy_manager.Policy()
                                            splitted_policy2.priority = bandwidth_requirement[0][3].priority
                                            print " YOLOOOOL ", bandwidth_requirement[0][3].priority
                                            splitted_policy2.action(bandwidth_requirement=rest)
                                            running_policies.append([second[0], splitted_policy2])

                                #If ports has been appended, a group rule must be created
                                if len(group_rule) > 0:

                                    #Create a groupID
                                    group_id = random.randint(1,99999)

                                    #Creates a group rule
                                    self.send_group_rule(src, dst, first[0][f], group_rule, group_id)

                                    #Creates a flowrule linking to the group rule
                                    self.send_flow_rule_install(src,dst,group_id, first[0][f], "group", None)

                                    #Saves the group_rule to a list, to prevent creating two copies
                                    group_rules_created.append(first[0][f])

                                else:
                                    #Send a flow rule to that switch (ensure its not to the clients)
                                    if first[0][f] != first[0][0] and first[0][f+1] != first[0][-1] and first[0][f] not in group_rules_created:

                                        #Finds the next port
                                        port = self.find_out_port(first[0][f], first[0][f+1])

                                        #Installs flow rule to the switch
                                        self.send_flow_rule_install(src, dst, port, first[0][f], "port", 0)

                                    #Installs flow rule to the host
                                    elif first[0][f+1] == first[0][-1]:
                                        port = self.net[first[0][f]][first[0][f+1]]['port']
                                        self.send_flow_rule_install(src, dst, port, first[0][f], "port", None)
                        return
                print "Traffic loading is not allowed by policy"
                loadbalance = False


            #If no possible paths are found with traffic loading; continue to inspect the flowing traffic
            if len(bandwidth_requirement) == 1 or loadbalance is False:
                #running_policies = [path, policy]
                print "Using moving average to get picture of the flowing traffic."
                possible_paths = nx.all_simple_paths(self.net, src, dst)
                ma_path = []

                non_strict = False
                for match in policy_match:
                    non_strict = self.policy_action_fetcher(match, "bandwidth_requirement_nonstrict")
                    if non_strict is True:
                        #If the policy is non-strict, try to add it to queue 1.
                        for p in possible_paths:
                            flow_count = 0
                            average_path = 0
                            average_flow = 0
                            full_path = 0

                            #Counts the running flows down a specific path
                            for r in running_policies:
                                if p[1:-1] ==r[0][1:-1]:
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

                                    print "Average per flow :", average_flow, "Average per path ", average_path, "Full path bandwidth", full_path, "with realistic remaining capacity ", capacity

                                    req = self.policy_action_fetcher(bandwidth_requirement[0],"bandwidth_requirement")

                                    #If less than 50% link capacity is in use by adding the new flow as well as the realistic capacity is higher that the policy requirement
                                    if capacity >= full_path/2 and capacity >= req:
                                        ma_path.append([capacity, p])

                                except TypeError:
                                    print "No flow path statistics available: no update yet"
                                    ma_path = []

                        if len(ma_path) > 0:
                            #Sorts by capacity
                            sorted(ma_path)
                            for ma in ma_path:
                                #Installs the flow in queue 1 (non-qos)
                                self.flow_rule_crawler_install(ma[1], True, 1)
                                #running_policies.append([ma[1], bandwidth_requirement])
                                running_flows.append(ma[1])
                                print "Policy requirements are achieved based on current path traffic. Using the link temporary."
                                break
                        else:
                            non_strict = False
                        break

                    else:
                        print "The policy is strict, adding it to a path is not allowed."
                        non_strict = False

                #If the policy is strict, it is not allowed to be added in non-qos queue.
                if non_strict is False:
                    #lower_policies = priority and path
                    print "Trying to delete lower policies in order to make room for new policy."
                    possible_paths = nx.all_simple_paths(self.net, src, dst)
                    #For every policy, check if there are lower policies using the same path

                    for p in policy_match:
                        lower_policies = self.find_lower_policies(possible_paths, p)

                        for lower in lower_policies:
                            self.policy_deleter(lower)

                            #Checks if we get a match
                            bandwidth_requirement = self.bandwidth_checker(src, dst, bw_policy)

                            if bandwidth_requirement is not 0:
                                print "Ending iteration, found a path after removing policy"
                                return

                    print "Policy moving executed, and still no path available!"
                    possible_paths = nx.all_simple_paths(self.net, src, dst)
                    for p in possible_paths:
                        self.send_flow_rule_drop(p[0], p[-1], p[1])
                        self.send_flow_rule_drop(p[-1], p[-0], p[-2])
                    dropped[src][dst] = True

        else:
            print "Policy contains no bandwidth requirements. Please update it to minimum 1!"


    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)


    #Iterates through network data and checks if network parameters is accepted by the policy.
    def bandwidth_checker(self, src, dst, policy):
        sorted_actions = []
        flow_rule_policies = []
        single_path = []
        actions = [policy.get_actions()]
        single_path = []
        bw_limit = 0
        for action in actions:
            for key, value in action.iteritems():
                if value != 0 or value is True:
                    if key == "bandwidth_requirement":
                        bw_limit = value

        #print "Policy_action", key, value
        traffic_load_bol = True

        #Gets the possible paths in the network
        possible_paths = nx.all_simple_paths(self.net, src, dst)

        # Filters out the bad links
        bad_links = self.check_path_bandwidth(possible_paths, bw_limit)

        for l in bad_links:
            try:
                self.net.remove_edge(l.src.dpid, l.dst.dpid)
                self.net.remove_edge(l.dst.dpid, l.src.dpid)
            except nx.NetworkXError:
                print "Link is already deleted"

        #Tries to find a path among the filtred links
        if nx.has_path(self.net, src, dst):

            #If a path is available, take the shortest path.
            possible_paths = nx.all_simple_paths(self.net,src,dst)
            print "Found a path which matches requirements"

            for path in possible_paths:
                single_path.append(path)

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
            return [single_path, policy, bw_limit]

            #Adds the bad links back in top routing pool
        for l in bad_links:
            try:
                self.net.add_edge(l.src.dpid, l.dst.dpid)
                self.net.add_edge(l.dst.dpid, l.src.dpid)
            except nx.NetworkXError:
                print "Link is already added"

        if traffic_load_bol:
            #If no paths is found
            print "Checking if traffic loading is possible"
            traffic_load_paths = []
            traffic_load_limit = bw_limit

            #Find all possible physical paths
            possible_paths = nx.all_simple_paths(self.net, src, dst)

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
                traffic_load_paths.append([p,link_bandwidth, bw_limit, policy])

                for nodez in range(len(p)-1):
                    for chosen in limited_links:
                        if p[nodez] == chosen[1].src.dpid and p[nodez+1] == chosen[1].dst.dpid:
                            chosen[0] = chosen[0]-link_bandwidth
                traffic_load_limit = traffic_load_limit - link_bandwidth

                #Only use traffic load to split the traffic using two paths
                if traffic_load_limit <= 0 and len(traffic_load_paths) <= 2:
                    for p in traffic_load_paths:
                        print "Traffic loading is possible by using ", p

                    #Returns the list of the possible paths!
                    return traffic_load_paths

            if bw_limit > 0 or len(traffic_load_paths) > 2:
                print "Traffic loading is not possible."
                return [policy]



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

    #Generates a virtual network for real time traffic. Filters out any links less than 2 mbit
    def real_time_pool(self):
        if len(real_time_pool)== 0:
            for link in links_list:
                #Removes any link with capcacity two
                if link_bandwidths_original[link.src.dpid][link.src.port_no] <= real_time_limit:
                    real_time_pool.append(link)

            return real_time_pool

        else:
            return real_time_pool




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
                        if running_policies[r] == lower_policy:
                            remove.append(r)

                            #Deletes the whole path in both directions!
                            self.flow_rule_crawler_delete(lower_policy[0], True)

                            self.flow_rule_crawler_delete(lower_policy[0], False)

                            #Update the link bandwidths:
                            for node in range(len(lower_policy[0])-1):
                                if lower_policy[0][node] != lower_policy[0][0] and lower_policy[0][node+1] != lower_policy[0][-1]:

                                    #Update path bandwidth in both directions
                                    try:
                                        port1 = self.find_out_port(lower_policy[0][node], lower_policy[0][node+1])
                                        link_bandwidths[lower_policy[0][node]][port1] = link_bandwidths[lower_policy[0][node]][port1] + value

                                        port2 = self.find_out_port(lower_policy[0][node+1], lower_policy[0][node])
                                        link_bandwidths[lower_policy[0][node+1]][port2] = link_bandwidths[lower_policy[0][node+1]][port2] + value

                                        print "[POLICY DELETER] Link bandwidths updated on link connecting sw:",lower_policy[0][node], " and sw:",lower_policy[0][node+1], " with capasity ", link_bandwidths[lower_policy[0][node]][port1]
                                        print "[POLICY DELETER] Link bandwidths updated on link connecting sw:",lower_policy[0][node+1], " and sw:",lower_policy[0][node], " with capasity ", link_bandwidths[lower_policy[0][node+1]][port2]

                                    except TypeError:
                                        print "Disconnected link removed "

                    try:
                        for pop in remove:
                            running_policies.pop(pop)
                    except IndexError:
                        self.logger("Iterating error due to remove items from running policies")


    #Checks policy_lists for key value, based on priority. Returns a list of lower policies!
    def find_lower_policies(self, paths, policy):
        lower_policies = []
        sorted_lower_policies = []
        # running_policies[path, policy] other policies and the chosen paths
        # paths = possible paths for this policy
        # policy = this policy

        for path in paths:
            #If a running policy has weaker priority: seek to find bandwidth requirements. Higher number means a lower priority
            for p in running_policies:
                #Check if this policy is higher than other. And ensure that it is not checked against itself
                if p[1].priority > policy.priority and (p[0][0] != path[0] and p[0][-1] != path[-1]):
                    if ([p[1].priority, p]) not in lower_policies:
                        lower_policies.append([p[1].priority, p])
                        print "FOUND LOWER POLICY ", p, " with pri ", p[1].priority

        #Removing the policy from lower_policies if there exists a higher policy for the same flow.
        #for l in lower_policies:
        #    for p in running_policies:
        #        if p[0][0] == l[1][0][0] and p[0][-1] == l[1][0][-1] and p[1].priority < policy.priority:
        #            lower_policies.pop(lower_policies.index(l))

        for l in sorted(lower_policies,reverse=True):
            sorted_lower_policies.append(l[1])

        print "SORTED POLICIES BY PRI ", sorted_lower_policies
        return sorted_lower_policies


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
        else:
            return 0


    def find_non_policies_on_link(self, link):
        running = []
        for r in running_flows:
            for l in range(len(r[0])-1):
                try:
                    if r[l] != r[0] and r[l+1]!= r[-1]:
                        if r[l]==link.src.dpid and r[l+1] == link.dst.dpid:
                            running.append(r)

                        elif r[l]==link.dst.dpid and r[l+1] == link.src.dpid:
                            running.append(r)
                except IndexError:
                    pass
        return running


    #Calculate traffic class by adding the links and the bw!
    def calculate_traffic_class(self, paths, traffic_class):
        weighted_paths = []
        for path in paths:
            weakest_link = 999
            path_bw = 0
            for node in range(len(path)-1):
                if path[node] != path[0] and path[node+1] != path[-1]:
                    port = self.find_out_port(path[node], path[node+1])
                    path_bw = path_bw + link_bandwidths_original[path[node]][port]
                    if weakest_link > link_bandwidths_original[path[node]][port]:
                        weakest_link = link_bandwidths_original[path[node]][port]

            #Algorithm to find the best path: Multiply weakest link with the average link bandwidth
            weighted = weakest_link*(path_bw/(len(path)-2))
            weighted_paths.append([weighted, path])

        relative_length = float(len(weighted_paths)/100)

        edge = int(relative_length*25)
        if edge == 0:
            edge = 1

        sorted_weighted_paths = sorted(weighted_paths, reverse=True)

        if len(weighted_paths) >= 3:
            if traffic_class == 1:
                print "Traffic class 1: ", sorted_weighted_paths[:int(edge)]
                return sorted_weighted_paths[:int(edge)]

            elif traffic_class == 2:
                print "Traffic class 2: ", sorted_weighted_paths[int(edge):-(int(edge))]
                return sorted_weighted_paths[int(edge):-(int(edge))]

            else:
                print "Traffic class 3: ", sorted_weighted_paths[-int(edge):]
                return sorted_weighted_paths[-int(edge):]

        elif len(weighted_paths) == 2:
            if traffic_class == 1 or traffic_class == 2:
                print "Traffic class 1/2: ", sorted_weighted_paths[:int(edge)]
                return sorted_weighted_paths[:int(edge)]
            else:
                print "Traffic class 3: ", sorted_weighted_paths[int(edge):]
                return sorted_weighted_paths[int(edge):]
        else:
            print "Traffic class used, but only one possible path"
            return sorted_weighted_paths

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
    def update_path_bandwidth(self, path, policy_requirement, negative):
        for node in range(len(path)):
            for link in links_list:
                try:
                    if negative:
                        if node+2 < (len(path)-1) and link.src.dpid == path[node+2] and link.dst.dpid == path[node+1]:
                            link_bandwidths[link.src.dpid][link.src.port_no] = link_bandwidths[link.src.dpid][link.src.port_no] - policy_requirement
                            link_bandwidths[link.dst.dpid][link.dst.port_no] = link_bandwidths[link.dst.dpid][link.dst.port_no] - policy_requirement
                            print "Link bandwidths updated on link connecting sw: ", link.src.dpid, " and ", link.dst.dpid, " with capacity: ", link_bandwidths[link.src.dpid][link.src.port_no]
                            print "Link bandwidths updated on link connecting sw: ", link.dst.dpid, " and ", link.src.dpid, " with capasity: ", link_bandwidths[link.dst.dpid][link.dst.port_no]

                    else:
                        if node+2 < (len(path)-1) and link.src.dpid == path[node+2] and link.dst.dpid == path[node+1]:
                            link_bandwidths[link.src.dpid][link.src.port_no] = link_bandwidths[link.src.dpid][link.src.port_no] + policy_requirement
                            link_bandwidths[link.dst.dpid][link.dst.port_no] = link_bandwidths[link.dst.dpid][link.dst.port_no] + policy_requirement
                            print "Link bandwidths updated on link connecting sw: ", link.src.dpid, " and ", link.dst.dpid, " with capacity: ", link_bandwidths[link.src.dpid][link.src.port_no]
                            print "Link bandwidths updated on link connecting sw: ", link.dst.dpid, " and ", link.src.dpid, " with capasity: ", link_bandwidths[link.dst.dpid][link.dst.port_no]


                except IndexError:
                    print "Iterating function out of range"


    #Iterate through flow tables based on path and action. Action is install or delete flow rules
    def flow_rule_crawler_install(self, path, reverse, queue):
        if reverse:
            path = path[::-1]
        mac_src=path[-1]
        mac_dst=path[0]

        try:
            out_port= self.net[path[1]][mac_dst]['port']
            self.send_flow_rule_install(mac_src, mac_dst, out_port, path[1], "port", None)

        except KeyError:
            print "Error creating source flow rules"

        #Install intermediate path
        for node in range(len(path)):
            for l in links_list:
                try:
                    if node+2 < (len(path)-1) and l.src.dpid == path[node+2] and l.dst.dpid == path[node+1]:
                        out_port = l.src.port_no
                        self.send_flow_rule_install(mac_src, mac_dst, out_port, path[node+2], "port", queue)

                except IndexError:
                    print "Iterating function out of range"


    def flow_rule_crawler_delete(self, path, reverse):
        if reverse:
            path = path[::-1]
        src = path[0]
        dst = path[-1]

        for node in range(len(path)-1):
                    if path[node] != src and path[node] != dst:
                        self.send_flow_rule_delete(src, dst, None, path[node],"port")


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

                #print "Link average on link, SW", link.src.dpid, " to SW ",link.dst.dpid, " is ", link_bandwidths_ma[link.src.dpid][link.src.port_no], "Packet loss", flowing[0]

                #If the controller notifies dropped packets on a used link:
                if link_bandwidths_ma[link.src.dpid][link.src.port_no] >= 1 and flowing[0] > 0.2:

                    #If we have running flows without any policies attatched, remove to prioritize non-strict policies
                    non_policies = self.find_non_policies_on_link(link)
                    if non_policies is not None or non_policies is not 0:
                        print "Dropped packets detected on link SW", link.src.dpid, " to ", " SW", link.dst.dpid, ". Deleting non-policy flows to free bandwidth"
                        for np in non_policies:
                            self.flow_rule_crawler_delete(np, False)
                            self.flow_rule_crawler_delete(np, True)

                    else:
                        lowest_policy = self.find_lowest_policy_on_link(link)
                        if lowest_policy is not 0:
                            print "Dropped packets detected on link SW", link.src.dpid, " to ", " SW", link.dst.dpid, ". Deleting the lowest policy to free bandwidth"
                            self.policy_deleter(lowest_policy)

            if ma < 20:
                ma = ma+1
            else:
                ma = 1
                link_bandwidths_ma.clear()
                #Clears blocked src-dst pairs
                dropped.clear()
                for policy in running_policies:
                    print "Active flows with policies: ", policy

                for flows in running_flows:
                    print "Active flows without policies: ", flows
            hub.sleep(sleeptime)


    def _queue_class_generator(self):
        #Adds two QoS queues to each port, ensuring that strict policies are added to q0 and non-strict to q1
        hub.sleep(2)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect('129.241.209.195', username='mininet', password='mininet')
        #ssh.connect('192.168.1.33', username='mininet', password='mininet')
        #ssh.connect('192.168.38.112', username='mininet', password='mininet')
        try:
            for switch in switch_list:
                for port in switch.ports:
                    for link in links_list:
                        if link.src.dpid == switch.dp.id and port.port_no == link.src.port_no:
                            link_bw = (link_bandwidths[link.src.dpid][link.src.port_no]*1000000)

                            queuecmd = "sudo ovs-vsctl set port %s qos=@defaultqos -- --id=@defaultqos create qos type=linux-htb other-config:max-rate=%s queues=0=@q0,1=@q1 -- " \
                                       "--id=@q0 create queue other-config:min-rate=%s -- " \
                                       "--id=@q1 create queue other-config:min-rate=0"% (port.name,link_bw, link_bw)

                            policecmd = " sudo ovs-vsctl set Interface %s ingress_policing_rate=%s" % (port.name,(link_bw/1000))

                            ssh.exec_command(queuecmd)
                            ssh.exec_command(policecmd)
                            print queuecmd
                            print policecmd
        except RuntimeError:
            pass

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
    def send_flow_rule_install(self,src, dst, out_port, sw, action, queue):
        print "Installing flow rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, ". Action: out_port =  ", out_port

        for node in switch_list:
            if node.dp.id == sw:
                ofp_parser = node.dp.ofproto_parser
                if action == "port" and queue is not None:
                    actions = [ofp_parser.OFPActionSetQueue(queue), ofp_parser.OFPActionOutput(out_port)]

                if action == "port" and queue is None:
                    actions = [ofp_parser.OFPActionOutput(out_port)]

                if action == "group":
                    actions = [ofp_parser.OFPActionGroup(out_port)]

                match = node.dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                inst = [ofp_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
                mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, cookie=0, command=ofproto_v1_3.OFPFC_ADD, idle_timeout=20, hard_timeout=320,priority=100, instructions=inst, flags=ofproto_v1_3.OFPFF_SEND_FLOW_REM)
                node.dp.send_msg(mod)


    def send_flow_rule_drop(self, src, dst, sw):
        print "################################################################################################################"
        print "# Drop rule created on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, " #"
        print "################################################################################################################"

        for node in switch_list:
            if node.dp.id == sw:
                match = node.dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, cookie=0, command=ofproto_v1_3.OFPFC_ADD, hard_timeout=180,priority=2, instructions=[])
                node.dp.send_msg(mod)


    def send_flow_rule_delete(self, src, dst, out_port, sw, action):
        print "Deleting flow rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst
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

        #Sends a Port_Stats_Request
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)