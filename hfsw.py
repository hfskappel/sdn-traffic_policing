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
sleeptime = 5
port_status = defaultdict(lambda:defaultdict(lambda:None))
old_src_tx_bytes = defaultdict(lambda:defaultdict(lambda:None))
old_src_rx_bytes = defaultdict(lambda:defaultdict(lambda:None))
old_dst_tx_bytes = defaultdict(lambda:defaultdict(lambda:None))
old_dst_rx_bytes = defaultdict(lambda:defaultdict(lambda:None))
link_bandwidths = defaultdict(lambda:defaultdict(lambda:None))


class HFsw(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HFsw, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.net=nx.DiGraph()
        #self.path=nx.DiGraph()
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
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            dp = msg.datapath
            eth = pkt.get_protocols(ethernet.ethernet)[0]
            dpid = dp.id
            dst = eth.dst
            src = eth.src
            in_port = msg.match['in_port']
            ofp_parser = dp.ofproto_parser

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
                            self.flow_rule_crawler(path,"install")
                            running_flows.append(path)


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
            linkspeed = random.randint(2,2)
            if link_bandwidths[link.src.dpid][link.src.port_no] is None and link_bandwidths[link.dst.dpid][link.dst.port_no] is None:
                link_bandwidths[link.src.dpid][link.src.port_no] = linkspeed
                link_bandwidths[link.dst.dpid][link.dst.port_no] = linkspeed
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
            print "Error gitt"


    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):

        #Adding the port information to a global list
        global port_status
        port_status[ev.msg.datapath.id] = ev.msg.body



################ CUSTOM FUNCTIONS ######################################################################################

    #Packet handling function
    def packet_handler(self, src, dst, policy_match):

        flow = self.network_checker(src, dst, policy_match)

        if flow is not 0 and flow is not None:

            #If a accepted path is found: install it
            if isinstance(flow[0], str) is True:    #One path is found
                self.flow_rule_crawler(flow,"install")


            else:
                #If paths are found, but traffic loading is needed. flow = [path, bandwidth, value]
                #Iterates over the first path and compairs all the other paths with it
                group_rules_created = []
                for first in flow:
                    for f in range(len(first[0])-1):
                        group_rule = []
                        for second in flow:
                            port1 = 0
                            for s in range(len(second[0])-1):
                                #Checks for multiple paths, and that a group rule is not created on the node allready.
                                if first[0][f] == second[0][s] and first[0][f+1] != second[0][s+1] and first[0][f] not in group_rules_created:

                                    if port1 == 0:
                                        port1 = self.find_out_port(first[0][f], first[0][f+1])
                                        #Weight is policy requirement - link bandiwdth
                                        weight = first[2] - first[1]
                                        group_rule.append([port1, weight])

                                        #Update the link bandwidth
                                        self.update_path_bandwidth(first[0],first[2])

                                    port2 = self.find_out_port(first[0][f], second[0][s+1])
                                    if weight > second[2]:
                                        weight = weight - second[2]
                                        self.update_path_bandwidth(second[0],second[2])

                                    else:
                                        weight = second[2]
                                    group_rule.append([port2, weight])
                                    self.update_path_bandwidth([second[0]],second[2])

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


        elif flow is 0:
            #lower_policies = priority and path
            print "No possible paths. Trying to move policies!"
            possible_paths = nx.all_shortest_paths(self.net, src, dst)

            #For every policy, check if there are lower policies using the same path
            for p in policy_match:
                lower_policies = self.find_lower_policies(possible_paths, p)
                print "Lower policies in this list: ", lower_policies

                for lower in lower_policies:
                    self.policy_deleter(lower)

                    #Checks if we get a match
                    flow = self.network_checker(src, dst, policy_match)

                    if flow is not 0 and flow is not None:
                        print "Ending iteration, found a path"
                        return

            print "Flow deletion done, and still no path available!"

        else:
            print "Something went wrong!"



    #Iterates through network data and checks if network parameters is accepted by the policy.
    def network_checker(self, src, dst, policy_match):
        sorted_actions = []
        flow_rule_policies = []


        for policy in policy_match:
            #Fetches the sorted policies
            actions = [policy.get_actions()]
            for action in actions:
                for key, value in action.iteritems():
                    if value != 0 or value is True:
                        if key == "idle_timeout":
                            print "Policy_action", key, value
                            flow_rule_policies.extend((key, value))

                        if key == "hard_timeout":
                            print "Policy_action", key, value
                            flow_rule_policies.extend((key, value))

                        if key == "block":
                            print "Policy_action", key, value
                            flow_rule_policies.extend((key, value))

                        if key == "random_routing":
                            print "Policy_action", key, value

                        if key == "load_balance":
                            print "Policy_action", key, value
                            sorted_actions.extend((key, value, policy.get_priority()))

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
                                print "Found a path which matches requirements"

                                #Saves the policy and the path to the running policy list
                                running_policies.append([possible_paths, policy])

                                #Skip traffic loading,due to a path is found
                                traffic_load_bol = False

                                #Update link-bandwidth
                                self.update_path_bandwidth(possible_paths, value)

                                #Install flow rules
                                return possible_paths

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
                                    traffic_load_paths.append([p, link_bandwidth, value])

                                    for nodez in range(len(p)-1):
                                        for chosen in limited_links:
                                            if p[nodez] == chosen[1].src.dpid and p[nodez+1] == chosen[1].dst.dpid:
                                                chosen[0] = chosen[0]-link_bandwidth
                                    traffic_load_limit = traffic_load_limit - link_bandwidth

                                    if traffic_load_limit <= 0:
                                        for p in traffic_load_paths:
                                            print "Bandwidth limit achieved, using ", p

                                            #Saves the policies to a list with path
                                            running_policies.append([p, policy])

                                        #Returns the list of the possible paths!
                                        return traffic_load_paths

                                if value > 0:
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
        print "Deleting flow", lower_policy
        action = lower_policy[1][1].get_actions()
        print "ACTION", action
        for key, value in action.iteritems():
            if value != 0 or value is True:
                if key == "bandwidth_requirement":
                    print "Found a weaker policy with requirement:", key, value, "on path: ", lower_policy[1][0]

                    #Deletes the whole path
                    self.flow_rule_crawler(lower_policy[1][0], "delete")

                    #Removes the policy from the running list
                    for r in range(len(running_policies)):
                        if running_policies[r][0] == lower_policy[1][0] and running_policies[r][0] == lower_policy[1][1]:
                            running_policies.pop(r)

                    #Update the link bandwidths:
                    for node in range(len(lower_policy[1][0])-1):

                        print "NODE", link_bandwidths[lower_policy[1][0][node]]

                        if lower_policy[1][0][node] != lower_policy[1][0][0] and lower_policy[1][0][node+1] != lower_policy[1][0][-1]:

                            port = self.find_out_port(lower_policy[1][0][node], lower_policy[1][0][node+1])
                            link_bandwidths[lower_policy[1][0][node]][port] = link_bandwidths[lower_policy[1][0][node]][port] + value
                            print "LINK BW", link_bandwidths[lower_policy[1][0][node]][port]

                            #TODO: ENDED HERE! THE FUNCTION ABOVE IS NOT WORKING PROPERLY
                            #
                            #

                    else:
                        print "Hello there!"

        else:
          print "No possible path found in network. Change your bandwidth requirements, or delete other policies!"



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
                    lower_policies.append([p[1].priority, p])


        #Removing the policy from lower_policies if there excists a higher policy for the same flow.
        for l in lower_policies:
            for p in running_policies:
                if p[0][0] == l[1][0] and p[0][-1] == l[1][-1] and p[1].priority < policy.priority:
                    lower_policies.pop(l)
        return lower_policies


    #Checks a the path for bandwidth and compair it with policy requirements
    def check_path_bandwidth(self, possible_paths, limit):
        bad = []
        #Path crawler
        for p in possible_paths:
            for node in range(len(p)):
                for l in links_list:
                    try:
                        if node+2 < (len(p)-1) and l.src.dpid == p[node+2] and l.dst.dpid == p[node+1]:

                            if link_bandwidths[l.src.dpid][l.src.port_no] < limit or link_bandwidths[l.dst.dpid][l.dst.port_no] < limit:
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
                        print "Link bandwidths updated on link: ", link, ": ", link_bandwidths[link.src.dpid][link.src.port_no], " and link ", link, ": ", link_bandwidths[link.dst.dpid][link.dst.port_no]
                except IndexError:
                    print "Iterating function out of range"




    #Iterate through flow tables based on path and action. Action is install or delete flow rules
    def flow_rule_crawler(self, path, action):

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
        while True:
            for node in switch_list:
                self.send_stats_request(node.dp)
            #for link in links_list:
                #self.check_link(link, True, True)
            hub.sleep(sleeptime)


    #Iterating function to inspect a given link for packet loss and transmitting traffic
    def check_link(self, link, measure_loss, measure_bandwidth):
        global old_dst_tx_bytes, old_src_tx_bytes, old_src_tx_bytes, old_src_tx_bytes
        src_tx_bytes = 0
        dst_tx_bytes = 0
        src_rx_bytes = 0
        dst_rx_bytes = 0

        for stat in port_status[link.src.dpid]:
            if link.src.port_no == stat.port_no:
                src_rx_bytes = stat.rx_bytes
                src_tx_bytes = stat.tx_bytes

        for stat in port_status[link.dst.dpid]:
            if link.dst.port_no == stat.port_no:
                dst_rx_bytes = stat.rx_bytes
                dst_tx_bytes = stat.tx_bytes

        if old_src_tx_bytes[link.src.dpid][link.src.port_no] is None and old_dst_tx_bytes[link.dst.dpid][link.dst.port_no] \
                is None and old_src_rx_bytes[link.src.dpid][link.src.port_no] is None and old_dst_rx_bytes[link.dst.dpid][link.dst.port_no] is None:
            old_src_rx_bytes[link.src.dpid][link.src.port_no] = src_rx_bytes
            old_src_tx_bytes[link.src.dpid][link.src.port_no] = src_tx_bytes
            old_dst_rx_bytes[link.dst.dpid][link.dst.port_no] = dst_rx_bytes
            old_dst_tx_bytes[link.dst.dpid][link.dst.port_no] = dst_tx_bytes

        pathloss = abs(((old_src_tx_bytes[link.src.dpid][link.src.port_no]+old_src_rx_bytes[link.src.dpid][link.src.port_no]) - \
                   (old_dst_tx_bytes[link.dst.dpid][link.dst.port_no]+old_dst_rx_bytes[link.dst.dpid][link.dst.port_no])) - \
                   ((src_rx_bytes+src_tx_bytes)-(dst_rx_bytes+dst_tx_bytes)))

        old_traffic = (old_src_tx_bytes[link.src.dpid][link.src.port_no]+old_src_rx_bytes[link.src.dpid][link.src.port_no]+ \
                       old_dst_tx_bytes[link.dst.dpid][link.dst.port_no] + old_dst_rx_bytes[link.dst.dpid][link.dst.port_no])
        traffic = abs((8*float(old_traffic - (src_tx_bytes+src_rx_bytes+dst_tx_bytes+dst_rx_bytes))/4/1000000)/sleeptime)

        old_src_tx_bytes[link.src.dpid][link.src.port_no] = src_tx_bytes
        old_src_rx_bytes[link.src.dpid][link.src.port_no] = src_rx_bytes
        old_dst_tx_bytes[link.dst.dpid][link.dst.port_no] = dst_tx_bytes
        old_dst_rx_bytes[link.dst.dpid][link.dst.port_no] = dst_rx_bytes


        if measure_bandwidth and measure_loss:
            #print traffic, " mbit/s and with packet loss of ", pathloss, "the last ", sleeptime, "seconds at link:", link.src.dpid, "-", link.dst.dpid
            return pathloss, traffic

        elif measure_loss:
            #print pathloss, "bytes lost the last ", sleeptime, "  seconds at link ", link.src.dpid, " - ", link.dst.dpid
            return pathloss

        elif measure_bandwidth:
            #print traffic, " mbit/s at link:", link.src.dpid, " - ", link.dst.dpid
            return traffic



################ OPENFLOW MESSAGE FUNCTIONS ############################################################################


    #Function to send a flow rule to a switch
    def send_flow_rule_install(self,src, dst, out_port, sw, action):
        print "Installing flow rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, ". Action: out_port =  ", out_port
        for node in switch_list:
            if node.dp.id == sw:
                ofp_parser = node.dp.ofproto_parser
                if action == "port":
                    actions = [ofp_parser.OFPActionOutput(port=out_port)]
                if action == "group":
                    actions = [ofp_parser.OFPActionGroup(out_port)]

                match = node.dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                inst = [ofp_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]
                mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, cookie=0, command=ofproto_v1_3.OFPFC_ADD, idle_timeout=0, hard_timeout=0,priority=2, instructions=inst)
                node.dp.send_msg(mod)



    def send_flow_rule_delete(self,src, dst, out_port, sw, action):
        print "Deleting flow rule on :", sw, "Match conditions: eth_src =  ", src, " and eth_dst = ", dst, ". Action: out_port/group =  ", out_port
        for node in switch_list:

            if node.dp.id == sw:
                match = node.dp.ofproto_parser.OFPMatch(eth_src=src, eth_dst=dst)
                if action == "port":
                    mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, out_port=out_port)
                if action == "group":
                    mod = node.dp.ofproto_parser.OFPFlowMod(datapath=node.dp, match=match, out_group=out_port)

                node.dp.send_msg(mod)

                #inst = [ofp_parser.OFPInstructionActions(ofproto_v1_3.OFPIT_APPLY_ACTIONS, actions)]









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

    #TODO: Ports/weigth dosent seem to work properly (pw[0] and pw[1])



    #Function to send a stats requests to a switch
    def send_stats_request(self,datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #Sends a Flow Stats Request
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        #Sends a Port_Stats_Request
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

        #Sends a Group_Stats_Request
        req = parser.OFPGroupStatsRequest(datapath,0, ofproto.OFPG_ALL,None)
        datapath.send_msg(req)


#TODO: Handle policy crawler. Delete flows withouth any policies first?
#TODO: Handle flows with multiple policies
#TODO: Bandwidth decrementing function is not very stable Bandwidth limit achieved, using  [['e2:ac:ce:83:82:8b', 2, 4, 3, '06:77:b1:7a:9e:0c'], 2, 1]
