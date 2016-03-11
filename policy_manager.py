import networkx as nx
from ryu.lib.packet import ethernet, ipv4, vlan, ipv6, arp
policy_list = []
action_list = []

class Policy(object):

    def __init__(self):
        self.match_list = {}
        self.actions_list = {}

    def match(self, protocol=0, ip_src=0, ip_dst= 0,
    eth_src=0, eth_dst=0, eth_type=0, all=False):

        self.match_list = {
            'protocol': protocol,
            'ip_src': ip_src,
            'ip_dst': ip_dst,
            'eth_src': eth_src,
            'eth_dst': eth_dst,
            'eth_type': eth_type,
            'all': all
        }

    def get_matches(self):
        return self.match_list

    def priority(self, priority=0):
        self.priority=priority

    def get_priority(self):
        return self.priority

    def action(self, bandwidth_requirement=0, bandwidth_requirement_strict= False, allow_load_balance=False, random_routing=False, block=False, traffic_class = 0):

            self.actions_list = {
            'bandwidth_requirement': bandwidth_requirement,
            'bandwidth_requirement_strict': bandwidth_requirement_strict,
            'allow_load_balance': allow_load_balance,
            'random_routing': random_routing,
            'block': block,
            'traffic_class' : traffic_class
            }

    def get_actions(self):
        return self.actions_list


    def print_policy(self):

        printlist = ["Condition(s)"]

        for key, value in self.match_list.iteritems():

            if value != 0 or value is True:
                printlist.extend((key,value))

        printlist.append("Action(s): ")
        for key, value in self.actions_list.iteritems():
            if value != 0 or value is True:
                printlist.extend((key,value))

        return printlist



#Function that finds the associated policies
def policy_finder(packet, policy_list):
    eth = packet.get_protocols(ethernet.ethernet)[0]
    if packet.get_protocol(arp.arp):
        ip = packet.get_protocols(arp.arp)[0]
        ip_dst = ip.dst_ip
        ip_src = ip.src_ip
    elif packet.get_protocol(ipv4.ipv4):
        ip = packet.get_protocols(ipv4.ipv4)[0]
        ip_dst = ip.dst
        ip_src = ip.src
    eth_dst = eth.dst
    eth_src = eth.src
    eth_type = eth.ethertype
    proto = ip.proto
    del action_list[:]


    for policy in policy_list:
        policy_check=[policy.get_matches()]
        for p in policy_check:
            total_matches = 0
            actual_matches = 0
            for key, value in p.iteritems():
                #Filters out unset parameters
                if value != 0 or value is True:
                    total_matches = total_matches+1

                    if key == "protocol" and value == proto:
                        actual_matches = actual_matches+1

                    if key == "ip_dst" and value == ip_dst:
                        actual_matches = actual_matches+1

                    if key == "ip_src" and value == ip_src:
                        actual_matches = actual_matches+1

                    if key == "eth_src" and value == eth_src:
                        actual_matches = actual_matches+1

                    if key == "eth_dst" and value == eth_dst:
                        actual_matches = actual_matches+1

                    if key == "eth_type" and value == eth_type:
                        actual_matches = actual_matches+1

            #Ensures that all policy criterions are matched with parameters from the packet
            if actual_matches == total_matches:

                #Ensures that 20 is the lowest possible priority.
                if policy.get_priority() > 20:
                    policy.priority = 20

                #If no priority is specified, use longest prefix to determine the priority.
                if policy.get_priority() == 0 or isinstance(policy.get_priority(), int) is False:
                    policy.priority = 10 - actual_matches

                #Action list represents all the policies which are to be executed
                action_list.append(policy)
                print "Found policy: ", policy.print_policy(), " with priority ", policy.get_priority()

    #Sorts the list based on the priority. Highest priority first!
    action_list.sort(key=lambda x: x.priority, reverse=False)

    #Returns a list of matched and sorted policies
    return action_list




#Function that checks the policies against the topology and excisting rules







#TODO: Create Network_checker() and Running_policy_checker()
#TODO: Pass the returned list from policy_finder to network_checker
#