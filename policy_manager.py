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

    def action(self, idle_timeout=0, hard_timeout=0, random_routing=False, block=False, bandwidth_requirement=0, load_balance=False):

            self.actions_list = {
            'idle_timeout': idle_timeout,
            'hard_timeout': hard_timeout,
            'random_routing': random_routing,
            'block': block,
            'bandwidth_requirement': bandwidth_requirement,
            'load_balance': load_balance
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
    ip = packet.get_protocols(arp.arp)[0]
    eth_dst = eth.dst
    eth_src = eth.src
    eth_type = eth.ethertype
    ip_dst = ip.dst_ip
    ip_src = ip.src_ip
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
def policy_checker(action_list):#packetIN):
    capasity = 0
    random = 0

    #Flow-based priorities
    for policy in action_list:
        if policy.block:print "blocked"
            #OFP_action = Drop
        if policy.hard_timeout != 0:print "hard timeout"
            #OFP_hard_timeout == policy.hard_timeout
        if policy.idle_timeout != 0:print "idle timeout"
            #OFP_hard_timeout == policy.idle_timeout
        if policy.vlan != 0: print "vlan"
            #OFP_vlan = policy.vlan


    #Group-based priorities
        #Where all is true, perhaps?



    #Routing-based priorities

        if capasity == 0:
            capasity = policy.bandwidth

        if random == False:
            random =policy.random

    #Generate path
    path_calculation(random,capasity)




def path_calculation(random=False, capasity = 0):
    if random:
        #Find the shortest path to the destination
        path = nx.shortest_path

    else:
        #Pick a random path to the destination
        path = random.sample(nx.all_shortest_paths,1)


    if capasity == 0:
        #If no capasity needs, choose the path
        return path

    if capasity != 0:
        #If the flow has capasity needs; check the path for its needs
        if network_capasity(path, capasity):
            return path
        else:
            #Iterate through paths until a suitable path is found
            path = nx.all_shortest_paths()
            for p in path:
                if network_capasity(path, capasity):
                    return path
            else:
                #If no path with capabilities found, return false!
                print "No path found which matches capacity need: ", capasity
                return False

def network_capasity(path, capasity):
    #Insert function to get link status from network
    return True




#TODO: Create Network_checker() and Running_policy_checker()
#TODO: Pass the returned list from policy_finder to network_checker
#