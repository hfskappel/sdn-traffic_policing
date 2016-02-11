import networkx as nx
from ryu.lib.packet import ethernet, ipv4, vlan
policy_list = []
action_list = []

class Policy(object):

    def __init__(self):
        self.match_list = {}
        self.actions_list = {}

    def match(self, protocol=0, ip_src=0, ip_dst= 0,tos=0,
    eth_src=0, eth_dst=0, vlan=0, eth_type=0, all=False):

        self.match_list = {
            'protocol': protocol,
            'ip_src': ip_src,
            'ip_dst': ip_dst,
            'tos': tos,
            'eth_src': eth_src,
            'eth_dst': eth_dst,
            'vlan': vlan,
            'eth_type': eth_type,
            'all': all
        }

    def get_matches(self):
        return self.match_list

    def priority(self, priority=0):
        self.priority=priority

    def get_priority(self):
        return self.priority

    def action(self, idle_timeout=0, hard_timeout=0, random=False, block=False, bandwidth_requirement=0, load_balance=False):

            self.actions_list = {
            'idle_timeout': idle_timeout,
            'hard_timeout': hard_timeout,
            'random': random,
            'block': block,
            'bandwidth_requirement': bandwidth_requirement,
            'load_balance': load_balance
            }

    def get_actions(self):
        return self.actions_list



#Function that finds the associated policies
def policy_finder(packet, policy_list):
    eth = packet.get_protocols(ethernet.ethernet)[0]
    ip = packet.get_protocols(ipv4.ipv4)
    vl = packet.get_protocols(vlan.vlan)
    eth_dst = eth.dst
    eth_src = eth.src
    eth_type = 1337    #eth.type
    ip_dst = 1337       #ip.dst
    ip_src = 1337       #ip.src
    tos = 1337           #ip.tos
    proto = 1337        #ip.proto
    vlanid = 1337       #vl.vid

    for policy in policy_list:
        policy_check=[policy.get_matches()]
        for p in policy_check:
            total_matches = 0
            actual_matches = 0
            for key, value in p.iteritems():
                #Filters out unset parameters
                if value != 0 or value is True:
                    total_matches = total_matches+1
                    #print key, value
                    #print total_matches

                    if key == "protocol" and value == proto:
                        actual_matches = actual_matches+1

                    if key == "ip_dst" and value == ip_dst:
                        actual_matches = actual_matches+1

                    if key == "ip_src" and value == ip_src:
                        actual_matches = actual_matches+1

                    if key == "tos" and value == tos:
                        actual_matches = actual_matches+1

                    if key == "eth_src" and value == eth_src:
                        actual_matches = actual_matches+1

                    if key == "eth_dst" and value == eth_dst:
                        actual_matches = actual_matches+1

                    if key == "vlan" and value == vlanid:
                        actual_matches = actual_matches+1

                    if key == "eth_type" and value == eth_type:
                        actual_matches = actual_matches+1

            #Ensures that all policy criterions are matched with parameters from the packet
            if actual_matches == total_matches:
                print "Found policy!"

                #Ensures that 20 is the lowest possible priority.
                if policy.get_priority() > 20:
                    #policy.priority(20-actual_matches)
                    print "Priority: ", policy.get_priority()

                #If priority is lower than matches on the prefix, adjust priority. If higher; assume admin wants it high.
                if actual_matches < policy.get_priority():
                    #policy.priority(20-actual_matches)
                    print "Priority: ", policy.get_priority()

                #Action list represents all the policies which are to be executed
                action_list.append(policy)


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



#1. Iterate through reactive policies
#2. Add policies to a action list
#3. Sort by priority (longest prefix or fixed pri is highest)
#4. Gather network information
#4. Executes the actions according to the order and network status
#5 Create flow rules based on the parameters given
# Flow rules should be passed through group tables if there are policies at switch/proactive level

#OFP_MOD_OUT-PORT=Generate_port()
# Need to solve how we can apply and add flow rules into group rules

#
    #Execute each policy
    #Adds new policies if there are more. (IF end of policy do..
    #If mismatch; discard policies with low priority
    #Deletes actions -list
    #A policiy with highest priority needs longest prefix match as flow rules

#TODO: Get IP and VLAN properties
#TODO: Why dosent policy.priority(20-actual_match) work
#TODO: Test it!