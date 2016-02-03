#One class for group policies due to every policiy needs it? OR just a general policy?
#What about switch spesific policies?
#Longest prefix = highest priority
#Each policy has a priority. If its 0 (lowest), then the pri is based on the match criterions (longest prefix)
import networkx as nx
policy_list = []
action_list = []

class Policy():

    # In a user-interface, this will be listed
    def match(self, protocol= 0, ip_src = 0, ip_dst= 0, mask = 0, tos = 0,
    eth_src = 0, eth_dst=0, eth_type=0, vlan=0, all = False):

        self.protocol = protocol
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.mask = mask
        self.tos = tos
        self.eth_src = eth_src
        self.eth_dst = eth_dst
        self.eth_type = eth_type
        self.vlan = vlan
        self.all = all  #General/wildcard policies

    def priority(self, priority=0):
        self.priority=priority

    def get_priority(self):
        return self.priority

    def action(self, limitation=False, nodes=False, resource_allocation=False, random=False, block=False):
        self.limitation = limitation
        self.nodes = nodes
        self.resource_allocation = resource_allocation
        self.random = random
        self.block = block
        #Some policies are pushed down to router level, but can by applied by linking the route to the group table?

    def get_action(self):
        #Return actions which is true
        if self.limitation != 0 or self.limitation:
            return self.limitation

        if self.nodes != 0 or self.nodes:
            return self.nodes

        if self.resource_allocation != 0 or self.resource_allocation:
            return self.resource_allocation

        if self.random != 0 or self.random:
            return self.random

        if self.block != 0 or self.block:
            return self.block


def policy_sorter():#ev):
    ev = 1337
    #Dekomponere ev to get properties from the packet

    for policy in policy_list:
        priority = 0

        #Getting all general policies.
        if policy.all:
            action_list.append(policy)

        if policy.protocol==ev:
            priority = priority+1

        if policy.ip_src == ev:
            priority = priority+1

        if policy.ip_dst ==ev:
            priority = priority+1

        if policy.mask == ev:
            priority = priority+1

        if policy.tos ==ev:
            priority = priority+1

        if policy.eth_src == ev:
            priority = priority+1

        if policy.eth_dst == ev:
            priority = priority+1

        if policy.eth_type == ev:
            priority = priority+1

        if policy.vlan == ev:
            priority = priority+1

        #If priority is bigger than 0, then a match is found. Checks the policies priority
        if priority != 0:
            if priority > policy.get_priority():
                policy.priority(priority)
            action_list.append(policy)

    #Sorts the list based on the priority. Highest priority first!
    action_list.sort(key=lambda x: x.priority, reverse=True)

    for action in action_list:
        #INSERT SORT FUNCTION!
        print action.get_action()



def policy_enforce(action_list):#packetIN):
    #Function is used to execute the actions in the policies
    for policy in action_list:
        if policy.get_action == "Random":
            print "OFP_Hard-timeout = 180"
            print "Generate path"

        if policy.get_action == "Block":
            print "OFP_OUT-port = None"

        #Idle timeout
        #Hard timeout
        #Priority
        #Instructions: GoToTable og WriteActions( Output, Push/POP VLAN, SetQueue), Apply actions, Clear actions.
        #GoToTable is used for more processing

    #OSV..
    # Need to solve how we can apply and add flow rules into group rules




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
                print "No path found"
                return False



def network_capasity(path, capasity):
    #Insert function to get link status from network
    return True








    #Execute each policy
    #Adds new policies if there are more. (IF end of policy do..
    #If mismatch; discard policies with low priority
    #Deletes actions -list
    #A policiy with highest priority needs longest prefix match as flow rules




pelle = Policy()
pelle.match(ip_dst=1337)
pelle.action(nodes=2)
pelle.priority(2)
policy_list.append(pelle)

pello = Policy()
pello.match(ip_src=1337)
pello.action(nodes=555)
pello.priority(100)
policy_list.append(pello)

policy_sorter()
policy_enforce(action_list)

#1. Iterate through reactive policies
#2. Add policies to a action list
#3. Sort by priority (longest prefix or fixed pri is highest)
#4. Gather network information
#4. Executes the actions according to the order and network status
#5 Create flow rules based on the parameters given
# Flow rules should be passed through group tables if there are policies at switch/proactive level

#OFP_MOD_OUT-PORT=Generate_port()