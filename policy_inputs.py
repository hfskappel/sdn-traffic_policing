#Module which is used to load and execute the policies.
#Simulates ACL which is implemented by the administrator.

######################################################
# Match = Match condition(s) for the policy.
# Priority = Policy priority in range 1-20, where 1 is the highest priority

# Action: What action(s) the policy should execute
##########################################################
# bandwidth_requirement: The flows minimum bandwidth requirement
# bandwidth_requirement_strict : bandwidth_requirement_strict
# allow_load_balance : Allows the flow to be traffic loaded in order to achieve bandwidth limits
# block : Blocks the flow
# traffic_class : What traffic class the flow should use, based on the links bandwidths. 1-3 where 1 is the best class
# random_routing: Applies random routing of the flow
###########################################################





import policy_manager

def generate_policies():

    policy001 = policy_manager.Policy()
    policy001.match(ip_src="10.10.10.106")
    policy001.action(bandwidth_requirement=2, random_routing=True)
    policy001.priority(2)

    policy002 = policy_manager.Policy()
    policy002.match(ip_src="10.10.10.104")
    policy002.action(bandwidth_requirement=2, traffic_class=1, random_routing=True)
    policy002.priority(3)

    policy003 = policy_manager.Policy()
    policy003.match(ip_src="10.10.10.105")
    policy003.action(bandwidth_requirement=3)
    policy003.priority(2)

    policy004 = policy_manager.Policy()
    policy004.match(ip_src="10.10.10.199")
    policy004.action(bandwidth_requirement=2)
    policy004.priority(1)


    policy_list = [policy001, policy002, policy003, policy004]
    return policy_list


generate_policies()
