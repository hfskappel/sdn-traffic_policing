#Module which is used to load and execute the policies.
#Simulates ACL which is implemented by the administrator.
#Priority in the range 1 to 20, where 1 is the highest

import policy_manager

#policy_list = [9]
def generate_policies():
    policy001 = policy_manager.Policy()
    policy001.match(eth_src="aa:b2:44:34:74:24")
    policy001.action(load_balance=True)
    policy001.priority(2)
    #policy_list.append(policy001)

    policy002 = policy_manager.Policy()
    policy002.match(eth_dst="aa:b2:44:34:74:24")
    policy002.action(random_routing=True)
    policy002.priority(20)
    #policy_list.append(policy002)

    policy003 = policy_manager.Policy()
    policy003.match(ip_src="10.10.10.101")
    policy003.action(random_routing=True)
    policy003.priority(0)
    #policy_list.append(policy003)

    policy004 = policy_manager.Policy()
    policy004.match(ip_src="10.10.10.102")
    policy004.action(random_routing=True)
    #policy004.priority(100)
    #policy_list.append(policy004)

    policy_list = [policy001, policy002, policy003, policy004]
    return policy_list


generate_policies()
