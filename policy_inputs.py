#Module which is used to load and execute the policies.
#Simulates ACL which is implemented by the administrator.
#Priority in the range 1 to 20, where 1 is the highest

import policy_manager

#policy_list = [9]
def generate_policies():
    policy001 = policy_manager.Policy()
    policy001.match(ip_src="10.10.10.103")
    policy001.action(bandwidth_requirement=3)
    policy001.priority(8)

    policy002 = policy_manager.Policy()
    policy002.match(ip_src="10.10.10.101")
    policy002.action(load_balance=True)
    policy002.priority(4)

    policy003 = policy_manager.Policy()
    policy003.match(ip_src="10.10.10.101")
    policy003.action(bandwidth_requirement=3)
    policy003.priority(2)

    policy004 = policy_manager.Policy()
    policy004.match(ip_src="10.10.10.102")
    policy004.action(bandwidth_requirement=2)

    policy005 = policy_manager.Policy()
    policy005.match(ip_src="10.10.10.104")
    policy005.action(bandwidth_requirement=3)
    policy005.priority(10)


    policy_list = [policy001, policy002, policy003, policy004, policy005]
    return policy_list


generate_policies()
