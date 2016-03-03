#Module which is used to load and execute the policies.
#Simulates ACL which is implemented by the administrator.
#Priority in the range 1 to 20, where 1 is the highest

import policy_manager

#policy_list = [9]
def generate_policies():
    policy001 = policy_manager.Policy()
    policy001.match(ip_src="10.10.10.102")
    policy001.action(bandwidth_requirement=3)
    policy001.priority(2)

    policy002 = policy_manager.Policy()
    policy002.match(ip_src="10.10.10.104")
    policy002.action(bandwidth_requirement=2)
    policy002.priority(16)

    policy003 = policy_manager.Policy()
    policy003.match(ip_src="10.10.10.199")
    policy003.action(bandwidth_requirement=3)
    policy003.priority(2)

    policy004 = policy_manager.Policy()
    policy004.match(ip_src="10.10.10.199")
    policy004.action(bandwidth_requirement=2)
    policy004.priority(1)


    policy_list = [policy001, policy002, policy003, policy004]
    return policy_list


generate_policies()
