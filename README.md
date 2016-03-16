# SDN traffic policing controller
SDN controller used for traffic policing in changing network conditions.

# Software needed
- Mininet VM
- Open vSwitch 2.5 (https://github.com/mininet/mininet/wiki/Installing-new-version-of-Open-vSwitch)
- Ryu controller

# Ryu
- Run application by issuing ./ryu/bin/ryu-manager /path-to-controller-script/hfsw.py
- Stop it with control+c
- Clean flow rules on all switches between stopping and starting the controller. See commands below

# Mininet
- Mininet topology used is Topology01.py and Topology01 .mn Make sure to edit the IP-address to your computer where the Ryu-controller is running
- Start (prefered) sudo ./mininet/examples/miniedit.py and open Topology01.mn from GUI
  - When using ssh to Mininet VM, ensure that the " -X "property is used. Ex: ssh mininet@10.10.10.10 -X  
- Start (alternative) sudo mn --custom Topology01.py
- Commands:
  - h1 ping h2 - Ping from h1 to h2
  - sudo ovs-ofctl -O OpenFlow13 del-flows s1 - Delete flow tables on switch 1
  - sudo ovs-ofctl -O OpenFlow13 dump-flows s1 - Dump flow rules on switch 1
  - sudo ovs-ofctl -O OpenFlow13 del-groups s1 - Delete group tables on switch 1
  - sudo ovs-ofctl -O OpenFlow13 dump-groups s1 - Dump group rules on switch 1
  - ip -s -s neigh flush all - Flush a hosts arp-table

# The controller
- The controller is still under development, so expect bugs.
- Policies can be defined in policy_inputs.py
- To this date, only bandwidth requirements can be used as a policy requirement


# Troubleshooting
- If "[Errno 98] Address already in use" when starting Ryu: use sudo lsof -i:6633 to get pid and kill with sudo kill -9 "pid"
- If the controller don't get the packets it might be because of already installed flow rules: clean them with the del-flows command
- If "Waiting for the host's local ARP cache to reset" does not disapear: clear the hosts local arp table
