# SDN traffic policing controller
SDN controller used for traffic policing.

# Software needed
- Mininet VM
- Open vSwitch 2.5 (https://gist.github.com/pichuang/9b362f802f40913c4b8f)
- Ryu

# Ryu
- Run application by issuing ./ruy-manager /path-to-controller-script/hfsw.py
- Stop it with control+c
- Clean flow rules between stopping and starting the controller

# Mininet
- Mininet topology used is Topology01.py and Topology01 .mn Make sure to edit the IP-address to your computer where the Ryu-controller is running
- Start (prefered) sudo ./mininet/examples/miniedit.py and open Topology01.mn from GUI
- Start (alternative) sudo mn --custom Topology01.py
- Commands:
  - h1 ping h2 - Ping from h1 to h2
  - sudo ovs-ofctl -O OpenFlow13 del-flows s1 - Delete flow tables on switch 1
  - sudo ovs-ofctl -O OpenFlow13 dump-flows s1 - Dump flow rules on switch 1
  - sudo ovs-ofctl -O OpenFlow13 del-groups s1 - Delete group tables on switch 1
  - sudo ovs-ofctl -O OpenFlow13 dump-groups s1 - Dump group rules on switch 1
