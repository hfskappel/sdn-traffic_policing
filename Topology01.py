#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import CPULimitedHost, Host, Node
from mininet.node import OVSKernelSwitch, UserSwitch
from mininet.node import IVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink, Intf
from subprocess import call

def myNetwork():

    net = Mininet( topo=None,
                   build=False,
                   ipBase='10.0.0.0/8')

    info( '*** Adding controller\n' )
    c0=net.addController(name='c0',
                      controller=RemoteController,
                      ip='129.241.208.193',
                      protocol='tcp',
                      port=6633)

    info( '*** Add switches\n')
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch, dpid='3')
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch, dpid='2')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch, dpid='1')
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch, dpid='4')

    info( '*** Add hosts\n')
    h4 = net.addHost('h4', cls=Host, ip='10.10.10.104', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.10.10.102', defaultRoute=None)
    h1 = net.addHost('h1', cls=Host, ip='10.10.10.101', defaultRoute=None)
    h5 = net.addHost('h5', cls=Host, ip='10.10.10.105', defaultRoute=None)

    info( '*** Add links\n')
    net.addLink(h1, s3)
    net.addLink(s3, s1)
    net.addLink(s2, s4)
    net.addLink(s2, h2)
    net.addLink(s4, s3)
    s1s2 = {'bw':5}
    net.addLink(s1, s2, cls=TCLink , **s1s2)
    net.addLink(s2, h4)
    net.addLink(s3, h5)

    info( '*** Starting network\n')
    net.build()
    info( '*** Starting controllers\n')
    for controller in net.controllers:
        controller.start()

    info( '*** Starting switches\n')
    net.get('s3').start([c0])
    net.get('s2').start([c0])
    net.get('s1').start([c0])
    net.get('s4').start([c0])

    info( '*** Post configure switches and hosts\n')
    s3.cmd('ifconfig s3 10.10.10.3')
    s2.cmd('ifconfig s2 10.10.10.2')
    s1.cmd('ifconfig s1 10.10.10.1')
    s4.cmd('ifconfig s4 10.10.10.3')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

