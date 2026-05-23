# -*- coding: utf-8 -*-
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def ping(host, dst, count=1, timeout=1):
    return host.cmd('ping -c %s -W %s %s' % (count, timeout, dst))

def send_arp(node, count=1):
    node.cmd('arping -c %s -A -I %s-eth0 %s' % (count, node.name, node.IP()))

def send_dhcp(node):
    print('Sending DHCP request dhclient -v %s-eth0 '% (node.name))
    node.cmd('dhclient -v %s-eth0' % (node.name))


def do_arp_all(net):
    for h in net.hosts:
        send_arp(h)

class TriangleTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s1)


def run_tests(net):
    import time
    h1, h2, h3 = net.get('h1'), net.get('h2'), net.get('h3')

    print("\n========== Waiting for topology discovery ==========")
    time.sleep(3)
    do_arp_all(net)
    time.sleep(10)

    print("\n========== Test 1: basic connectivity ==========")
    print(ping(h1, h2.IP()))
    print(ping(h1, h3.IP()))
    print(ping(h2, h3.IP()))

    print("\n========== Test 2: dump flows ==========")
    for s in net.switches:
        print(f"\n--- {s.name} ---")
        print(s.cmd('ovs-ofctl dump-flows %s --no-stats' % s.name))

    print("\n========== Test 3: bring down s1-s2 ==========")
    net.configLinkStatus('s1', 's2', 'down')
    time.sleep(3)
    print("h1 -> h2:", ping(h1, h2.IP()))
    print("h1 -> h3:", ping(h1, h3.IP()))

    print("\n========== Test 4: dump flows after link down ==========")
    for s in net.switches:
        print(f"\n--- {s.name} ---")
        print(s.cmd('ovs-ofctl dump-flows %s --no-stats' % s.name))

    print("\n========== Test 5: restore link ==========")
    net.configLinkStatus('s1', 's2', 'up')
    time.sleep(3)
    print("h1 -> h2:", ping(h1, h2.IP()))

    print("\n========== Test 6: double link failure ==========")
    net.configLinkStatus('s1', 's2', 'down')
    net.configLinkStatus('s2', 's3', 'down')
    time.sleep(3)
    print("h1 -> h2 (should fail):", ping(h1, h2.IP()))
    print("h1 -> h3 (should pass):", ping(h1, h3.IP()))

    # restore
    net.configLinkStatus('s1', 's2', 'up')
    net.configLinkStatus('s2', 's3', 'up')
    time.sleep(3)

    print("\n========== All tests complete ==========")

def run_mininet():
    import time
    topo = TriangleTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)
    for h in net.hosts:
        disable_ipv6(h)
    for h in net.switches:
        disable_ipv6(h)
    
    net.start()
    time.sleep(1)
    do_arp_all(net)

    # automatic tests
    run_tests(net)

    # then enter CLI for manual tests
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()