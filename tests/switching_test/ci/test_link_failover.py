#!/usr/bin/env python
"""
CI test: Link failover - when a link goes down, the controller
recomputes paths and restores connectivity via alternate routes.
"""

import sys
import time
import re
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


class RedundantTopo(Topo):
    """
    Topology with redundant paths:

        s1 ---- s2
        |  \    |
        |   \   |
        s3 ---- s4

    h1 on s1, h2 on s4.
    Paths: s1->s2->s4, s1->s3->s4, s1->s4 (direct)
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')

        self.addLink(h1, s1)
        self.addLink(s4, h2)
        self.addLink(s1, s2)
        self.addLink(s2, s4)
        self.addLink(s1, s3)
        self.addLink(s3, s4)
        self.addLink(s1, s4)  # Direct link


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host):
    intf = host.defaultIntf().name
    host.cmd("arping -c 1 -A -I %s %s" % (intf, host.IP()))


def check_ping(src, dst, retries=4):
    for attempt in range(retries):
        result = src.cmd("ping -c 2 -W 2 %s" % dst.IP())
        if " 0% packet loss" in result or re.search(r'[12] received', result):
            return True
        time.sleep(2)
    return False


def run_test():
    passed = True
    net = Mininet(topo=RedundantTopo(), autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(4)

    for h in net.hosts:
        send_garp(h)
    time.sleep(2)

    h1, h2 = net.get('h1', 'h2')
    s1, s4 = net.get('s1', 's4')

    # Test 1: Initial connectivity
    if check_ping(h1, h2):
        print("PASS: initial connectivity h1 -> h2")
    else:
        print("FAIL: initial connectivity h1 -> h2")
        passed = False
        net.stop()
        return False  # No point continuing

    # Test 2: Take down the direct s1-s4 link, verify connectivity via alternate path
    print("--- Taking down s1-s4 direct link ---")
    # Find the link between s1 and s4
    link_to_remove = None
    for link in net.links:
        intf1 = link.intf1
        intf2 = link.intf2
        node1 = intf1.node.name
        node2 = intf2.node.name
        if (node1 == 's1' and node2 == 's4') or (node1 == 's4' and node2 == 's1'):
            link_to_remove = link
            break

    if link_to_remove:
        # Bring interfaces down to simulate link failure
        link_to_remove.intf1.config(up=False)
        link_to_remove.intf2.config(up=False)
        time.sleep(5)  # Wait for controller to detect and recompute

        # Re-send garp after topology change
        for h in net.hosts:
            send_garp(h)
        time.sleep(2)

        if check_ping(h1, h2):
            print("PASS: connectivity maintained after s1-s4 link down (via alternate path)")
        else:
            print("FAIL: connectivity lost after s1-s4 link down")
            passed = False

        # Test 3: Bring the link back up
        print("--- Bringing s1-s4 link back up ---")
        link_to_remove.intf1.config(up=True)
        link_to_remove.intf2.config(up=True)
        time.sleep(5)

        for h in net.hosts:
            send_garp(h)
        time.sleep(2)

        if check_ping(h1, h2):
            print("PASS: connectivity restored after s1-s4 link restored")
        else:
            print("FAIL: connectivity not restored after s1-s4 link restored")
            passed = False
    else:
        print("FAIL: could not find s1-s4 link to test failover")
        passed = False

    # Test 4: Take down multiple links, still reachable via remaining path
    print("--- Taking down s1-s2 link (leaving s1-s3-s4 and s1-s4) ---")
    link_s1_s2 = None
    for link in net.links:
        node1 = link.intf1.node.name
        node2 = link.intf2.node.name
        if (node1 == 's1' and node2 == 's2') or (node1 == 's2' and node2 == 's1'):
            link_s1_s2 = link
            break

    if link_s1_s2:
        link_s1_s2.intf1.config(up=False)
        link_s1_s2.intf2.config(up=False)
        time.sleep(5)

        for h in net.hosts:
            send_garp(h)
        time.sleep(2)

        if check_ping(h1, h2):
            print("PASS: connectivity maintained after s1-s2 link also down")
        else:
            print("FAIL: connectivity lost after s1-s2 link down")
            passed = False
    else:
        print("FAIL: could not find s1-s2 link")
        passed = False

    net.stop()
    return passed


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)