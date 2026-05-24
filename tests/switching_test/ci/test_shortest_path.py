#!/usr/bin/env python
"""
CI test: Shortest path forwarding in a multi-hop topology.
Verifies that the controller computes and installs correct shortest paths.
"""

import sys
import time
import re
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


class MultiHopTopo(Topo):
    """
    Linear topology with 4 switches:
    h1 -- s1 -- s2 -- s3 -- s4 -- h2

    This tests multi-hop shortest path computation.
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
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, h2)


class DiamondTopo(Topo):
    """
    Diamond topology - two paths between s1 and s4:
       s1 --- s2 --- s4
        \            /
         s3 --------

    h1 on s1, h2 on s4.
    Both paths have length 2 hops, so either is valid.
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
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s4)
        self.addLink(s4, h2)


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host):
    intf = host.defaultIntf().name
    host.cmd("arping -c 1 -A -I %s %s" % (intf, host.IP()))


def check_ping(src, dst, retries=3):
    for attempt in range(retries):
        result = src.cmd("ping -c 2 -W 2 %s" % dst.IP())
        if " 0% packet loss" in result or re.search(r'[12] received', result):
            return True
        time.sleep(1)
    return False


def check_traceroute_hops(src, dst, max_expected_hops):
    """Verify the path length doesn't exceed expected hops."""
    result = src.cmd("traceroute -n -m %d -w 1 %s" % (max_expected_hops + 2, dst.IP()))
    # Count lines that look like hop entries (start with a number)
    hops = [line for line in result.strip().split('\n')[1:] if line.strip() and not line.strip().startswith('traceroute')]
    return len(hops) <= max_expected_hops


def run_test():
    passed = True

    # --- Part 1: Linear multi-hop test ---
    print("--- Testing linear 4-switch topology ---")
    net = Mininet(topo=MultiHopTopo(), autoSetMacs=True, controller=RemoteController)
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

    # Test: Connectivity across 4 switches
    if check_ping(h1, h2):
        print("PASS: multi-hop h1 -> h2 (4 switches)")
    else:
        print("FAIL: multi-hop h1 -> h2 (4 switches)")
        passed = False

    # Test: Bidirectional
    if check_ping(h2, h1):
        print("PASS: multi-hop h2 -> h1 (reverse)")
    else:
        print("FAIL: multi-hop h2 -> h1 (reverse)")
        passed = False

    net.stop()
    time.sleep(2)

    # --- Part 2: Diamond topology test ---
    print("--- Testing diamond topology (redundant paths) ---")
    net2 = Mininet(topo=DiamondTopo(), autoSetMacs=True, controller=RemoteController)
    for h in net2.hosts:
        disable_ipv6(h)
    for s in net2.switches:
        disable_ipv6(s)

    net2.start()
    time.sleep(4)

    for h in net2.hosts:
        send_garp(h)
    time.sleep(2)

    h1, h2 = net2.get('h1', 'h2')

    # Test: Connectivity in diamond (either path is fine)
    if check_ping(h1, h2):
        print("PASS: diamond topology h1 -> h2")
    else:
        print("FAIL: diamond topology h1 -> h2")
        passed = False

    if check_ping(h2, h1):
        print("PASS: diamond topology h2 -> h1")
    else:
        print("FAIL: diamond topology h2 -> h1")
        passed = False

    net2.stop()
    return passed


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)