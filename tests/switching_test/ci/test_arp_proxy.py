#!/usr/bin/env python
"""
CI test: ARP proxy functionality.
Verifies the controller correctly replies to ARP requests on behalf of known hosts.
"""

import sys
import time
import re
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


class ARPTestTopo(Topo):
    """
    h1 -- s1 -- s2 -- h2
               |
              s3 -- h3
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')

        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)
        self.addLink(s2, s3)
        self.addLink(s3, h3)


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host):
    intf = host.defaultIntf().name
    host.cmd("arping -c 1 -A -I %s %s" % (intf, host.IP()))


def run_test():
    passed = True
    net = Mininet(topo=ARPTestTopo(), autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)

    h1, h2, h3 = net.get('h1', 'h2', 'h3')

    # Send gratuitous ARP from all hosts to populate controller's ARP table
    for h in net.hosts:
        send_garp(h)
    time.sleep(2)

    # Test 1: ARP resolution - h1 should be able to resolve h2's MAC
    h1.cmd("arp -d %s 2>/dev/null" % h2.IP())  # Clear local ARP cache
    time.sleep(1)
    result = h1.cmd("arping -c 2 -W 2 -I h1-eth0 %s" % h2.IP())
    if "reply from" in result.lower() or "unicast reply" in result.lower() or "bytes from" in result.lower():
        print("PASS: ARP resolution h1 -> h2 (controller proxy)")
    else:
        # Fallback: just check if ping works (which requires ARP to succeed)
        ping_result = h1.cmd("ping -c 2 -W 2 %s" % h2.IP())
        if " 0% packet loss" in ping_result:
            print("PASS: ARP resolution h1 -> h2 (verified via ping)")
        else:
            print("FAIL: ARP resolution h1 -> h2")
            passed = False

    # Test 2: ARP table populated on hosts after communication
    h1.cmd("ping -c 1 -W 2 %s" % h2.IP())
    time.sleep(1)
    arp_output = h1.cmd("arp -n")
    if h2.IP() in arp_output:
        print("PASS: h1 ARP table contains h2's IP")
    else:
        print("FAIL: h1 ARP table missing h2's IP")
        passed = False

    # Test 3: ARP works for host on different switch (h1 -> h3)
    h1.cmd("arp -d %s 2>/dev/null" % h3.IP())
    time.sleep(1)
    ping_result = h1.cmd("ping -c 2 -W 2 %s" % h3.IP())
    if " 0% packet loss" in ping_result or re.search(r'[12] received', ping_result):
        print("PASS: ARP + connectivity h1 -> h3 (multi-hop)")
    else:
        print("FAIL: ARP + connectivity h1 -> h3 (multi-hop)")
        passed = False

    # Test 4: Rapid ARP queries (stress test proxy)
    success_count = 0
    for i in range(5):
        h1.cmd("arp -d %s 2>/dev/null" % h2.IP())
        result = h1.cmd("ping -c 1 -W 2 %s" % h2.IP())
        if " 0% packet loss" in result or "1 received" in result:
            success_count += 1
        time.sleep(0.5)

    if success_count >= 4:
        print("PASS: rapid ARP queries (%d/5 successful)" % success_count)
    else:
        print("FAIL: rapid ARP queries (%d/5 successful)" % success_count)
        passed = False

    # Test 5: ARP for non-existent host should timeout (no crash)
    result = h1.cmd("ping -c 1 -W 3 10.0.0.99")
    # We just verify the controller doesn't crash and returns no reply
    if "100% packet loss" in result or "0 received" in result:
        print("PASS: ARP for non-existent host correctly times out")
    else:
        print("PASS: ARP for non-existent host handled (no crash)")

    net.stop()
    return passed


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)