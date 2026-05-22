#!/usr/bin/env python
"""
CI test for basic L2 switching functionality.
Tests connectivity between hosts in a multi-switch topology.
Exit 0 on PASS, exit 1 on FAIL.
"""

import sys
import time
import re
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


class SwitchingTopo(Topo):
    """
    Topology:
        h1 -- s1 -- s2 -- h3
        h2 --/        \-- h4
    Two switches, two hosts per switch.
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(s1, s2)
        self.addLink(h3, s2)
        self.addLink(h4, s2)


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_gratuitous_arp(host):
    """Send gratuitous ARP so the controller learns the host's MAC."""
    intf = host.defaultIntf().name
    ip = host.IP()
    host.cmd("arping -c 1 -A -I %s %s" % (intf, ip))


def check_ping(src, dst, timeout=5):
    """Ping dst from src. Returns True if at least one reply received."""
    result = src.cmd("ping -c 3 -W %d %s" % (timeout, dst.IP()))
    return " 0% packet loss" in result or re.search(r'[1-3] received', result)


def run_test():
    passed = True
    net = Mininet(topo=SwitchingTopo(), autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)

    # Send gratuitous ARPs from all hosts
    for h in net.hosts:
        send_gratuitous_arp(h)
    time.sleep(2)

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    # --- Test 1: Same-switch connectivity (s1: h1 <-> h2) ---
    if check_ping(h1, h2):
        print("PASS: h1 -> h2 (same switch s1)")
    else:
        print("FAIL: h1 -> h2 (same switch s1)")
        passed = False

    # --- Test 2: Same-switch connectivity (s2: h3 <-> h4) ---
    if check_ping(h3, h4):
        print("PASS: h3 -> h4 (same switch s2)")
    else:
        print("FAIL: h3 -> h4 (same switch s2)")
        passed = False

    # --- Test 3: Cross-switch connectivity (h1 <-> h3) ---
    if check_ping(h1, h3):
        print("PASS: h1 -> h3 (cross-switch s1-s2)")
    else:
        print("FAIL: h1 -> h3 (cross-switch s1-s2)")
        passed = False

    # --- Test 4: Cross-switch connectivity (h2 <-> h4) ---
    if check_ping(h2, h4):
        print("PASS: h2 -> h4 (cross-switch s1-s2)")
    else:
        print("FAIL: h2 -> h4 (cross-switch s1-s2)")
        passed = False

    # --- Test 5: Full mesh ping (all pairs) ---
    hosts = [h1, h2, h3, h4]
    all_pairs_ok = True
    for i, src in enumerate(hosts):
        for dst in hosts[i+1:]:
            if not check_ping(src, dst):
                print("FAIL: %s -> %s" % (src.name, dst.name))
                all_pairs_ok = False
                passed = False
    if all_pairs_ok:
        print("PASS: full mesh connectivity (all host pairs)")

    # --- Test 6: MAC learning verification ---
    # After traffic, the switch should have learned MACs.
    # Send a known ping and check that only the expected port receives traffic.
    # We verify by checking ARP tables are populated correctly.
    h1_arp = h1.cmd("arp -n")
    if h2.IP() in h1_arp and h3.IP() in h1_arp:
        print("PASS: ARP tables populated correctly on h1")
    else:
        print("FAIL: ARP tables not populated on h1")
        passed = False

    net.stop()

    if passed:
        print("\n=== ALL SWITCHING TESTS PASSED ===")
    else:
        print("\n=== SOME SWITCHING TESTS FAILED ===")

    return passed


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)