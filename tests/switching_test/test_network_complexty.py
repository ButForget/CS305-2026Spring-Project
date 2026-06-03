# -*- coding: utf-8 -*-
"""
Switching test: HeavyMesh topology
6 switches, 8 hosts, 11 switch-to-switch links

Topology:
     h1 h2       h3        h4
      \ /         |         |
       s1 ------ s2 ------ s3
       | \      / |  \    / |
       |  \   /   |   \ /   |
       |   \ /    |    X    |
       |   / \    |   / \   |
       |  /   \   |  /   \  |
       s4 ------ s5 ------ s6
       |          |        / \
       h5         h6      h7  h8
"""

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
import time
import sys


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def ping(host, dst, count=1, timeout=1):
    return host.cmd('ping -c %s -W %s %s' % (count, timeout, dst))


def send_arp(node, count=1):
    node.cmd('arping -c %s -A -I %s-eth0 %s' % (count, node.name, node.IP()))


def send_dhcp(node):
    print('Sending DHCP request dhclient -v %s-eth0' % (node.name))
    node.cmd('dhclient -v %s-eth0' % (node.name))


def do_arp_all(net):
    for h in net.hosts:
        send_arp(h)


class HeavyMeshTopo(Topo):
    """
    6 switches, 8 hosts, 11 switch-to-switch edges.

    Switch layout (2x3 grid with cross-links):

        s1 ---- s2 ---- s3
        | \   / |  \  / |
        |  \ /  |   \/  |
        |  / \  |   /\  |
        | /   \ |  /  \ |
        s4 ---- s5 ---- s6

    Switch-to-switch links (11 total):
      Horizontal:  s1-s2, s2-s3, s4-s5, s5-s6
      Vertical:    s1-s4, s2-s5, s3-s6
      Cross:       s1-s5, s2-s4, s2-s6, s3-s5

    Host assignments:
      s1: h1, h2
      s2: h3
      s3: h4
      s4: h5
      s5: h6
      s6: h7, h8
    """

    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Create 6 switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')
        s5 = self.addSwitch('s5')
        s6 = self.addSwitch('s6')

        # Create 8 hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')
        h5 = self.addHost('h5')
        h6 = self.addHost('h6')
        h7 = self.addHost('h7')
        h8 = self.addHost('h8')

        # Host-to-switch links (8 links)
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s2)
        self.addLink(h4, s3)
        self.addLink(h5, s4)
        self.addLink(h6, s5)
        self.addLink(h7, s6)
        self.addLink(h8, s6)

        # Switch-to-switch links (11 links)
        # Horizontal (top row)
        self.addLink(s1, s2)   # 1
        self.addLink(s2, s3)   # 2
        # Horizontal (bottom row)
        self.addLink(s4, s5)   # 3
        self.addLink(s5, s6)   # 4
        # Vertical
        self.addLink(s1, s4)   # 5
        self.addLink(s2, s5)   # 6
        self.addLink(s3, s6)   # 7
        # Cross-links (diagonals)
        self.addLink(s1, s5)   # 8
        self.addLink(s2, s4)   # 9
        self.addLink(s2, s6)   # 10
        self.addLink(s3, s5)   # 11


def ping_all_pairs(hosts, count=2, timeout=1):
    """Ping every host pair and return dict of results."""
    results = {}
    for i, src in enumerate(hosts):
        for dst in hosts[i + 1:]:
            out = ping(src, dst.IP(), count=count, timeout=timeout)
            results[(src.name, dst.name)] = out
    return results


def print_ping_results(results, title):
    print("\n========== %s ==========" % title)
    for (src, dst), out in results.items():
        loss_line = [l for l in out.split('\n') if 'packet loss' in l]
        summary = loss_line[0].strip() if loss_line else out.strip()
        print("  %s -> %s: %s" % (src, dst, summary))


def count_failures(results):
    failures = 0
    for out in results.values():
        if " 0% packet loss" not in out:
            failures += 1
    return failures


def has_link(net, left, right):
    for link in net.links:
        n1 = link.intf1.node.name
        n2 = link.intf2.node.name
        if {n1, n2} == {left, right}:
            return True
    return False


def run_scenario(net, hosts, name, links_down, expect_connected):
    """Bring links down, test connectivity, restore links."""
    for a, b in links_down:
        if not has_link(net, a, b):
            print("\n========== %s (SKIP: no link %s-%s) ==========" % (name, a, b))
            return True

    expect_label = "expect CONNECTED" if expect_connected else "expect DISCONNECTED"
    print("\n========== %s (%s) ==========" % (name, expect_label))

    # Bring links down
    for a, b in links_down:
        net.configLinkStatus(a, b, 'down')
        print("  [DOWN] %s <--> %s" % (a, b))

    time.sleep(4)

    # Re-send ARP so controller can re-learn after topology change
    do_arp_all(net)
    time.sleep(2)

    results = ping_all_pairs(hosts)
    print_ping_results(results, "Connectivity after link(s) down")

    failed_pairs = count_failures(results)
    if expect_connected:
        ok = (failed_pairs == 0)
    else:
        ok = (failed_pairs > 0)

    # Restore links
    for a, b in links_down:
        net.configLinkStatus(a, b, 'up')
        print("  [UP]   %s <--> %s" % (a, b))
    time.sleep(3)
    do_arp_all(net)
    time.sleep(2)

    if ok:
        print("  SCENARIO RESULT: PASS")
    else:
        print("  SCENARIO RESULT: FAIL (failed pairs: %d)" % failed_pairs)
    return ok


def run_tests(net):
    """Run all test scenarios on the HeavyMesh topology."""
    hosts = net.hosts
    failures = 0
    total = 0

    # ------------------------------------------------------------------
    # Phase 1: Wait for topology discovery and host learning
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  HeavyMesh Topology Test Suite")
    print("  6 switches, 8 hosts, 11 switch-to-switch links")
    print("=" * 60)

    print("\n========== Waiting for topology discovery ==========")
    time.sleep(3)
    do_arp_all(net)
    time.sleep(5)
    do_arp_all(net)
    time.sleep(3)

    # ------------------------------------------------------------------
    # Test 1: Baseline full-mesh connectivity
    # ------------------------------------------------------------------
    total += 1
    print("\n========== Test 1: Full-mesh connectivity (28 host pairs) ==========")
    results = ping_all_pairs(hosts, count=3, timeout=2)
    print_ping_results(results, "Baseline ping (all pairs)")
    baseline_failures = count_failures(results)
    if baseline_failures == 0:
        print("\n  BASELINE RESULT: PASS (all 28 pairs connected)")
    else:
        print("\n  BASELINE RESULT: FAIL (%d/%d pairs failed)" %
              (baseline_failures, len(results)))
        failures += 1

    # ------------------------------------------------------------------
    # Test 2: Flow table inspection
    # ------------------------------------------------------------------
    print("\n========== Test 2: Flow table dump ==========")
    for s in net.switches:
        print("\n--- %s ---" % s.name)
        flows = s.cmd('ovs-ofctl dump-flows %s --no-stats' % s.name)
        flow_lines = [l.strip() for l in flows.split('\n') if l.strip()]
        print("  Total flow entries: %d" % len(flow_lines))
        for line in flow_lines[:10]:  # Print first 10 flows
            print("  %s" % line)
        if len(flow_lines) > 10:
            print("  ... (%d more)" % (len(flow_lines) - 10))

    # ------------------------------------------------------------------
    # Test 3: Single link failure (high redundancy - should stay connected)
    # ------------------------------------------------------------------
    scenarios = [
        # Single link failures: network has enough redundancy
        ("Single failure: s1-s2",
         [('s1', 's2')], True),

        ("Single failure: s2-s5 (central vertical)",
         [('s2', 's5')], True),

        ("Single failure: s3-s5 (diagonal)",
         [('s3', 's5')], True),

        # Double link failures: still enough paths through cross-links
        ("Double failure: s1-s2 and s4-s5 (both horizontals on same side)",
         [('s1', 's2'), ('s4', 's5')], True),

        ("Double failure: s1-s4 and s2-s5 (two verticals)",
         [('s1', 's4'), ('s2', 's5')], True),

        # Triple link failure: still connected thanks to mesh
        ("Triple failure: s1-s2, s1-s4, s1-s5 (cut s1 to only cross-link via s2-s4? no, h1/h2 on s1)",
         [('s1', 's2'), ('s1', 's5'), ('s1', 's4')], False),
        # s1 only connects to s2, s4, s5 in non-host links. Cutting all 3 isolates s1 (h1, h2).

        # Isolate s3: s3 connects to s2, s6, s5. Cut all three.
        ("Isolate s3: break s2-s3, s3-s6, s3-s5",
         [('s2', 's3'), ('s3', 's6'), ('s3', 's5')], False),

        # Isolate s4: s4 connects to s1, s5, s2. Cut all three.
        ("Isolate s4: break s1-s4, s4-s5, s2-s4",
         [('s1', 's4'), ('s4', 's5'), ('s2', 's4')], False),
    ]

    print("\n========== Test 3-N: Link failure scenarios ==========")
    for name, links_down, expect_connected in scenarios:
        total += 1
        ok = run_scenario(net, hosts, name, links_down, expect_connected)
        if not ok:
            failures += 1

    # ------------------------------------------------------------------
    # Test Final: Verify recovery (full connectivity after all links restored)
    # ------------------------------------------------------------------
    total += 1
    print("\n========== Final Test: Full recovery verification ==========")
    time.sleep(3)
    do_arp_all(net)
    time.sleep(3)
    results = ping_all_pairs(hosts, count=3, timeout=2)
    print_ping_results(results, "Full connectivity after all links restored")
    recovery_failures = count_failures(results)
    if recovery_failures == 0:
        print("\n  RECOVERY RESULT: PASS (all pairs reconnected)")
    else:
        print("\n  RECOVERY RESULT: FAIL (%d pairs still failing)" % recovery_failures)
        failures += 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("  TEST SUMMARY")
    print("=" * 60)
    print("  Total scenarios: %d" % total)
    print("  Passed: %d" % (total - failures))
    print("  Failed: %d" % failures)
    print("=" * 60)
    if failures == 0:
        print("  OVERALL RESULT: PASS")
    else:
        print("  OVERALL RESULT: FAIL")
    print("=" * 60)


def run_mininet():
    """Start Mininet with HeavyMesh topology and run tests."""
    topo = HeavyMeshTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    # Disable IPv6 on all nodes
    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(1)
    do_arp_all(net)

    # Print topology info
    print("\n========== Topology Info ==========")
    print("  Switches: %s" % [s.name for s in net.switches])
    print("  Hosts: %s" % [(h.name, h.IP()) for h in net.hosts])
    print("  Links: %d total" % len(net.links))
    for link in net.links:
        print("    %s <--> %s" % (link.intf1.node.name, link.intf2.node.name))

    # Run automated tests
    run_tests(net)

    # Enter CLI for manual testing
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()