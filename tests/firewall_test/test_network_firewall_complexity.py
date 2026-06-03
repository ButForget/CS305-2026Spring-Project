#!/usr/bin/env python
"""
CI test: Firewall × Shortest-Path Switching (HeavyMesh topology).

Reuses the complex HeavyMesh topology (6 switches, 8 hosts, 11 links,
high path redundancy) to verify that firewall deny rules correctly
override shortest-path forwarding.

Two firewall rule sets are supported (switch via --mode):

  connect    – firewall_rules_connect.json (empty rules)
                All 28 host pairs MUST be reachable.

  disconnect – firewall_rules_disconnect.json (4 deny rules)
                h1<->h3 and h5<->h8 ICMP MUST be blocked, even though
                multiple redundant paths exist between their switches.
                All other host pairs MUST remain reachable.

Usage:
  # Test with empty rules (all hosts connected):
  cp firewall_rules_connect.json firewall_rules.json
  osken-manager --observe-links controller.py &
  sudo python test_network_firewall_complexity.py --mode connect

  # Test with blocking rules (specific pairs disconnected):
  cp firewall_rules_disconnect.json firewall_rules.json
  osken-manager --observe-links controller.py &
  sudo python test_network_firewall_complexity.py --mode disconnect

Exit 0 if all checks pass; non-zero otherwise.
"""

import argparse
import re
import sys
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


# ==========================================================================
# HeavyMesh Topology (same as tests/switching_test/test_network_complexty.py)
# ==========================================================================

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

    Host assignments (with explicit IPs so firewall rules match):
      s1: h1 (10.0.0.1), h2 (10.0.0.2)
      s2: h3 (10.0.0.3)
      s3: h4 (10.0.0.4)
      s4: h5 (10.0.0.5)
      s5: h6 (10.0.0.6)
      s6: h7 (10.0.0.7), h8 (10.0.0.8)

    Total host pairs: C(8,2) = 28
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

        # Create 8 hosts with explicit IPs
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        h5 = self.addHost('h5', ip='10.0.0.5/24')
        h6 = self.addHost('h6', ip='10.0.0.6/24')
        h7 = self.addHost('h7', ip='10.0.0.7/24')
        h8 = self.addHost('h8', ip='10.0.0.8/24')

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
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        # Horizontal (bottom row)
        self.addLink(s4, s5)
        self.addLink(s5, s6)
        # Vertical
        self.addLink(s1, s4)
        self.addLink(s2, s5)
        self.addLink(s3, s6)
        # Cross-links (diagonals)
        self.addLink(s1, s5)
        self.addLink(s2, s4)
        self.addLink(s2, s6)
        self.addLink(s3, s5)


# ==========================================================================
# Helpers
# ==========================================================================

def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host):
    """Send gratuitous ARP so the controller learns the host location."""
    intf = host.defaultIntf().name
    host.cmd("arping -c 1 -A -I %s %s" % (intf, host.IP()))


def ping_ok(src, dst_ip, count=3, timeout=2):
    """Return True if ping from src to dst_ip gets at least one reply."""
    result = src.cmd("ping -c %d -W %d %s" % (count, timeout, dst_ip))
    if " 0% packet loss" in result:
        return True
    if re.search(r'[1-9]\d* received', result):
        return True
    return False


def count_firewall_flows(switch):
    """Count firewall flow entries (cookie=0x305f) on a switch."""
    raw = switch.cmd('ovs-ofctl -O OpenFlow10 dump-flows %s' % switch.name)
    return len([l for l in raw.split('\n') if 'cookie=0x305f' in l])


# ==========================================================================
# Expected blocked pairs for "disconnect" mode
# ==========================================================================

# These MUST match the rules in firewall_rules_disconnect.json
DISCONNECT_BLOCKED_PAIRS = {
    ('h1', 'h3'),  # 10.0.0.1 <-> 10.0.0.3 ICMP (bidirectional rules)
    ('h3', 'h1'),
    ('h5', 'h8'),  # 10.0.0.5 <-> 10.0.0.8 ICMP (bidirectional rules)
    ('h8', 'h5'),
}


# ==========================================================================
# Main test runner
# ==========================================================================

def run_test(mode):
    """Run the firewall × switching complexity test.

    Args:
        mode: 'connect' or 'disconnect'

    Returns:
        True if all checks pass, False otherwise.
    """
    passed = True
    failures = []

    print("=" * 60)
    print("  Firewall × Shortest-Path Switching Test")
    print("  Topology: HeavyMesh (6 switches, 8 hosts, 11 links)")
    print("  Mode: %s" % mode.upper())
    print("=" * 60)

    # ------------------------------------------------------------------
    # Start Mininet
    # ------------------------------------------------------------------
    topo = HeavyMeshTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)

    # Resolve hosts
    hosts = {h.name: h for h in net.hosts}
    switches = {s.name: s for s in net.switches}

    # ------------------------------------------------------------------
    # Send gratuitous ARP so the controller learns all hosts
    # ------------------------------------------------------------------
    print("\n--- Learning host locations (ARP) ---")
    for _ in range(3):
        for h in net.hosts:
            send_garp(h)
        time.sleep(1)

    # ------------------------------------------------------------------
    # Test 1: Verify firewall flows are installed on ALL switches
    # ------------------------------------------------------------------
    print("\n--- Test 1: Firewall flow installation ---")
    total_fw_flows = 0
    for s in net.switches:
        n = count_firewall_flows(s)
        total_fw_flows += n
        print("  %s: %d firewall flow(s)" % (s.name, n))

    if mode == "connect":
        if total_fw_flows == 0:
            print("  PASS: No firewall flows (empty ruleset)")
        else:
            print("  FAIL: Expected 0 firewall flows, got %d" % total_fw_flows)
            failures.append("Firewall flows found in connect mode")
            passed = False
    else:  # disconnect
        # 4 deny rules × 6 switches = 24 flows (but dedup in installed set)
        # Each unique rule key is per-switch, so 4 rules × 6 switches = 24
        expected_min = 4 * 6  # 4 rules on each of 6 switches
        if total_fw_flows >= expected_min:
            print("  PASS: %d firewall flows (>= %d expected)" %
                  (total_fw_flows, expected_min))
        else:
            print("  FAIL: Only %d firewall flows (< %d expected)" %
                  (total_fw_flows, expected_min))
            failures.append("Too few firewall flows in disconnect mode")
            passed = False

    # ------------------------------------------------------------------
    # Test 2: Full-mesh ping (28 host pairs)
    # ------------------------------------------------------------------
    print("\n--- Test 2: Full-mesh connectivity (28 host pairs) ---")
    host_list = sorted(net.hosts, key=lambda h: h.name)
    blocked_found = []
    ping_results = {}

    for i, src in enumerate(host_list):
        for dst in host_list[i + 1:]:
            ok = ping_ok(src, dst.IP())
            ping_results[(src.name, dst.name)] = ok
            # Also test reverse direction explicitly
            ok_rev = ping_ok(dst, src.IP())
            ping_results[(dst.name, src.name)] = ok_rev

    # Analyze results
    connect_ok = 0
    connect_fail = 0
    for (src_name, dst_name), ok in sorted(ping_results.items()):
        pair = (src_name, dst_name)
        if mode == "connect":
            # All pairs should be reachable
            if ok:
                connect_ok += 1
            else:
                connect_fail += 1
                print("  FAIL: %s -> %s (expected REACHABLE, but BLOCKED)" %
                      (src_name, dst_name))
                failures.append("%s -> %s should be reachable in connect mode" %
                                (src_name, dst_name))
        else:  # disconnect
            if pair in DISCONNECT_BLOCKED_PAIRS:
                if not ok:
                    print("  PASS: %s -> %s (correctly BLOCKED by firewall)" %
                          (src_name, dst_name))
                    blocked_found.append(pair)
                else:
                    print("  FAIL: %s -> %s (should be BLOCKED, but REACHABLE)" %
                          (src_name, dst_name))
                    failures.append("%s -> %s should be blocked by firewall" %
                                    (src_name, dst_name))
            else:
                if ok:
                    connect_ok += 1
                else:
                    connect_fail += 1
                    print("  FAIL: %s -> %s (should be REACHABLE, but BLOCKED)" %
                          (src_name, dst_name))
                    failures.append("%s -> %s should be reachable" %
                                    (src_name, dst_name))

    # Summarize
    if mode == "connect":
        total = connect_ok + connect_fail
        print("\n  Connect mode summary: %d/%d pairs reachable" %
              (connect_ok, total))
        if connect_fail > 0:
            print("  FAIL: %d pairs unexpectedly blocked" % connect_fail)
            passed = False
        else:
            print("  PASS: All pairs connected (firewall inactive)")
    else:
        total_unblocked = connect_ok + connect_fail
        print("\n  Disconnect mode summary:")
        print("    Blocked pairs (expected=4): %d found - %s" %
              (len(blocked_found),
               "PASS" if len(blocked_found) == 4 else "FAIL"))
        print("    Unblocked pairs: %d/%d reachable" %
              (connect_ok, total_unblocked))
        if len(blocked_found) != 4:
            failures.append("Expected 4 blocked pairs, found %d" %
                            len(blocked_found))
            passed = False
        if connect_fail > 0:
            failures.append("%d unblocked pairs unexpectedly blocked" %
                            connect_fail)
            passed = False

    # ------------------------------------------------------------------
    # Test 3: Verify specific cross-switch, multi-path blocking
    # ------------------------------------------------------------------
    if mode == "disconnect":
        print("\n--- Test 3: Multi-path redundancy check ---")

        # h1(s1) and h3(s2): multiple paths exist
        #   Path 1: s1 -> s2 (1 hop)
        #   Path 2: s1 -> s4 -> s5 -> s2 (3 hops)
        #   Path 3: s1 -> s5 -> s2 (2 hops)
        h1 = hosts['h1']
        h3 = hosts['h3']
        if not ping_ok(h1, h3.IP()):
            print("  PASS: h1(s1) -> h3(s2) blocked despite multiple paths")
        else:
            print("  FAIL: h1(s1) -> h3(s2) reachable (firewall not enforced)")
            failures.append("h1->h3 should be blocked on all paths")
            passed = False

        # h5(s4) and h8(s6): multiple paths exist
        #   Path 1: s4 -> s5 -> s6 (2 hops)
        #   Path 2: s4 -> s1 -> s2 -> s3 -> s6 (4 hops)
        #   Path 3: s4 -> s1 -> s5 -> s6 (3 hops)
        h5 = hosts['h5']
        h8 = hosts['h8']
        if not ping_ok(h5, h8.IP()):
            print("  PASS: h5(s4) -> h8(s6) blocked despite multiple paths")
        else:
            print("  FAIL: h5(s4) -> h8(s6) reachable (firewall not enforced)")
            failures.append("h5->h8 should be blocked on all paths")
            passed = False

        # h2(s1) and h4(s3): NOT blocked, should be reachable
        h2 = hosts['h2']
        h4 = hosts['h4']
        if ping_ok(h2, h4.IP()):
            print("  PASS: h2(s1) -> h4(s3) reachable (not in firewall rules)")
        else:
            print("  FAIL: h2(s1) -> h4(s3) unexpectedly blocked")
            failures.append("h2->h4 should be reachable")
            passed = False

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------
    net.stop()

    # ------------------------------------------------------------------
    # Final report
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    if passed:
        print("  OVERALL RESULT: PASS")
        print("  Mode: %s - all checks passed" % mode.upper())
    else:
        print("  OVERALL RESULT: FAIL")
        print("  Failures:")
        for f in failures:
            print("    - %s" % f)
    print("=" * 60)

    return passed


# ==========================================================================
# Entry point
# ==========================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Firewall × Shortest-Path Switching Complexity Test"
    )
    parser.add_argument(
        "--mode", required=True, choices=["connect", "disconnect"],
        help="'connect': empty firewall rules (all hosts reachable); "
             "'disconnect': deny rules active (specific pairs blocked)"
    )
    args = parser.parse_args()

    setLogLevel("info")
    sys.exit(0 if run_test(args.mode) else 1)
