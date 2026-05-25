#!/usr/bin/env python
"""
CI test for firewall module.

Verifies that deny rules loaded from firewall_rules.json are correctly
enforced by the controller on OpenFlow switches.

Tests:
  1. h1 -> h2 ICMP ping should be BLOCKED (firewall deny rule)
  2. h1 -> h3 ICMP ping should PASS (no rule matches)
  3. h1 -> h2 TCP/80 (HTTP) should be BLOCKED (firewall deny rule)
  4. h1 -> h2 TCP/8080 should PASS (no rule matches)
  5. h3 -> h2 ICMP ping should PASS (src is not h1)

Exit 0 if all tests pass; non-zero otherwise.
"""

import sys
import time
import re

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


class FirewallTopo(Topo):
    """Single-switch topology with three hosts.

       h1 (192.168.117.2)
       h2 (192.168.117.3)  -- s1
       h3 (192.168.117.4)
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')

        h1 = self.addHost('h1', ip='192.168.117.2/24')
        h2 = self.addHost('h2', ip='192.168.117.3/24')
        h3 = self.addHost('h3', ip='192.168.117.4/24')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host):
    """Send gratuitous ARP so the controller learns the host location."""
    intf = host.defaultIntf().name
    host.cmd("arping -c 1 -A -I %s %s" % (intf, host.IP()))


def ping_ok(src, dst, count=3, timeout=2):
    """Return True if ping from src to dst gets at least one reply."""
    result = src.cmd("ping -c %d -W %d %s" % (count, timeout, dst.IP()))
    # "0% packet loss" means all replies received
    if " 0% packet loss" in result:
        return True
    # Partial replies are still success in firewall context (at least got through)
    if re.search(r'[1-9] received', result):
        return True
    return False


def tcp_reachable(host, target_ip, port, connect_timeout=2, max_time=3):
    """Return True if a TCP connection to target_ip:port succeeds."""
    cmd = (
        "curl -sS --connect-timeout %d -m %d "
        "-o /dev/null -w '%%{http_code}' "
        "http://%s:%d/ 2>/dev/null" % (connect_timeout, max_time, target_ip, port)
    )
    result = host.cmd(cmd).strip()
    # Any numeric HTTP status code means TCP connected
    if result.isdigit():
        return True
    return False


def run_test():
    passed = True
    failures = []

    topo = FirewallTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')

    # --- Send gratuitous ARP from all hosts so the controller learns them ---
    for _ in range(3):
        for h in net.hosts:
            send_garp(h)
        time.sleep(1)

    # --- Start HTTP servers on h2 for TCP tests ---
    h2.cmd('pkill -f "python3 -m http.server" 2>/dev/null; true')
    h2.cmd('python3 -m http.server 80 --bind 192.168.117.3 >/tmp/h2-http80.log 2>&1 &')
    h2.cmd('python3 -m http.server 8080 --bind 192.168.117.3 >/tmp/h2-http8080.log 2>&1 &')
    time.sleep(2)

    # ============================================================
    # Test 1: h1 -> h2 ICMP should be BLOCKED by firewall rule
    # ============================================================
    if ping_ok(h1, h2):
        print("FAIL: h1 -> h2 ICMP (expected DENY, but ping passed)")
        failures.append("h1 -> h2 ICMP should be blocked")
        passed = False
    else:
        print("PASS: h1 -> h2 ICMP (correctly blocked by firewall)")

    # ============================================================
    # Test 2: h1 -> h3 ICMP should PASS (no rule for h3)
    # ============================================================
    if ping_ok(h1, h3):
        print("PASS: h1 -> h3 ICMP (allowed, no matching rule)")
    else:
        print("FAIL: h1 -> h3 ICMP (expected ALLOW, but ping failed)")
        failures.append("h1 -> h3 ICMP should be allowed")
        passed = False

    # ============================================================
    # Test 3: h3 -> h2 ICMP should PASS (src is not h1)
    # ============================================================
    if ping_ok(h3, h2):
        print("PASS: h3 -> h2 ICMP (allowed, src_ip is not 192.168.117.2)")
    else:
        print("FAIL: h3 -> h2 ICMP (expected ALLOW, but ping failed)")
        failures.append("h3 -> h2 ICMP should be allowed")
        passed = False

    # ============================================================
    # Test 4: h1 -> h2 TCP/80 should be BLOCKED by firewall rule
    # ============================================================
    if tcp_reachable(h1, "192.168.117.3", 80):
        print("FAIL: h1 -> h2 TCP/80 (expected DENY, but connection succeeded)")
        failures.append("h1 -> h2 TCP/80 should be blocked")
        passed = False
    else:
        print("PASS: h1 -> h2 TCP/80 (correctly blocked by firewall)")

    # ============================================================
    # Test 5: h1 -> h2 TCP/8080 should PASS (no rule for port 8080)
    # ============================================================
    if tcp_reachable(h1, "192.168.117.3", 8080):
        print("PASS: h1 -> h2 TCP/8080 (allowed, no matching rule)")
    else:
        print("FAIL: h1 -> h2 TCP/8080 (expected ALLOW, but connection failed)")
        failures.append("h1 -> h2 TCP/8080 should be allowed")
        passed = False

    # ============================================================
    # Test 6: h2 -> h1 ICMP should PASS (reverse direction, no rule)
    # ============================================================
    if ping_ok(h2, h1):
        print("PASS: h2 -> h1 ICMP (allowed, reverse direction)")
    else:
        print("FAIL: h2 -> h1 ICMP (expected ALLOW, but ping failed)")
        failures.append("h2 -> h1 ICMP should be allowed")
        passed = False

    # --- Cleanup ---
    h2.cmd('pkill -f "python3 -m http.server" 2>/dev/null; true')
    net.stop()

    if passed:
        print("\n=== ALL FIREWALL TESTS PASSED ===")
    else:
        print("\n=== SOME FIREWALL TESTS FAILED ===")
        for f in failures:
            print("  - %s" % f)

    return passed


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
