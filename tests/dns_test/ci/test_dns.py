"""
CI test for DNS module.

Tests:
  1. test_dns_resolve_known  — Resolve a registered hostname, expect correct IP.
  2. test_dns_resolve_nxdomain — Resolve an unregistered hostname, expect NXDOMAIN.
  3. test_dns_reverse_lookup  — PTR (reverse) lookup for a known IP.

Exit 0 if all enabled tests pass; non-zero otherwise.
"""

import sys
import time
import re
import struct
import socket

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


# ---------------------------------------------------------------------------
# Configuration (must match dhcp.py Config / dns.py)
# ---------------------------------------------------------------------------
DNS_SERVER_IP = "192.168.1.1"
POOL_START = "192.168.1.2"
POOL_END = "192.168.1.100"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def dhclient(node, timeout_s=15):
    return node.cmd(
        "timeout %s dhclient -v %s-eth0 2>&1" % (timeout_s, node.name)
    )


def send_arp(node):
    node.cmd("arping -c 2 -A -I %s-eth0 %s" % (node.name, node.defaultIntf().updateIP() or node.IP()))


def dns_resolve(host, qname, timeout=5):
    """Send a DNS A-record query using dig and return the resolved IP or 'NXDOMAIN'."""
    # Use dig without +short to get status line for NXDOMAIN detection
    result = host.cmd("dig +time=%d +tries=1 @%s %s A 2>&1" % (timeout, DNS_SERVER_IP, qname))
    
    # Check for NXDOMAIN in full dig output
    if 'NXDOMAIN' in result:
        return "NXDOMAIN"
    if 'SERVFAIL' in result:
        return None
    if 'timed out' in result or 'no servers could be reached' in result:
        return None
    
    # Parse answer section for IP address
    for line in result.split('\n'):
        line = line.strip()
        if line.startswith(';;') or not line:
            continue
        parts = line.split()
        # A record line: "name. TTL IN A ip"
        if len(parts) >= 5 and parts[-2] == 'A':
            try:
                socket.inet_aton(parts[-1])
                return parts[-1]
            except Exception:
                pass
    
    return None


def _ip_in_pool(ip):
    try:
        v = struct.unpack("!I", socket.inet_aton(ip))[0]
        s = struct.unpack("!I", socket.inet_aton(POOL_START))[0]
        e = struct.unpack("!I", socket.inet_aton(POOL_END))[0]
        return s <= v <= e
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------
class DNSTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch("s1")
        h1 = self.addHost("h1", ip="no ip defined/8")
        h2 = self.addHost("h2", ip="no ip defined/8")
        self.addLink(h1, s1)
        self.addLink(h2, s1)


# ---------------------------------------------------------------------------
# Test 1 — Resolve known hostname
# ---------------------------------------------------------------------------
def test_dns_resolve_known(net):
    """h1 and h2 get IPs via DHCP.  h1 resolves 'h2.local' via DNS and
    verifies the returned IP matches h2's actual IP."""
    passed = True

    h1 = net.get("h1")
    h2 = net.get("h2")

    dhclient(h1, timeout_s=20)
    dhclient(h2, timeout_s=20)
    time.sleep(3)

    ip1 = h1.defaultIntf().updateIP()
    ip2 = h2.defaultIntf().updateIP()

    if not ip1 or not _ip_in_pool(ip1):
        print("FAIL: h1 did not get a valid IP (%s)" % ip1)
        return False
    if not ip2 or not _ip_in_pool(ip2):
        print("FAIL: h2 did not get a valid IP (%s)" % ip2)
        return False

    print("INFO: h1=%s  h2=%s" % (ip1, ip2))

    send_arp(h1)
    send_arp(h2)
    time.sleep(2)

    # Resolve h2.local via DNS
    resolved_ip = dns_resolve(h1, "h2.local", timeout=5)
    if resolved_ip and resolved_ip != "NXDOMAIN":
        if resolved_ip == ip2:
            print("PASS: h2.local resolved to %s (correct)" % resolved_ip)
        else:
            print("FAIL: h2.local resolved to %s, expected %s" % (resolved_ip, ip2))
            passed = False
    else:
        print("FAIL: could not resolve h2.local (got: %s)" % resolved_ip)
        passed = False

    # Resolve h1.local from h2
    resolved_ip = dns_resolve(h2, "h1.local", timeout=5)
    if resolved_ip and resolved_ip != "NXDOMAIN":
        if resolved_ip == ip1:
            print("PASS: h1.local resolved to %s (correct)" % resolved_ip)
        else:
            print("FAIL: h1.local resolved to %s, expected %s" % (resolved_ip, ip1))
            passed = False
    else:
        print("FAIL: could not resolve h1.local (got: %s)" % resolved_ip)
        passed = False

    return passed


# ---------------------------------------------------------------------------
# Test 2 — NXDOMAIN for unknown hostname
# ---------------------------------------------------------------------------
def test_dns_nxdomain(net):
    """Resolve 'nonexistent.local' — the DNS server should return NXDOMAIN."""
    passed = True

    h1 = net.get("h1")
    ip1 = h1.defaultIntf().updateIP()
    if not ip1 or not _ip_in_pool(ip1):
        print("SKIP: h1 has no valid IP for NXDOMAIN test")
        return True

    result = dns_resolve(h1, "nonexistent.local", timeout=5)
    if result == "NXDOMAIN":
        print("PASS: nonexistent.local correctly returned NXDOMAIN")
    elif result is None:
        # None means timeout — the server didn't respond at all (not NXDOMAIN)
        print("FAIL: nonexistent.local query timed out (no response from DNS server)")
        passed = False
    elif result:
        print("FAIL: nonexistent.local unexpectedly resolved to %s" % result)
        passed = False

    return passed


# ---------------------------------------------------------------------------
# Test 3 — PTR reverse lookup
# ---------------------------------------------------------------------------
def test_dns_reverse_lookup(net):
    """h1 performs a reverse (PTR) lookup of h2's IP and verifies the result."""
    passed = True

    h1 = net.get("h1")
    h2 = net.get("h2")

    ip2 = h2.defaultIntf().updateIP()
    if not ip2 or not _ip_in_pool(ip2):
        print("SKIP: h2 has no valid IP for reverse lookup test")
        return True

    # Use dig -x for reverse lookup (explicitly targets our DNS server)
    result = h1.cmd("dig +short +time=5 @%s -x %s 2>&1" % (DNS_SERVER_IP, ip2)).strip()
    
    if result and "timed out" not in result and "SERVFAIL" not in result:
        # Verify the result actually contains "h2" (the expected hostname)
        if "h2" in result.lower():
            print("PASS: PTR lookup for %s returned: %s" % (ip2, result))
            passed = True
        else:
            print("FAIL: PTR lookup for %s returned '%s' (expected 'h2' in result)" % (ip2, result))
            passed = False
    elif "NXDOMAIN" in result or "not found" in result:
        print("FAIL: PTR lookup for %s returned NXDOMAIN (should have PTR record)" % ip2)
        passed = False
    elif "timed out" in result or "no servers could be reached" in result:
        print("FAIL: PTR lookup for %s timed out (DNS server unreachable)" % ip2)
        passed = False
    else:
        print("INFO: PTR lookup for %s returned unexpected: %s" % (ip2, result.strip()[:100]))
        passed = False

    return passed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run_test():
    passed = True

    topo = DNSTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)
    try:
        for h in net.hosts:
            disable_ipv6(h)
        for s in net.switches:
            disable_ipv6(s)

        net.start()
        time.sleep(4)

        print("--- DNS Test 1: Resolve known hostname ---")
        if not test_dns_resolve_known(net):
            passed = False

        print("--- DNS Test 2: NXDOMAIN for unknown hostname ---")
        if not test_dns_nxdomain(net):
            passed = False

        print("--- DNS Test 3: Reverse PTR lookup ---")
        if not test_dns_reverse_lookup(net):
            passed = False

        if passed:
            print("\n=== ALL DNS TESTS PASSED ===")
        else:
            print("\n=== SOME DNS TESTS FAILED ===")
    finally:
        net.stop()

    return passed


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
