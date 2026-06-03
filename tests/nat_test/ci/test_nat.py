"""
CI test for NAT module.

The controller implements SNAT/DNAT between an "internal" subnet (10.0.1.0/24)
and an "external" subnet (10.0.2.0/24).  Internal hosts' source IPs are rewritten
to a designated NAT external IP (10.0.2.100) when communicating with external
hosts, and reply packets are translated back.

Topology:
    h1 (10.0.1.2) -- s1 -- s2 -- h2 (10.0.2.2)

Tests:
  1. test_nat_connectivity  — h1 can ping h2 through NAT.
  2. test_nat_snat          — h2 sees the NAT IP (10.0.2.100) as the source
                               of packets from h1, not h1's real IP.
  3. test_nat_bidirectional — h2 can also ping h1 (reverse DNAT).
  4. test_nat_tcp           — TCP connection h1->h2 works through NAT.

Exit 0 if all enabled tests pass; non-zero otherwise.
"""

import sys
import time
import re

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


# ---------------------------------------------------------------------------
# Configuration (must match nat.py)
# ---------------------------------------------------------------------------
NAT_EXTERNAL_IP = "10.0.2.100"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host, count=2):
    intf = host.defaultIntf().name
    host.cmd("arping -c %d -A -I %s %s" % (count, intf, host.IP()))


def check_ping(src, dst, count=4, retries=2):
    """Return True if ping succeeds with at least 1 reply."""
    for attempt in range(retries):
        result = src.cmd("ping -c %d -W 2 %s" % (count, dst.IP()))
        if re.search(r"[1-9]\d* received", result) or " 0% packet loss" in result:
            return True
        time.sleep(2)
    return False


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------
class NATTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")

        h1 = self.addHost("h1", ip="10.0.1.2/16")
        h2 = self.addHost("h2", ip="10.0.2.2/16")

        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)


# ---------------------------------------------------------------------------
# Test 1 — Basic NAT connectivity
# ---------------------------------------------------------------------------
def test_nat_connectivity(net):
    """h1 (internal) should be able to ping h2 (external) through NAT."""
    passed = True

    h1 = net.get("h1")
    h2 = net.get("h2")

    # Send gratuitous ARP
    for h in net.hosts:
        send_garp(h)
    time.sleep(3)

    if check_ping(h1, h2, count=3, retries=3):
        print("PASS: h1 (%s) can ping h2 (%s) through NAT" % (h1.IP(), h2.IP()))
    else:
        # Retry with more wait
        time.sleep(2)
        send_garp(h1)
        send_garp(h2)
        time.sleep(2)
        if check_ping(h1, h2, count=3, retries=2):
            print("PASS: h1 (%s) can ping h2 (%s) through NAT (retry)" % (h1.IP(), h2.IP()))
        else:
            print("FAIL: h1 (%s) cannot ping h2 (%s)" % (h1.IP(), h2.IP()))
            passed = False

    return passed


# ---------------------------------------------------------------------------
# Test 2 — SNAT: h2 sees the NAT IP as source
# ---------------------------------------------------------------------------
def test_nat_snat(net):
    """Verify SNAT: h2 should see NAT_EXTERNAL_IP as source of connections from h1.
    Uses a TCP server on h2 that reports the client IP (connects via NAT-proven TCP)."""
    passed = True
    h1 = net.get("h1")
    h2 = net.get("h2")

    # Start TCP server that reports client IP
    server_script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('', 12346))\n"
        "s.listen(1)\n"
        "s.settimeout(6)\n"
        "try:\n"
        "    conn, addr = s.accept()\n"
        "    print(addr[0])\n"
        "    conn.send(b'HTTP/1.0 200 OK\\r\\n\\r\\nOK')\n"
        "    conn.close()\n"
        "except socket.timeout:\n"
        "    print('TIMEOUT')\n"
        "finally:\n"
        "    s.close()\n"
    )
    h2.cmd("echo '%s' > /tmp/tcp_server.py" % server_script.replace("'", "'\"'\"'"))
    h2.cmd("python3 /tmp/tcp_server.py > /tmp/tcp_out.txt 2>/dev/null &")
    time.sleep(0.5)

    # h1 connects via curl (TCP through NAT is proven to work in test 4)
    h1.cmd("curl -sS --connect-timeout 3 -m 4 http://%s:12346/ 2>/dev/null" % h2.IP())
    time.sleep(5)

    result = h2.cmd("cat /tmp/tcp_out.txt 2>/dev/null").strip()
    h2.cmd("pkill -f tcp_server.py 2>/dev/null; true")
    h2.cmd("rm -f /tmp/tcp_server.py /tmp/tcp_out.txt")

    if not result or result == 'TIMEOUT':
        print("FAIL: SNAT TCP server timed out (NAT translation not working)")
        passed = False
    elif result == NAT_EXTERNAL_IP:
        print("PASS: h2 sees source IP %s (NAT translated correctly)" % NAT_EXTERNAL_IP)
        passed = True
    elif result == h1.IP():
        print("FAIL: h2 sees original IP %s (NAT NOT translating)" % h1.IP())
        passed = False
    else:
        print("FAIL: h2 sees unexpected source IP %s (expected %s)" % (result, NAT_EXTERNAL_IP))
        passed = False

    return passed


# ---------------------------------------------------------------------------
# Test 3 — Bidirectional connectivity
# ---------------------------------------------------------------------------
def test_nat_bidirectional(net):
    """h2 (external) should also be able to ping h1 (internal) via DNAT."""
    passed = True

    h1 = net.get("h1")
    h2 = net.get("h2")

    send_garp(h1)
    send_garp(h2)
    time.sleep(2)

    if check_ping(h2, h1, count=3, retries=3):
        print("PASS: h2 (%s) can ping h1 (%s) through NAT (reverse)" % (h2.IP(), h1.IP()))
    else:
        time.sleep(2)
        send_garp(h1)
        send_garp(h2)
        time.sleep(2)
        if check_ping(h2, h1, count=3, retries=2):
            print("PASS: h2 (%s) can ping h1 (%s) through NAT (reverse, retry)" % (h2.IP(), h1.IP()))
        else:
            print("FAIL: h2 (%s) cannot ping h1 (%s)" % (h2.IP(), h1.IP()))
            passed = False

    return passed


# ---------------------------------------------------------------------------
# Test 4 — TCP connectivity through NAT
# ---------------------------------------------------------------------------
def test_nat_tcp(net):
    """TCP connection from h1 to h2 should work through NAT."""
    passed = True
    h1 = net.get("h1")
    h2 = net.get("h2")

    h2.cmd("pkill -f 'python3 -m http.server' 2>/dev/null; true")
    h2.cmd("python3 -m http.server 9999 --bind %s >/tmp/h2-http-nat.log 2>&1 &" % h2.IP())
    time.sleep(2)

    success = False
    for attempt in range(3):
        result = h1.cmd(
            "curl -sS --connect-timeout 3 -m 4 -o /dev/null -w '%%{http_code}' "
            "http://%s:9999/ 2>/dev/null" % h2.IP()
        ).strip()
        if result.isdigit() and result != "000":
            print("PASS: TCP h1->h2:%s/9999 succeeded (HTTP %s)" % (h2.IP(), result))
            success = True
            break
        time.sleep(2)

    h2.cmd("pkill -f 'python3 -m http.server' 2>/dev/null; true")

    if not success:
        print("FAIL: TCP h1->h2:%s/9999 failed (NAT TCP checksum/connection tracking may need fixing)" % h2.IP())
        passed = False

    return passed


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def run_test():
    passed = True

    topo = NATTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)
    try:
        for h in net.hosts:
            disable_ipv6(h)
        for s in net.switches:
            disable_ipv6(s)

        net.start()
        time.sleep(4)

        print("--- NAT Test 1: Basic connectivity ---")
        if not test_nat_connectivity(net):
            passed = False

        print("--- NAT Test 2: SNAT source IP verification ---")
        if not test_nat_snat(net):
            passed = False

        print("--- NAT Test 3: Bidirectional connectivity ---")
        if not test_nat_bidirectional(net):
            passed = False

        print("--- NAT Test 4: TCP through NAT ---")
        if not test_nat_tcp(net):
            passed = False

        if passed:
            print("\n=== ALL NAT TESTS PASSED ===")
        else:
            print("\n=== SOME NAT TESTS FAILED ===")
    finally:
        net.stop()

    return passed


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
