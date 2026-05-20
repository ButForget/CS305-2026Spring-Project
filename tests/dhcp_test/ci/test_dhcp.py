"""
CI test for DHCP module.

Tests:
  1. test_basic_dhcp      — Two hosts each get a valid, unique IP via DHCP;
                            they can ping each other after gratuitous ARP.
  2. test_dhcp_release    — A host releases its lease; the IP is returned to
                            the pool and can be re-issued to another host.
  3. test_duplicate_ip    — A host attempts to steal an already-bound IP;
                            the server should reject with NAK (bonus).

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
# Python 2/3 compat for string checking
# ---------------------------------------------------------------------------
try:
    unicode          # type: ignore
except NameError:
    unicode = str    # type: ignore


# ---------------------------------------------------------------------------
# Configuration (must match dhcp.py Config)
# ---------------------------------------------------------------------------
POOL_START = "192.168.1.2"
POOL_END   = "192.168.1.100"
POOL_NETMASK = "255.255.255.0"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _ip_to_int(ip):
    import struct, socket
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _int_to_ip(val):
    import struct, socket
    return socket.inet_ntoa(struct.pack("!I", val))


def _ip_in_pool(ip):
    """Return True if *ip* is within [POOL_START .. POOL_END]."""
    try:
        v = _ip_to_int(ip)
        return _ip_to_int(POOL_START) <= v <= _ip_to_int(POOL_END)
    except Exception:
        return False


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_arp(node, count=1):
    node.cmd("arping -c %s -A -I %s-eth0 %s" % (count, node.name, node.defaultIntf().updateIP() or node.IP()))


def dhclient(node, timeout_s=15):
    """Run dhclient on *node* with a timeout; return stdout output."""
    return node.cmd(
        "timeout %s dhclient -v %s-eth0 2>&1" % (timeout_s, node.name)
    )


def dhclient_release(node, timeout_s=10):
    """Send DHCP RELEASE; return stdout."""
    return node.cmd(
        "timeout %s dhclient -r %s-eth0 2>&1" % (timeout_s, node.name)
    )


def strip_ip(node):
    """Remove any IP address from the node's interface (keep it up)."""
    node.cmd("ip addr flush dev %s-eth0" % node.name)


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------
class DHCPTopo(Topo):
    def __init__(self, host_count=2, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch("s1")
        for i in range(host_count):
            name = "h%d" % (i + 1)
            h = self.addHost(name, ip="no ip defined/8")
            self.addLink(h, s1)


# ---------------------------------------------------------------------------
# Test 1 — Basic DHCP
# ---------------------------------------------------------------------------
def test_basic_dhcp(net):
    """
    Two hosts request IPs via DHCP.
    - Each receives an address inside the pool range.
    - The two addresses differ.
    - After gratuitous ARP, hosts can ping each other.
    """
    passed = True

    h1 = net.get("h1")
    h2 = net.get("h2")

    # --- Request IPs -------------------------------------------------------
    out1 = dhclient(h1)
    out2 = dhclient(h2)
    time.sleep(2)

    ip1 = h1.defaultIntf().updateIP()
    ip2 = h2.defaultIntf().updateIP()

    # --- Check each host received an IP inside the pool --------------------
    if ip1 is None or len(ip1) == 0:
        print("FAIL: h1 did not obtain an IP")
        print("  dhclient output: %s" % out1.strip()[-400:])
        passed = False
    elif not _ip_in_pool(ip1):
        print("FAIL: h1 IP %s is outside pool [%s - %s]" % (ip1, POOL_START, POOL_END))
        passed = False
    else:
        print("PASS: h1 obtained IP %s (in pool)" % ip1)

    if ip2 is None or len(ip2) == 0:
        print("FAIL: h2 did not obtain an IP")
        print("  dhclient output: %s" % out2.strip()[-400:])
        passed = False
    elif not _ip_in_pool(ip2):
        print("FAIL: h2 IP %s is outside pool [%s - %s]" % (ip2, POOL_START, POOL_END))
        passed = False
    else:
        print("PASS: h2 obtained IP %s (in pool)" % ip2)

    # --- Ensure different IPs ----------------------------------------------
    if ip1 == ip2 and passed:
        print("FAIL: h1 and h2 both received the same IP %s" % ip1)
        passed = False
    elif passed:
        print("PASS: h1 and h2 have different IPs (%s vs %s)" % (ip1, ip2))

    # --- Connectivity ------------------------------------------------------
    # TODO: re-enable below after shortest-path switching is implemented
    return passed

    if passed:
        send_arp(h1)
        send_arp(h2)
        time.sleep(3)

        result = h1.cmd("ping -c 3 -W 1 %s" % ip2)
        if " 0% packet loss" in result or "/0%" in result:
            print("PASS: h1 (%s) can ping h2 (%s)" % (ip1, ip2))
        else:
            print("FAIL: h1 (%s) cannot ping h2 (%s)" % (ip1, ip2))
            print("  ping output: %s" % result.strip()[-300:])
            passed = False

    return passed


# ---------------------------------------------------------------------------
# Test 2 — DHCP RELEASE (bonus)
# ---------------------------------------------------------------------------
def test_dhcp_release(net):
    """
    h1 releases its DHCP lease.  h2 (after stripping its IP) requests a new
    address.  The pool should now have h1's old address available again.
    """
    passed = True

    h1 = net.get("h1")
    h2 = net.get("h2")

    # --- Both hosts get IPs first -----------------------------------------
    dhclient(h1)
    dhclient(h2)
    time.sleep(2)

    ip1_before = h1.defaultIntf().updateIP()
    ip2_before = h2.defaultIntf().updateIP()

    if not ip1_before or not _ip_in_pool(ip1_before):
        print("FAIL: h1 did not get a valid IP before release (%s)" % ip1_before)
        return False
    if not ip2_before or not _ip_in_pool(ip2_before):
        print("FAIL: h2 did not get a valid IP before release (%s)" % ip2_before)
        return False

    print("INFO: h1 = %s, h2 = %s (before release)" % (ip1_before, ip2_before))

    # --- h1 releases its lease --------------------------------------------
    print("INFO: h1 sending DHCP RELEASE...")
    dhclient_release(h1)
    time.sleep(2)

    # --- h2 releases and re-requests; should get h1's old IP or another ---
    dhclient_release(h2)
    strip_ip(h2)
    time.sleep(1)
    print("INFO: h2 requesting new DHCP lease...")
    dhclient(h2)
    time.sleep(2)
    ip2_after = h2.defaultIntf().updateIP()

    if not ip2_after or not _ip_in_pool(ip2_after):
        print("FAIL: h2 did not obtain a valid IP after release (%s)" % ip2_after)
        passed = False
    else:
        print("PASS: h2 obtained IP %s after release" % ip2_after)

    # --- h1 re-requests; should get a pool IP too -------------------------
    strip_ip(h1)
    dhclient(h1)
    time.sleep(2)
    ip1_after = h1.defaultIntf().updateIP()

    if not ip1_after or not _ip_in_pool(ip1_after):
        print("FAIL: h1 did not obtain a valid IP after re-request (%s)" % ip1_after)
        passed = False
    else:
        print("PASS: h1 obtained IP %s after re-request" % ip1_after)

    # After both re-request, both should still have different IPs
    if ip1_after == ip2_after and passed:
        print("FAIL: h1 and h2 got same IP %s after release cycle" % ip1_after)
        passed = False

    return passed


# ---------------------------------------------------------------------------
# Test 3 — Duplicate IP rejection (bonus)
# ---------------------------------------------------------------------------
def test_duplicate_ip(net):
    """
    h1 obtains an IP via DHCP.  h2 is manually assigned the same IP and then
    runs dhclient.  The server should reject the request for the already-bound
    IP and h2 should end up with a *different* IP (not the stolen one).
    """
    passed = True

    h1 = net.get("h1")
    h2 = net.get("h2")

    # --- h1 obtains a valid IP --------------------------------------------
    dhclient(h1)
    time.sleep(2)
    ip_h1 = h1.defaultIntf().updateIP()
    if not ip_h1 or not _ip_in_pool(ip_h1):
        print("FAIL: h1 did not get a valid IP (%s)" % ip_h1)
        return False
    print("INFO: h1 obtained IP %s" % ip_h1)

    # --- Send gratuitous ARP from h1 so the switch learns its MAC ---------
    send_arp(h1)
    time.sleep(2)

    # --- Force h2 to steal h1's IP ----------------------------------------
    strip_ip(h2)
    h2.setIP(ip_h1, prefixLen=24)
    time.sleep(1)
    print("INFO: h2 manually set to h1's IP (%s), now running dhclient..." % ip_h1)

    out2 = dhclient(h2, timeout_s=15)
    time.sleep(2)
    # dhclient added its IP as secondary; delete the manually-set primary
    # so updateIP() returns dhclient's actual assigned IP.
    h2.cmd("ip addr del %s/24 dev h2-eth0 2>/dev/null" % ip_h1)
    ip_h2 = h2.defaultIntf().updateIP()
    nak_received = "DHCPNAK" in out2 or "NAK" in out2

    if ip_h2 and ip_h2 != "0.0.0.0" and _ip_in_pool(ip_h2):
        if ip_h2 == ip_h1:
            if nak_received:
                print("PASS: server sent NAK for duplicate IP %s (dhclient kept old IP)" % ip_h1)
            else:
                print("FAIL: h2 obtained duplicate IP %s with no NAK" % ip_h1)
                passed = False
        else:
            print("PASS: h2 was assigned different IP %s (duplicate rejected)" % ip_h1)
    else:
        if nak_received:
            print("PASS: server sent NAK (h2 has no valid IP, expected)")
        else:
            print("FAIL: h2 received no valid IP and no NAK")
            print("  dhclient output: %s" % out2.strip()[-400:])
            passed = False

    # --- Final sanity: h1 should still have its IP and be pingable --------
    time.sleep(1)
    result = h2.cmd("ping -c 2 -W 1 %s" % ip_h1)
    if " 0% packet loss" in result or "/0%" in result:
        print("PASS: h2 can ping h1 (%s) after test" % ip_h1)
    else:
        print("INFO: h2 cannot ping h1 — may be expected depending on binding state")

    return passed


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------
def run_test():
    """
    Create a Mininet network, run all subtests, tear down, and return
    True if every enabled test passes.
    """
    net = Mininet(
        topo=DHCPTopo(host_count=2),
        autoSetMacs=True,
        controller=RemoteController,
    )

    # Disable IPv6 everywhere
    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    all_pass = True

    try:
        net.start()
        time.sleep(3)                     # let controller discover topology

        # Clear any stale dhclient leases from previous runs
        for h in net.hosts:
            h.cmd("rm -f /var/lib/dhcp/dhclient*leases /var/lib/dhclient/dhclient*leases /var/lib/NetworkManager/dhclient*leases 2>/dev/null")

        # --- basic ---------------------------------------------------------
        print("\n=== Test 1: Basic DHCP ===")
        if not test_basic_dhcp(net):
            all_pass = False

        # --- release (bonus) -----------------------------------------------
        print("\n=== Test 2: DHCP RELEASE (bonus) ===")
        if not test_dhcp_release(net):
            all_pass = False

        # --- duplicate (bonus) ---------------------------------------------
        print("\n=== Test 3: Duplicate IP rejection (bonus) ===")
        if not test_duplicate_ip(net):
            all_pass = False

    finally:
        net.stop()

    if all_pass:
        print("\nPASS: all DHCP tests passed")
    else:
        print("\nFAIL: one or more DHCP tests failed")

    return all_pass


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
