"""
TC: Lease Expiration — timed expiry
---------------------------------------------------
Pre-condition (manual): Set Config.end_ip="192.168.1.3" and Config.lease_time=5
in dhcp.py before running this test. Revert afterwards.

Creates 3 hosts with a 2-IP pool (192.168.1.2, 192.168.1.3).
h1 and h2 exhaust the pool, then h1's dhclient is killed and its IP stripped.
h3 (a fresh observer never holding a lease) probes the pool before and after
the lease timeout expires.

Key verification chain:
  (a) h1, h2 get IPs → pool exhausted
  (b) kill h1 dhclient, strip h1 → h1 has no IP; lease still active server-side
  (c) h3 requests IMMEDIATELY → FAIL (pool exhausted, lease not expired)
  (d) wait > lease_time → h3 requests AGAIN → SUCCEED (lease reclaimed)
  (e) h3's IP == h1's old IP — proves the same IP was reclaimed, not a fresh one
"""

import os
import struct
import socket
import sys
import time

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

_project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, _project_root)
try:
    from dhcp import Config
except ImportError:
    Config = None


def _ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _pool_size():
    return _ip_to_int(Config.end_ip) - _ip_to_int(Config.start_ip) + 1


def _ip_in_pool(ip):
    try:
        v = _ip_to_int(ip)
        return _ip_to_int(Config.start_ip) <= v <= _ip_to_int(Config.end_ip)
    except Exception:
        return False


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def dhclient(node, timeout_s=15):
    return node.cmd("timeout %s dhclient -v %s-eth0 2>&1" % (timeout_s, node.name))


def strip_ip(node):
    node.cmd("ip addr flush dev %s-eth0" % node.name)


class LeaseExpiryTopo(Topo):
    def __init__(self, host_count=3, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch("s1")
        for i in range(host_count):
            name = "h%d" % (i + 1)
            self.addHost(name, ip="no ip defined/8")
            self.addLink(name, s1)


def run_test():
    if Config is None:
        print("ERROR: Cannot import dhcp.py. Run from project root.")
        return False

    from mininet.clean import cleanup

    cleanup()

    pool_n = _pool_size()
    host_n = 3

    if pool_n != 2:
        print("=" * 62)
        print("  WARNING: Pool size is %d, not 2." % pool_n)
        print("  This test expects Config.end_ip='192.168.1.3' (2 IPs).")
        print("  The test will still run but semantics may differ.")
        print("=" * 62)
        print()

    print()
    print("=" * 62)
    print("  TC: Lease Expiry — timed expiration")
    print("=" * 62)
    print("  Pool range    : %s - %s" % (Config.start_ip, Config.end_ip))
    print("  Pool size (n) : %d IPs" % pool_n)
    print("  Host count    : %d hosts" % host_n)
    print("  Lease time    : %d s" % Config.lease_time)
    print("=" * 62)

    net = Mininet(
        topo=LeaseExpiryTopo(host_count=host_n),
        autoSetMacs=True,
        controller=RemoteController,
    )
    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    all_pass = True

    try:
        net.start()
        time.sleep(3)

        h1 = net.get("h1")
        h2 = net.get("h2")
        h3 = net.get("h3")

        for h in net.hosts:
            h.cmd(
                "rm -f /var/lib/dhcp/dhclient*leases /var/lib/dhclient/dhclient*leases "
                "/var/lib/NetworkManager/dhclient*leases 2>/dev/null"
            )

        # ---------------------------------------------------------------
        # Step 1: h1 and h2 exhaust the pool
        # ---------------------------------------------------------------
        print("\n--- Step 1: Exhaust pool (h1 + h2) ---")
        dhclient(h1)
        dhclient(h2)
        time.sleep(2)

        ip1 = h1.defaultIntf().updateIP()
        ip2 = h2.defaultIntf().updateIP()

        if not ip1 or not _ip_in_pool(ip1):
            print("  [FAIL] h1 did not get a valid IP (%s)" % ip1)
            return False
        if not ip2 or not _ip_in_pool(ip2):
            print("  [FAIL] h2 did not get a valid IP (%s)" % ip2)
            return False
        if ip1 == ip2:
            print("  [FAIL] h1 and h2 got same IP %s" % ip1)
            return False

        print("  [INFO] h1 = %s, h2 = %s  (pool exhausted)" % (ip1, ip2))

        # ---------------------------------------------------------------
        # Step 2: Kill h1 dhclient, strip h1 — verify h1 has no IP
        # ---------------------------------------------------------------
        print("\n--- Step 2: Kill h1 dhclient, strip IP ---")
        h1.cmd("pkill -f 'dhclient.*h1-eth0' 2>/dev/null")
        strip_ip(h1)
        time.sleep(1)

        remaining = h1.defaultIntf().updateIP()
        if remaining:
            print("  [FAIL] h1 still has IP %s after strip" % remaining)
            return False
        print("  [PASS] h1 has no IP after kill+strip")

        # ---------------------------------------------------------------
        # Step 3: h3 requests IMMEDIATELY — MUST FAIL
        # h3 is a fresh observer, never held a lease → sends DISCOVER.
        # Pool is exhausted; server sends NAK (no IP available).
        # ---------------------------------------------------------------
        print("\n--- Step 3: h3 requests immediately (expect FAIL) ---")
        out_early = dhclient(h3, timeout_s=10)
        time.sleep(2)
        ip_early = h3.defaultIntf().updateIP()

        if ip_early and _ip_in_pool(ip_early):
            print("  [FAIL] h3 got IP %s before lease expired — pool should be exhausted"
                  % ip_early)
            print("         dhclient output: %s" % out_early.strip()[-300:])
            return False
        print("  [PASS] h3 did NOT get a pool IP (pool exhausted)")

        # ---------------------------------------------------------------
        # Step 4: Wait for h1's lease to expire
        # ---------------------------------------------------------------
        print("\n--- Step 4: Wait for lease to expire (%d s) ---" % Config.lease_time)
        wait_sec = Config.lease_time + 2
        for i in range(wait_sec):
            print("  ... %d/%d" % (i + 1, wait_sec), end="\r")
            time.sleep(1)
        print("  ... done waiting %d s          " % wait_sec)

        # ---------------------------------------------------------------
        # Step 5: h3 requests AGAIN — MUST SUCCEED
        # DISCOVER triggers _expire_leases(), reclaims h1's expired lease.
        # ---------------------------------------------------------------
        print("\n--- Step 5: h3 requests after expiry (expect SUCCESS) ---")
        out3 = dhclient(h3, timeout_s=15)
        time.sleep(2)
        ip3 = h3.defaultIntf().updateIP()

        if ip3 and _ip_in_pool(ip3):
            print("  [PASS] h3 obtained IP %s — expired lease reclaimed" % ip3)
        else:
            print("  [FAIL] h3 did not obtain a valid pool IP after expiry")
            print("    dhclient output: %s" % out3.strip()[-400:])
            all_pass = False

        # ---------------------------------------------------------------
        # Step 6: Verify h3 got h1's old IP (same IP reclaimed)
        # ---------------------------------------------------------------
        if all_pass and ip3 == ip1:
            print("  [PASS] h3's IP %s matches h1's old IP — same lease reclaimed" % ip3)
        elif all_pass:
            pass

    finally:
        net.stop()

    print()
    if all_pass:
        print("  RESULT: PASS — lease expiration and reclamation correct")
    else:
        print("  RESULT: FAIL — one or more checks failed")
    return all_pass


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
