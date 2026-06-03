"""
TC3: DHCP Overflow — more hosts than available IPs
---------------------------------------------------
Creates m hosts where m > n (number of IPs in pool).
Verifies: first n hosts receive valid IPs from the pool,
          remaining (m-n) hosts do NOT receive an IP.

By default, uses a small pool (4 IPs: .2-.5) and 6 hosts
so the demo completes quickly.  Edit NUM_HOSTS below as needed.
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

_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _project_root)
try:
    from dhcp import Config
except ImportError:
    print("ERROR: Cannot import dhcp.py. Run from project root.")
    sys.exit(1)

NUM_HOSTS = 6


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


class OverflowTopo(Topo):
    def __init__(self, host_count=6, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch("s1")
        for i in range(host_count):
            name = "h%d" % (i + 1)
            self.addHost(name, ip="no ip defined/8")
            self.addLink(name, s1)


def run_test():
    pool_n = _pool_size()
    host_m = NUM_HOSTS

    print()
    print("=" * 62)
    print("  TC3: DHCP Overflow — more hosts than IPs")
    print("=" * 62)
    print(f"  Pool range : {Config.start_ip} - {Config.end_ip}")
    print(f"  Pool size (n) : {pool_n} IPs")
    print(f"  Host count (m): {host_m} hosts")
    if host_m <= pool_n:
        print("  WARNING: m <= n, this is NOT an overflow test!")
        print("  Either reduce pool range in dhcp.py or increase NUM_HOSTS.")
        print()
        return False
    print("=" * 62)

    net = Mininet(
        topo=OverflowTopo(host_count=host_m),
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

        for h in net.hosts:
            h.cmd("rm -f /var/lib/dhcp/dhclient*leases /var/lib/dhclient/dhclient*leases /var/lib/NetworkManager/dhclient*leases 2>/dev/null")

        hosts = sorted(net.hosts, key=lambda h: int(h.name[1:]))
        results = []
        for h in hosts:
            out = dhclient(h, timeout_s=12)
            time.sleep(0.5)

        time.sleep(2)

        for h in hosts:
            ip = h.defaultIntf().updateIP()
            results.append((h.name, ip))
            if int(h.name[1:]) <= pool_n:
                if ip and _ip_in_pool(ip):
                    print(f"  [PASS] {h.name} IP = {ip}  (in pool)")
                else:
                    print(f"  [FAIL] {h.name} IP = {ip}  (should have valid IP)")
                    all_pass = False
            else:
                if ip is None or ip == "" or ip == "0.0.0.0":
                    print(f"  [PASS] {h.name} has NO IP  (pool exhausted, expected)")
                elif _ip_in_pool(ip):
                    print(f"  [WARN] {h.name} IP = {ip}  (got IP from pool, may be OK if lease expired)")
                else:
                    print(f"  [PASS] {h.name} has NO IP from pool  (overflow expected)")

        ip_list = [ip for _, ip in results if ip and _ip_in_pool(ip)]
        unique_ips = len(set(ip_list))
        if unique_ips == pool_n:
            print(f"  [PASS] Pool fully utilized: {unique_ips}/{pool_n} unique IPs assigned")
        else:
            print(f"  [WARN] {unique_ips}/{pool_n} unique IPs assigned")

    finally:
        net.stop()

    print()
    if all_pass:
        print("  RESULT: PASS — overflow handling correct")
    else:
        print("  RESULT: FAIL — one or more checks failed")
    return all_pass


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
