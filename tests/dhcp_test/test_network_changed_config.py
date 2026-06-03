"""
TC2: Changed DHCP config (start_ip, end_ip, netmask)
------------------------------------------------------
The presenter must edit dhcp.py Config BEFORE starting the controller,
then run this script. It reads Config from dhcp.py, creates 3 hosts,
runs dhclient on each, and validates all get IPs in the new range.
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


def _ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _ip_in_pool(ip):
    try:
        v = _ip_to_int(ip)
        return _ip_to_int(Config.start_ip) <= v <= _ip_to_int(Config.end_ip)
    except Exception:
        return False


def _pool_size():
    try:
        return _ip_to_int(Config.end_ip) - _ip_to_int(Config.start_ip) + 1
    except Exception:
        return 0


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def dhclient(node, timeout_s=15):
    return node.cmd("timeout %s dhclient -v %s-eth0 2>&1" % (timeout_s, node.name))


def wait_for_ip(node, timeout_s=10):
    for _ in range(int(timeout_s * 2)):
        ip = node.defaultIntf().updateIP()
        if ip:
            return ip
        time.sleep(0.5)
    return None


class ChangedConfigTopo(Topo):
    def __init__(self, host_count=3, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch("s1")
        for i in range(host_count):
            name = "h%d" % (i + 1)
            self.addHost(name, ip="no ip defined/8")
            self.addLink(name, s1)


def run_test():
    pool_n = _pool_size()
    host_count = min(3, max(1, pool_n))
    skip_uniqueness = pool_n < 2

    print()
    print("=" * 62)
    print("  TC2: Changed DHCP Config")
    print("=" * 62)
    print(f"  Current Config from dhcp.py:")
    print(f"    start_ip  = {Config.start_ip}")
    print(f"    end_ip    = {Config.end_ip}")
    print(f"    netmask   = {Config.netmask}")
    print(f"    IP range  = {Config.start_ip} - {Config.end_ip}")
    print(f"    Pool size = {pool_n} IPs")
    if pool_n < 3:
        print(f"  NOTE: Pool has only {pool_n} IPs; testing with {host_count} hosts.")
    if skip_uniqueness:
        print(f"  NOTE: Single-IP pool — skipping uniqueness check.")
    print("=" * 62)
    print("  !! IMPORTANT: Restart osken-manager after editing dhcp.py Config.")
    print("  !! If controller was not restarted, results below are INVALID.")
    print("=" * 62)

    from mininet.clean import cleanup
    cleanup()

    net = Mininet(
        topo=ChangedConfigTopo(host_count=host_count),
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

        hosts = sorted(net.hosts, key=lambda h: h.name)
        ips = {}
        for h in hosts:
            dhclient(h)
            wait_for_ip(h)

        for h in hosts:
            ip = h.defaultIntf().updateIP()
            ips[h.name] = ip
            in_pool = _ip_in_pool(ip) if ip else False
            if ip and in_pool:
                print(f"  [PASS] {h.name} IP = {ip}  (in pool)")
            else:
                print(f"  [FAIL] {h.name} IP = {ip}  (NOT in pool or no IP)")
                all_pass = False

        if not skip_uniqueness:
            ip_list = [v for v in ips.values() if v]
            if len(set(ip_list)) == len(ip_list):
                print(f"  [PASS] All {len(ip_list)} hosts have unique IPs")
            else:
                print(f"  [FAIL] Duplicate IPs detected: {ip_list}")
                all_pass = False

    finally:
        net.stop()

    print()
    if all_pass:
        print("  RESULT: PASS — all hosts got valid IPs in the changed range")
    else:
        print("  RESULT: FAIL — one or more checks failed")
    return all_pass


if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
