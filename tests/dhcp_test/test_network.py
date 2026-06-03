import os
import struct
import socket
import sys
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

_project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, _project_root)
try:
    from dhcp import Config
except ImportError:
    Config = None

test_results = []


def _ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]


def _int_to_ip(val):
    return socket.inet_ntoa(struct.pack("!I", val))


def _ip_in_pool(ip):
    if Config is None:
        return True
    try:
        v = _ip_to_int(ip)
        return _ip_to_int(Config.start_ip) <= v <= _ip_to_int(Config.end_ip)
    except Exception:
        return False


def record(test_name, passed, detail=""):
    label = "PASS" if passed else "FAIL"
    msg = f"  [{label}] {test_name}"
    if detail:
        msg += f"  ({detail})"
    print(msg)
    test_results.append((test_name, passed, detail))


def section(title):
    print()
    print("=" * 62)
    print(f"  {title}")
    print("=" * 62)


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_arp(node, count=1):
    node.cmd("arping -c %s -A -I %s-eth0 %s"
             % (count, node.name, node.defaultIntf().updateIP() or node.IP()))


def dhclient(node, timeout_s=15):
    return node.cmd("timeout %s dhclient -v %s-eth0 2>&1" % (timeout_s, node.name))


def dhclient_release(node, timeout_s=10):
    return node.cmd("timeout %s dhclient -r %s-eth0 2>&1" % (timeout_s, node.name))


def strip_ip(node):
    node.cmd("ip addr flush dev %s-eth0" % node.name)


class TestTopo(Topo):
    def __init__(self, host_count=3, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch("s1")
        for i in range(host_count):
            name = "h%d" % (i + 1)
            self.addHost(name, ip="no ip defined/8")
            self.addLink(name, s1)


def demo_tc1_basic(net):
    """TC1: Default config, 3 hosts — all get valid unique IPs."""
    hosts = sorted(net.hosts, key=lambda h: h.name)

    for h in hosts:
        dhclient(h)
    time.sleep(2)

    ips = []
    all_pass = True
    for h in hosts:
        ip = h.defaultIntf().updateIP()
        ips.append(ip)
        in_pool = _ip_in_pool(ip) if ip else False
        detail = f"{h.name} IP={ip}"
        record(detail, bool(ip and in_pool), "" if (ip and in_pool) else "outside pool or no IP")
        if not (ip and in_pool):
            all_pass = False

    unique = len(set(i for i in ips if i)) == len(ips)
    record("All hosts have unique IPs", unique)

    return all_pass and unique


def demo_tc4_release(net):
    """TC4 (Bonus): h1 releases IP → pool reclaims → h1/h2 re-request OK."""
    h1 = net.get("h1")
    h2 = net.get("h2")

    dhclient(h1)
    dhclient(h2)
    time.sleep(2)
    ip1_before = h1.defaultIntf().updateIP()
    ip2_before = h2.defaultIntf().updateIP()

    if not ip1_before or not _ip_in_pool(ip1_before):
        record("h1 pre-check for RELEASE", False, f"IP={ip1_before}")
        return False
    if not ip2_before or not _ip_in_pool(ip2_before):
        record("h2 pre-check for RELEASE", False, f"IP={ip2_before}")
        return False

    record(f"h1 IP before release = {ip1_before}", True)
    record(f"h2 IP before release = {ip2_before}", True)

    dhclient_release(h1)
    time.sleep(2)

    dhclient_release(h2)
    strip_ip(h2)
    time.sleep(1)
    dhclient(h2)
    time.sleep(2)
    ip2_after = h2.defaultIntf().updateIP()
    record(f"h2 re-request after release", bool(ip2_after and _ip_in_pool(ip2_after)),
           f"IP={ip2_after}")

    strip_ip(h1)
    dhclient(h1)
    time.sleep(2)
    ip1_after = h1.defaultIntf().updateIP()
    record(f"h1 re-request after release", bool(ip1_after and _ip_in_pool(ip1_after)),
           f"IP={ip1_after}")

    distinct = ip1_after != ip2_after
    record("Both hosts have distinct IPs after release cycle", distinct,
           f"h1={ip1_after} h2={ip2_after}")
    return distinct


def demo_tc5_duplicate(net):
    """TC5 (Bonus): h2 steals h1's IP → server NAKs, h2 gets different IP."""
    h1 = net.get("h1")
    h2 = net.get("h2")

    strip_ip(h1)
    strip_ip(h2)
    dhclient(h1)
    time.sleep(2)
    ip_h1 = h1.defaultIntf().updateIP()
    if not ip_h1 or not _ip_in_pool(ip_h1):
        record("h1 pre-check for duplicate", False, f"IP={ip_h1}")
        return False
    record(f"h1 obtained IP = {ip_h1}", True)

    send_arp(h1)
    time.sleep(2)

    strip_ip(h2)
    h2.setIP(ip_h1, prefixLen=24)
    time.sleep(1)
    out2 = dhclient(h2)
    time.sleep(2)
    h2.cmd("ip addr del %s/24 dev h2-eth0 2>/dev/null" % ip_h1)
    ip_h2 = h2.defaultIntf().updateIP()

    if ip_h2 and ip_h2 != ip_h1 and _ip_in_pool(ip_h2):
        record(f"h2 gets different IP (duplicate rejected)", True, f"h2 IP={ip_h2}")
    elif ip_h2 == ip_h1:
        record(f"h2 stole same IP {ip_h1}", False, "duplicate NOT rejected")
        return False
    else:
        record(f"h2 IP check", False, f"IP={ip_h2}")

    send_arp(h1)
    send_arp(h2)
    time.sleep(2)
    result = h2.cmd("ping -c 2 -W 1 %s" % ip_h1)
    ping_ok = " 0% packet loss" in result
    record("h2 can ping h1 after test", ping_ok, "may not apply depending on binding state")
    return True


def print_summary():
    print()
    print("=" * 62)
    print("  TEST SUMMARY")
    print("=" * 62)
    passed = 0
    failed = 0
    for name, ok, detail in test_results:
        status = "PASS" if ok else "FAIL"
        line = f"  [{status}] {name}"
        if detail:
            line += f"  ({detail})"
        print(line)
        if ok:
            passed += 1
        else:
            failed += 1
    print("-" * 62)
    print(f"  PASS: {passed}   FAIL: {failed}")
    print("=" * 62)
    return failed == 0


def run_mininet():
    topo = TestTopo(host_count=3)
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)
    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)

    for h in net.hosts:
        h.cmd("rm -f /var/lib/dhcp/dhclient*leases /var/lib/dhclient/dhclient*leases /var/lib/NetworkManager/dhclient*leases 2>/dev/null")

    section("TC1: Basic DHCP — default config, 3 hosts")
    demo_tc1_basic(net)

    section("TC4 (Bonus): DHCP RELEASE — IP reclamation")
    demo_tc4_release(net)

    section("TC5 (Bonus): Duplicate IP — NAK rejection")
    demo_tc5_duplicate(net)

    section("")
    all_pass = print_summary()

    print()
    print("Entering Mininet CLI for manual exploration. Type 'exit' to finish.")
    print('Try: h1 dhclient -v h1-eth0   /   h1 ping h2   /   h1 arping -c1 -A -I h1-eth0 <IP>')
    CLI(net)

    net.stop()
    return all_pass


if __name__ == "__main__":
    setLogLevel("info")
    ok = run_mininet()
    sys.exit(0 if ok else 1)
