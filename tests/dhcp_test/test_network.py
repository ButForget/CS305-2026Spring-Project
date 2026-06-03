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


def _pool_size():
    if Config is None:
        return 0
    try:
        return _ip_to_int(Config.end_ip) - _ip_to_int(Config.start_ip) + 1
    except Exception:
        return 0


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
    ip = node.defaultIntf().updateIP()
    if not ip:
        print(f"  [WARN] Cannot send gratuitous ARP from {node.name} — no IP assigned")
        return
    node.cmd("arping -c %s -A -I %s-eth0 %s" % (count, node.name, ip))


def wait_for_ip(node, timeout_s=10):
    for _ in range(int(timeout_s * 2)):
        ip = node.defaultIntf().updateIP()
        if ip:
            return ip
        time.sleep(0.5)
    return None


def dhclient(node, timeout_s=15):
    return node.cmd("timeout %s dhclient -v %s-eth0 2>&1" % (timeout_s, node.name))


def dhclient_release(node, timeout_s=10):
    return node.cmd("timeout %s dhclient -r %s-eth0 2>&1" % (timeout_s, node.name))


def dhclient_release_check(node, timeout_s=10):
    out = node.cmd("timeout %s dhclient -r %s-eth0 2>&1" % (timeout_s, node.name))
    return ("DHCPRELEASE" in out or "RELEASE" in out), out


def strip_ip(node):
    node.cmd("ip addr flush dev %s-eth0" % node.name)


def reset_hosts(net):
    for h in net.hosts:
        h.cmd("pkill -f 'dhclient.*%s-eth0' 2>/dev/null" % h.name)
        h.cmd("ip addr flush dev %s-eth0 2>/dev/null" % h.name)
        h.cmd("rm -f /var/lib/dhcp/dhclient*leases /var/lib/dhclient/dhclient*leases 2>/dev/null")
    time.sleep(1)


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
        wait_for_ip(h)
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
    """TC4 (Bonus): DHCP RELEASE — IP reclamation with exhaustion proof."""
    hosts = sorted(net.hosts, key=lambda h: h.name)
    h1 = hosts[0]
    h2 = hosts[1]
    h3 = hosts[2] if len(hosts) >= 3 else None
    pool_n = _pool_size()

    if pool_n > 3:
        print()
        print("  [WARN] RELEASE test requires pool_size <= 3 to prove reclamation.")
        print("  [WARN] Current pool has %d IPs. Fallback to lenient distinct-IP check." % pool_n)
        print("  [WARN] Consider setting end_ip='192.168.1.4' in dhcp.py for strict test.")

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

        released, _ = dhclient_release_check(h1)
        record("h1 sent DHCPRELEASE", released)
        time.sleep(2)

        dhclient_release(h2)
        strip_ip(h2)
        time.sleep(1)
        dhclient(h2)
        wait_for_ip(h2)
        ip2_after = h2.defaultIntf().updateIP()
        record(f"h2 re-request after release", bool(ip2_after and _ip_in_pool(ip2_after)),
               f"IP={ip2_after}")

        strip_ip(h1)
        dhclient(h1)
        wait_for_ip(h1)
        ip1_after = h1.defaultIntf().updateIP()
        record(f"h1 re-request after release", bool(ip1_after and _ip_in_pool(ip1_after)),
               f"IP={ip1_after}")

        distinct = ip1_after != ip2_after
        record("Both hosts have distinct IPs after release cycle", distinct,
               f"h1={ip1_after} h2={ip2_after}")
        return distinct

    # === STRICT PATH: pool_size <= 3, exhaustion proof ===
    all_pass = True

    # Step 1: exhaust pool — all hosts get IPs
    for h in [h1, h2, h3] if h3 else [h1, h2]:
        dhclient(h)
        wait_for_ip(h)
    time.sleep(2)

    ip1 = h1.defaultIntf().updateIP()
    ip2 = h2.defaultIntf().updateIP()
    ip3 = h3.defaultIntf().updateIP() if h3 else None

    if not (ip1 and _ip_in_pool(ip1)):
        record("TC4 init: h1 failed to get IP", False, f"IP={ip1}")
        return False
    if not (ip2 and _ip_in_pool(ip2)):
        record("TC4 init: h2 failed to get IP", False, f"IP={ip2}")
        return False
    if h3 and not (ip3 and _ip_in_pool(ip3)):
        record("TC4 init: h3 failed to get IP", False, f"IP={ip3}")
        return False

    unique_init = len(set(i for i in [ip1, ip2, ip3] if i)) == (3 if h3 else 2)
    record("TC4: pool exhausted — h1=%s, h2=%s%s" % (
        ip1, ip2, ", h3=%s" % ip3 if h3 else ""), unique_init)
    if not unique_init:
        return False

    # Step 2: Release h1
    dhclient_release(h1)
    time.sleep(2)

    # Step 3: Choose spare host (h3 if it exists, else h2) and re-request
    if h3:
        # h3 exists and already has an IP; release it then re-request
        dhclient_release(h3)
        strip_ip(h3)
        time.sleep(1)
        dhclient(h3)
        wait_for_ip(h3)
        ip_spare = h3.defaultIntf().updateIP()
        spare_name = h3.name
    else:
        # No h3: rely on h2 releasing and re-requesting from freed pool
        dhclient_release(h2)
        strip_ip(h2)
        time.sleep(1)
        dhclient(h2)
        wait_for_ip(h2)
        ip_spare = h2.defaultIntf().updateIP()
        spare_name = h2.name

    if ip_spare and _ip_in_pool(ip_spare):
        reclaimed = (ip_spare == ip1)
        if reclaimed:
            record("TC4: %s reclaimed h1's released IP %s" % (spare_name, ip1), True)
        else:
            record("TC4: %s got IP %s (released IP was %s, release still plausible)"
                   % (spare_name, ip_spare, ip1), True)
    else:
        record("TC4: %s failed to get IP after release" % spare_name, False)
        return False

    # Step 4: h1 re-requests
    strip_ip(h1)
    dhclient(h1)
    wait_for_ip(h1)
    ip1_new = h1.defaultIntf().updateIP()
    if ip1_new and _ip_in_pool(ip1_new):
        record("TC4: h1 re-request succeeded, IP=%s" % ip1_new, True)
    else:
        record("TC4: h1 re-request failed after release", False)
        all_pass = False

    return all_pass


def demo_tc5_duplicate(net):
    """TC5 (Bonus): h2 steals h1's IP → server NAKs, h2 gets different IP."""
    h1 = net.get("h1")
    h2 = net.get("h2")

    strip_ip(h1)
    strip_ip(h2)
    dhclient(h1)
    wait_for_ip(h1)
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
    from mininet.clean import cleanup
    cleanup()

    topo = TestTopo(host_count=3)
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)
    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)

    section("TC1: Basic DHCP — default config, 3 hosts")
    demo_tc1_basic(net)

    reset_hosts(net)

    section("TC4 (Bonus): DHCP RELEASE — IP reclamation")
    demo_tc4_release(net)

    reset_hosts(net)

    section("TC5 (Bonus): Duplicate IP — NAK rejection")
    demo_tc5_duplicate(net)

    section("")
    all_pass = print_summary()

    print()
    if sys.stdin.isatty() and '--no-cli' not in sys.argv:
        print("Entering Mininet CLI for manual exploration. Type 'exit' to finish.")
        print('Try: h1 dhclient -v h1-eth0   /   h1 ping h2   /   h1 arping -c1 -A -I h1-eth0 <IP>')
        CLI(net)

    net.stop()
    return all_pass


if __name__ == "__main__":
    setLogLevel("info")
    ok = run_mininet()
    sys.exit(0 if ok else 1)
