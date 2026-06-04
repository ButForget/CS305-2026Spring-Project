# test_network_nat_multi.py
# Multi-host NAT test: four internal hosts share one NAT IP,
# three external hosts distinguish them by translated port.
#
# Topology:
#   h1 (10.0.1.2) ─┐
#   h2 (10.0.1.3) ─┤
#   h3 (10.0.1.4) ─┤── s1 ── s2 ──┬── h5 (10.0.2.2)
#   h4 (10.0.1.5) ─┘              ├── h6 (10.0.2.3)
#   (internal)                     └── h7 (10.0.2.4)
#                                      (external)
#
# Usage:
#   1. Start controller:  osken-manager --observe-links controller.py
#   2. Run this script:   sudo env "PATH=$PATH" python test_network_nat_multi.py

import time
import re

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


NAT_EXTERNAL_IP = "10.0.2.100"

# Host IPs
INTERNAL_HOSTS = {
    'h1': '10.0.1.2/16',
    'h2': '10.0.1.3/16',
    'h3': '10.0.1.4/16',
    'h4': '10.0.1.5/16',
}
EXTERNAL_HOSTS = {
    'h5': '10.0.2.2/16',
    'h6': '10.0.2.3/16',
    'h7': '10.0.2.4/16',
}


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host, count=2):
    intf = host.defaultIntf().name
    host.cmd("arping -c %d -A -I %s %s" % (count, intf, host.IP()))


def ping_ok(src, dst_ip, count=3, timeout=2):
    result = src.cmd("ping -c %d -W %d %s" % (count, timeout, dst_ip))
    return ' 0% packet loss' in result or bool(re.search(r'[1-9]\d* received', result))


def run_one_test(label, ok):
    print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    return ok


def snat_client_ip(internal_host, external_host, port):
    """internal_host connects via curl to external_host's TCP server.
    Returns the source IP:port seen by external_host (after SNAT)."""
    server_script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('', %d))\n"
        "s.listen(1)\n"
        "s.settimeout(8)\n"
        "try:\n"
        "    conn, addr = s.accept()\n"
        "    print(addr[0] + ':' + str(addr[1]))\n"
        "    conn.send(b'HTTP/1.0 200 OK\\r\\n\\r\\nOK')\n"
        "    conn.close()\n"
        "except socket.timeout:\n"
        "    print('TIMEOUT')\n"
        "finally:\n"
        "    s.close()\n" % port
    )
    external_host.cmd("echo '%s' > /tmp/srv.py" % server_script.replace("'", "'\"'\"'"))
    external_host.cmd("python3 /tmp/srv.py > /tmp/out.txt 2>/dev/null &")
    time.sleep(0.5)
    # Client runs on internal_host, connecting to external_host
    internal_host.cmd(
        "curl -sS --connect-timeout 3 -m 5 http://%s:%d/ 2>/dev/null" % (external_host.IP(), port))
    time.sleep(5)
    result = external_host.cmd("cat /tmp/out.txt 2>/dev/null").strip()
    external_host.cmd("pkill -f srv.py 2>/dev/null; true")
    external_host.cmd("rm -f /tmp/srv.py /tmp/out.txt")
    return result


class MultiNATTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        # 4 internal hosts
        for name, ip in INTERNAL_HOSTS.items():
            self.addHost(name, ip=ip)
            self.addLink(name, s1)
        # 3 external hosts
        for name, ip in EXTERNAL_HOSTS.items():
            self.addHost(name, ip=ip)
            self.addLink(name, s2)
        self.addLink(s1, s2)


def run_mininet():
    topo = MultiNATTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)
    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)
    net.start()
    time.sleep(2)

    internal_hosts = [net.get(name) for name in INTERNAL_HOSTS]
    external_hosts = [net.get(name) for name in EXTERNAL_HOSTS]

    print('  internal: %s' % ', '.join('%s=%s' % (h.name, h.IP()) for h in internal_hosts))
    print('  external: %s' % ', '.join('%s=%s' % (h.name, h.IP()) for h in external_hosts))
    print('  NAT IP:   %s' % NAT_EXTERNAL_IP)
    print()

    for _ in range(3):
        for h in net.hosts:
            send_garp(h)
        time.sleep(1)

    # ---- Tests ----
    print('--- Multi-Host NAT Verification (4 internal × 3 external) ---')
    all_ok = True

    # 1. Internal → External ping (4×3 = 12 tests)
    print('\n[1] Internal → External ping:')
    for src in internal_hosts:
        for dst in external_hosts:
            all_ok &= run_one_test(
                '%s(%s) -> %s(%s) ping' % (src.name, src.IP(), dst.name, dst.IP()),
                ping_ok(src, dst.IP()))

    # 2. External → NAT_IP ping (reverse DNAT, 3 tests)
    print('\n[2] External → NAT_IP ping (reverse DNAT):')
    for src in external_hosts:
        all_ok &= run_one_test(
            '%s(%s) -> NAT_IP(%s) ping' % (src.name, src.IP(), NAT_EXTERNAL_IP),
            ping_ok(src, NAT_EXTERNAL_IP))

    # 3. SNAT: external hosts see all internal hosts as NAT_IP with DIFFERENT ports
    print('\n[3] SNAT verification:')
    # Use one external host as the observer for all SNAT tests
    observer = external_hosts[0]  # h5

    base_port = 22350
    results = {}
    for i, src in enumerate(internal_hosts):
        port = base_port + i
        results[src.name] = snat_client_ip(src, observer, port)

    seen_ips = {}
    seen_ports = set()
    for name, r in results.items():
        ip_part = r.split(':')[0] if ':' in r else ''
        port_part = r.split(':')[1] if ':' in r else ''
        seen_ips[name] = ip_part
        seen_ports.add(port_part)

    for host in internal_hosts:
        ip = seen_ips.get(host.name, '')
        all_ok &= run_one_test(
            '%s sees %s as %s (expect %s)' % (observer.name, host.name, ip, NAT_EXTERNAL_IP),
            ip == NAT_EXTERNAL_IP)

    # All 4 internal hosts should map to different translated ports
    valid_ports = [p for p in seen_ports if p]
    all_ok &= run_one_test(
        'all 4 SNAT ports are unique: %s' % ', '.join(sorted(valid_ports)),
        len(valid_ports) == len(internal_hosts))

    # 4. Cross-external: each internal host can also reach other external hosts
    print('\n[4] Internal → other external hosts ping:')
    for src in internal_hosts:
        for dst in external_hosts[1:]:  # skip h5 (already tested)
            all_ok &= run_one_test(
                '%s(%s) -> %s(%s) ping' % (src.name, src.IP(), dst.name, dst.IP()),
                ping_ok(src, dst.IP()))

    print('\n  -> %s' % ('ALL PASSED' if all_ok else 'SOME FAILED'))
    print()

    print('Try in CLI: h5 ping %s' % NAT_EXTERNAL_IP)
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()
