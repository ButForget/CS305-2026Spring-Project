# test_network_nat.py
# Interactive test for NAT module (SNAT/DNAT).
#
# Topology:
#   h1 (10.0.1.2) -- s1 -- s2 -- h2 (10.0.2.2)
#
# NAT rewrites:
#   internal (10.0.1.0/24) ←→ NAT_IP (10.0.2.100) ←→ external (10.0.2.0/24)
#
# Usage:
#   1. Start controller:  osken-manager --observe-links controller.py
#   2. Run this script:   sudo env "PATH=$PATH" python test_network_nat.py

import time
import re

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


# ==========================================================================
# Config (must match nat.py)
# ==========================================================================
NAT_EXTERNAL_IP = "10.0.2.100"


# ==========================================================================
# Helpers
# ==========================================================================

def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_garp(host, count=2):
    intf = host.defaultIntf().name
    host.cmd("arping -c %d -A -I %s %s" % (count, intf, host.IP()))


def ping_ok(src, dst_ip, count=3, timeout=2):
    """Return True if ping gets at least 1 reply."""
    result = src.cmd("ping -c %d -W %d %s" % (count, timeout, dst_ip))
    return ' 0% packet loss' in result or bool(re.search(r'[1-9]\d* received', result))


def run_one_test(label, ok):
    """Print a compact test result."""
    print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    return ok


# ==========================================================================
# Topology
# ==========================================================================

class NATTopo(Topo):
    """h1 (internal) --- s1 --- s2 --- h2 (external).

       Hosts use /16 so they ARP each other directly;
       controller uses /24 internally to decide SNAT/DNAT.
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        h1 = self.addHost('h1', ip='10.0.1.2/16')
        h2 = self.addHost('h2', ip='10.0.2.2/16')
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)


# ==========================================================================
# Main
# ==========================================================================

def run_mininet():
    topo = NATTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(2)

    h1 = net.get('h1')
    h2 = net.get('h2')
    print('  h1 (internal): %s' % h1.IP())
    print('  h2 (external): %s' % h2.IP())
    print('  NAT external IP: %s' % NAT_EXTERNAL_IP)
    print()

    # Gratuitous ARP — controller learns host locations
    for _ in range(3):
        for h in net.hosts:
            send_garp(h)
        time.sleep(1)

    # ---- Tests ----
    print('--- NAT Verification ---')
    all_ok = True

    # Test 1: h1 → h2 ping (SNAT outbound)
    ok = ping_ok(h1, h2.IP(), count=4)
    all_ok &= run_one_test(
        'h1(%s) -> h2(%s) ping' % (h1.IP(), h2.IP()), ok)

    # Test 2: h2 → NAT_IP ping (DNAT inbound)
    ok = ping_ok(h2, NAT_EXTERNAL_IP, count=4)
    all_ok &= run_one_test(
        'h2(%s) -> NAT_IP(%s) ping (DNAT)' % (h2.IP(), NAT_EXTERNAL_IP), ok)

    # Test 3: SNAT — h2 sees NAT_IP as source (not h1's real IP)
    # Run TCP server on h2 that logs client IP
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
    h1.cmd("curl -sS --connect-timeout 3 -m 4 http://%s:12346/ 2>/dev/null" % h2.IP())
    time.sleep(5)
    seen_ip = h2.cmd("cat /tmp/tcp_out.txt 2>/dev/null").strip()
    h2.cmd("pkill -f tcp_server.py 2>/dev/null; true")
    h2.cmd("rm -f /tmp/tcp_server.py /tmp/tcp_out.txt")

    all_ok &= run_one_test(
        'SNAT: h2 sees src=%s (NAT IP)' % seen_ip,
        seen_ip == NAT_EXTERNAL_IP)

    print('  -> %s' % ('ALL PASSED' if all_ok else 'SOME FAILED'))
    print()

    # ---- CLI for manual testing ----
    print('Try in CLI: h1 ping %s' % h2.IP())
    print('           h2 ifconfig  (check arp table for %s)' % NAT_EXTERNAL_IP)
    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()
