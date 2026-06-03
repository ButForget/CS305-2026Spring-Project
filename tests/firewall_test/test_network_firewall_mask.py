# test_network_firewall_mask.py
# Interactive test for firewall with CIDR subnet mask support.
#
# Usage:
#   1. Start controller:  osken-manager --observe-links controller.py
#   2. Run this script:   sudo env "PATH=$PATH" python test_network_firewall_mask.py

import sys
import time
import re

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


# ==========================================================================
# Helpers
# ==========================================================================

def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_arp(node, count=1):
    node.cmd('arping -c %s -A -I %s-eth0 %s' % (count, node.name, node.IP()))


def do_arp_all(net):
    for h in net.hosts:
        send_arp(h)


def curl(host, url):
    cmd = (
        "curl -sS --connect-timeout 2 -m 3 "
        "-o /dev/null -w 'HTTP_CODE=%%{http_code}\\n' "
        "%s 2>&1" % url
    )
    return host.cmd(cmd)


def ping_ok(src, dst_ip, count=2, timeout=1):
    """Return True if ping succeeded (got replies)."""
    result = src.cmd('ping -c %d -W %d %s' % (count, timeout, dst_ip))
    return ' 0% packet loss' in result or re.search(r'[1-9] received', result)


def tcp_ok(host, url):
    """Return True if TCP connection succeeded."""
    result = curl(host, url)
    return 'HTTP_CODE=200' in result or 'HTTP_CODE=404' in result


# ==========================================================================
# Formatted output
# ==========================================================================

def print_firewall_flows(switch):
    """Show firewall flows, one line each."""
    raw = switch.cmd('ovs-ofctl -O OpenFlow10 dump-flows %s' % switch.name)
    fw_lines = [l.strip() for l in raw.split('\n') if 'cookie=0x305f' in l]

    print('--- Installed Firewall Flows ---')
    for line in fw_lines:
        parts = []
        for pat in [r'nw_src=([\d.]+(?:/\d+)?)', r'nw_dst=([\d.]+(?:/\d+)?)',
                     r'tp_dst=(\d+)', r'icmp_type=(\d+)']:
            m = re.search(pat, line)
            if m:
                parts.append(m.group(0).replace('nw_','').replace('tp_','').replace('icmp_',''))
        if 'tcp,' in line: parts.insert(0, 'tcp')
        elif 'udp,' in line: parts.insert(0, 'udp')
        elif 'icmp,' in line: parts.insert(0, 'icmp')
        print('  DROP  %s' % '  '.join(parts))
    print()


def run_one_test(label, result, expect_blocked):
    """Print a compact test result."""
    ok = (not result) == expect_blocked
    print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    return ok


# ==========================================================================
# Topology
# ==========================================================================

class FirewallTopo(Topo):
    """Single-switch topology.

       h1 (192.168.117.2)
       h2 (192.168.117.3)  --- s1
       h3 (192.168.117.4)
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='192.168.117.2/24')
        h2 = self.addHost('h2', ip='192.168.117.3/24')
        h3 = self.addHost('h3', ip='192.168.117.4/24')
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


# ==========================================================================
# Main
# ==========================================================================

def run_mininet():
    topo = FirewallTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(1)

    h1 = net.get('h1')
    h2 = net.get('h2')
    h3 = net.get('h3')
    s1 = net.get('s1')

    # Send gratuitous ARP so the controller learns host locations
    for _ in range(3):
        do_arp_all(net)
        time.sleep(1)

    # ---- Tests ----
    print('--- CIDR Mask Verification ---')
    all_ok = True

    # Start servers on h2 for TCP tests
    h2.cmd('pkill -f "python3 -m http.server" 2>/dev/null; true')
    h2.cmd('python3 -m http.server 9999 --bind 192.168.117.3 '
           '>/tmp/h2-http9999.log 2>&1 &')
    h2.cmd('python3 -m http.server 9998 --bind 192.168.117.3 '
           '>/tmp/h2-http9998.log 2>&1 &')
    time.sleep(1)

    all_ok &= run_one_test(
        '[BLOCK] h1->h2 ICMP       (exact)',
        ping_ok(h1, '192.168.117.3'), True)
    all_ok &= run_one_test(
        '[ALLOW] h1->h3 ICMP       (no rule)',
        ping_ok(h1, '192.168.117.4'), False)

    # /30: 192.168.117.0/30 = .0-.3, h1(.2)∈, h3(.4)∉
    all_ok &= run_one_test(
        '[BLOCK] h1->h2 TCP:9999   (/30: h1 in .0-.3)',
        tcp_ok(h1, 'http://192.168.117.3:9999/'), True)
    all_ok &= run_one_test(
        '[ALLOW] h3->h2 TCP:9999   (/30: h3 not in .0-.3)',
        tcp_ok(h3, 'http://192.168.117.3:9999/'), False)

    # /31: 192.168.117.4/31 = .4-.5, h3(.4)∈, h1(.2)∉
    all_ok &= run_one_test(
        '[BLOCK] h3->h2 TCP:9998   (/31: h3 in .4-.5)',
        tcp_ok(h3, 'http://192.168.117.3:9998/'), True)
    all_ok &= run_one_test(
        '[ALLOW] h1->h2 TCP:9998   (/31: h1 not in .4-.5)',
        tcp_ok(h1, 'http://192.168.117.3:9998/'), False)

    print('  -> %s' % ('ALL PASSED' if all_ok else 'SOME FAILED'))
    print()

    # ---- Show installed flows (verify mask fields) ----
    print_firewall_flows(s1)

    # Drop into CLI for manual investigation
    CLI(net)

    # Cleanup
    h2.cmd('pkill -f "python3 -m http.server" 2>/dev/null; true')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()
