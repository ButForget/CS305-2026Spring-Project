# test_network_dns_complex.py
# Interactive test for DNS module with a more complex multi-switch topology.
#
# Usage:
#   1. Start controller:  osken-manager --observe-links controller.py
#   2. Run this script:   sudo env "PATH=$PATH" python test_network_dns_complex.py

import os
import sys
import time
import re
import socket

_project_root = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
sys.path.insert(0, _project_root)

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
from dhcp import Config

# ==========================================================================
# Config
# ==========================================================================
DNS_SERVER = Config.server_ip


# ==========================================================================
# Helpers
# ==========================================================================

def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def dhclient(node, timeout_s=15):
    return node.cmd("timeout %s dhclient -v %s-eth0 2>&1" % (timeout_s, node.name))


def send_arp(node):
    node.cmd("arping -c 2 -A -I %s-eth0 %s"
             % (node.name, node.defaultIntf().updateIP() or node.IP()))


def dig_a(host, qname, timeout=5):
    """Resolve A record, return IP or 'NXDOMAIN' or None."""
    result = host.cmd("dig +time=%d +tries=1 @%s %s A 2>&1" % (timeout, DNS_SERVER, qname))
    if 'NXDOMAIN' in result:
        return 'NXDOMAIN'
    if 'SERVFAIL' in result or 'timed out' in result:
        return None
    for line in result.split('\n'):
        line = line.strip()
        if line.startswith(';;') or not line:
            continue
        parts = line.split()
        if len(parts) >= 5 and parts[-2] == 'A':
            try:
                socket.inet_aton(parts[-1])
                return parts[-1]
            except Exception:
                pass
    return None


def dig_ptr(host, ip, timeout=5):
    """Reverse PTR lookup, return hostname or None."""
    result = host.cmd("dig +short +time=%d @%s -x %s 2>&1" % (timeout, DNS_SERVER, ip))
    result = result.strip().rstrip('.')
    if result and 'timed out' not in result and 'SERVFAIL' not in result:
        return result
    return None


def run_one_test(label, ok):
    """Print a compact test result."""
    print('  [%s] %s' % ('OK' if ok else 'FAIL', label))
    return ok


# ==========================================================================
# Topology: 4 switches (mesh), 6 hosts distributed across switches
#
#   h1 --- s1 --- s2 --- h2
#           | \   / |
#           |  \ /  |
#           |   X   |
#           |  / \  |
#           | /   \ |
#   h3 --- s3 --- s4 --- h4
#           |       |
#           h5      h6
#
# Host distribution:
#   s1: h1          (1 hop from s1)
#   s2: h2          (1 hop from s2)
#   s3: h3, h5      (2 hosts on same switch)
#   s4: h4, h6      (2 hosts on same switch)
#
# DNS resolution path lengths:
#   h1 <-> h2: s1-s2 (1 switch hop)
#   h1 <-> h3: s1-s3 (1 switch hop)
#   h1 <-> h4: s1-s4 or s1-s3-s4 or s1-s2-s4 (1-2 switch hops)
#   h5 <-> h6: s3-s4 or s3-s1-s4 or s3-s2-s4 (1-2 switch hops)
#   h2 <-> h5: s2-s3 or s2-s1-s3 or s2-s4-s3 (1-2 switch hops)
# ==========================================================================

class ComplexDNSTopo(Topo):
    """4 switches, 6 hosts, 5 switch-to-switch links forming a mesh.

        h1 --- s1 --- s2 --- h2
                | \   / |
                |  \ /  |
                |   X   |
                |  / \  |
                | /   \ |
        h3 --- s3 --- s4 --- h4
                |       |
                h5      h6
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        # Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Hosts (IPs assigned via DHCP)
        h1 = self.addHost('h1', ip='no ip defined/8')
        h2 = self.addHost('h2', ip='no ip defined/8')
        h3 = self.addHost('h3', ip='no ip defined/8')
        h4 = self.addHost('h4', ip='no ip defined/8')
        h5 = self.addHost('h5', ip='no ip defined/8')
        h6 = self.addHost('h6', ip='no ip defined/8')

        # Host-to-switch links
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)
        self.addLink(h5, s3)
        self.addLink(h6, s4)

        # Switch-to-switch links (mesh)
        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s1, s4)
        self.addLink(s2, s3)
        self.addLink(s3, s4)


# ==========================================================================
# Main
# ==========================================================================

def run_mininet():
    topo = ComplexDNSTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)

    # Retrieve all hosts
    hosts = {}
    for name in ['h1', 'h2', 'h3', 'h4', 'h5', 'h6']:
        hosts[name] = net.get(name)

    # ---- DHCP ----
    print('--- Getting IPs via DHCP ---')
    for name, h in hosts.items():
        print('  Requesting DHCP for %s ...' % name)
        dhclient(h, timeout_s=20)
    time.sleep(3)

    # Collect IPs
    ips = {}
    for name, h in hosts.items():
        ip = h.defaultIntf().updateIP()
        ips[name] = ip
        print('  %s: %s' % (name, ip))
    print()

    # ---- ARP to register with DNS ----
    print('--- Sending gratuitous ARP to register hosts with DNS ---')
    for name, h in hosts.items():
        send_arp(h)
    time.sleep(3)
    print()

    # ======================================================================
    # DNS Tests
    # ======================================================================
    print('=' * 60)
    print('--- DNS Verification (Complex Topology) ---')
    print('=' * 60)
    all_ok = True

    # ---- Test 1: A record - same switch ----
    print('\n[Test 1] A record: hosts on the same switch')
    # h3 and h5 are both on s3
    resolved = dig_a(hosts['h3'], 'h5.local')
    all_ok &= run_one_test(
        'h3 resolves h5.local -> %s (expected %s)' % (resolved, ips['h5']),
        resolved == ips['h5'])

    resolved = dig_a(hosts['h5'], 'h3.local')
    all_ok &= run_one_test(
        'h5 resolves h3.local -> %s (expected %s)' % (resolved, ips['h3']),
        resolved == ips['h3'])

    # h4 and h6 are both on s4
    resolved = dig_a(hosts['h4'], 'h6.local')
    all_ok &= run_one_test(
        'h4 resolves h6.local -> %s (expected %s)' % (resolved, ips['h6']),
        resolved == ips['h6'])

    resolved = dig_a(hosts['h6'], 'h4.local')
    all_ok &= run_one_test(
        'h6 resolves h4.local -> %s (expected %s)' % (resolved, ips['h4']),
        resolved == ips['h4'])

    # ---- Test 2: A record - 1 switch hop ----
    print('\n[Test 2] A record: hosts 1 switch hop away')
    # h1 (s1) <-> h3 (s3): direct s1-s3 link
    resolved = dig_a(hosts['h1'], 'h3.local')
    all_ok &= run_one_test(
        'h1 resolves h3.local -> %s (expected %s)' % (resolved, ips['h3']),
        resolved == ips['h3'])

    # h2 (s2) <-> h4 (s4): s2-s1-s4 or s2-s3-s4
    resolved = dig_a(hosts['h2'], 'h4.local')
    all_ok &= run_one_test(
        'h2 resolves h4.local -> %s (expected %s)' % (resolved, ips['h4']),
        resolved == ips['h4'])

    # ---- Test 3: A record - 2 switch hops ----
    print('\n[Test 3] A record: hosts 2 switch hops away')
    # h2 (s2) <-> h5 (s3): s2-s1-s3 or s2-s4-s3 or s2-s3
    resolved = dig_a(hosts['h2'], 'h5.local')
    all_ok &= run_one_test(
        'h2 resolves h5.local -> %s (expected %s)' % (resolved, ips['h5']),
        resolved == ips['h5'])

    # h1 (s1) <-> h6 (s4): s1-s4 or s1-s3-s4
    resolved = dig_a(hosts['h1'], 'h6.local')
    all_ok &= run_one_test(
        'h1 resolves h6.local -> %s (expected %s)' % (resolved, ips['h6']),
        resolved == ips['h6'])

    # ---- Test 4: Cross-resolution from every host ----
    print('\n[Test 4] A record: every host can resolve every other host')
    host_names = sorted(hosts.keys())
    for src_name in host_names:
        for dst_name in host_names:
            if src_name == dst_name:
                continue
            qname = '%s.local' % dst_name
            resolved = dig_a(hosts[src_name], qname)
            ok = (resolved == ips[dst_name])
            all_ok &= run_one_test(
                '%s resolves %s -> %s' % (src_name, qname, resolved),
                ok)

    # ---- Test 5: NXDOMAIN for various nonexistent names ----
    print('\n[Test 5] NXDOMAIN: various nonexistent hostnames')
    nonexistent_names = [
        'nonexistent.local',
        'ghost.local',
        'unknown.local',
        'h7.local',
        'random.host.local',
    ]
    for name in nonexistent_names:
        resolved = dig_a(hosts['h1'], name)
        all_ok &= run_one_test(
            '%s -> NXDOMAIN' % name,
            resolved == 'NXDOMAIN')

    # ---- Test 6: NXDOMAIN from different source hosts ----
    print('\n[Test 6] NXDOMAIN: same nonexistent name, different source hosts')
    for src_name in ['h2', 'h4', 'h6']:
        resolved = dig_a(hosts[src_name], 'no-such-host.local')
        all_ok &= run_one_test(
            '%s queries no-such-host.local -> NXDOMAIN' % src_name,
            resolved == 'NXDOMAIN')

    # ---- Test 7: PTR reverse lookup ----
    print('\n[Test 7] PTR: reverse lookup for all hosts')
    for name, ip in ips.items():
        ptr = dig_ptr(hosts['h1'], ip)
        all_ok &= run_one_test(
            'PTR %s (%s) -> %s' % (ip, name, ptr),
            ptr is not None and name.lower() in str(ptr).lower())

    # ---- Test 8: PTR from different source hosts ----
    print('\n[Test 8] PTR: reverse lookup from remote hosts')
    # h6 queries PTR for h1's IP
    ptr = dig_ptr(hosts['h6'], ips['h1'])
    all_ok &= run_one_test(
        'h6 PTR %s -> %s' % (ips['h1'], ptr),
        ptr is not None and 'h1' in str(ptr).lower())

    # h5 queries PTR for h2's IP
    ptr = dig_ptr(hosts['h5'], ips['h2'])
    all_ok &= run_one_test(
        'h5 PTR %s -> %s' % (ips['h2'], ptr),
        ptr is not None and 'h2' in str(ptr).lower())

    # ---- Test 9: DNS resolution of static entries ----
    print('\n[Test 9] A record: static DNS entries (dhcp.local, dns.local)')
    resolved = dig_a(hosts['h1'], 'dhcp.local')
    all_ok &= run_one_test(
        'dhcp.local -> %s (expected %s)' % (resolved, DNS_SERVER),
        resolved == DNS_SERVER)

    resolved = dig_a(hosts['h3'], 'dns.local')
    all_ok &= run_one_test(
        'dns.local -> %s (expected %s)' % (resolved, DNS_SERVER),
        resolved == DNS_SERVER)

    # ---- Test 10: DNS resolution without .local suffix (short name) ----
    print('\n[Test 10] A record: short hostname (without .local suffix)')
    resolved = dig_a(hosts['h1'], 'h2')
    all_ok &= run_one_test(
        'h1 resolves h2 (short) -> %s (expected %s)' % (resolved, ips['h2']),
        resolved == ips['h2'])

    resolved = dig_a(hosts['h4'], 'h3')
    all_ok &= run_one_test(
        'h4 resolves h3 (short) -> %s (expected %s)' % (resolved, ips['h3']),
        resolved == ips['h3'])

    # ======================================================================
    # Summary
    # ======================================================================
    print()
    print('=' * 60)
    print('  -> %s' % ('ALL PASSED' if all_ok else 'SOME FAILED'))
    print('=' * 60)
    print()

    # ---- Drop into CLI for manual testing ----
    print('Try in CLI:')
    print('  h1 dig @%s h6.local A' % DNS_SERVER)
    print('  h1 dig @%s -x %s' % (DNS_SERVER, ips['h6']))
    print('  h3 dig @%s h5.local A' % DNS_SERVER)
    print('  h6 dig @%s h1.local A' % DNS_SERVER)
    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()
