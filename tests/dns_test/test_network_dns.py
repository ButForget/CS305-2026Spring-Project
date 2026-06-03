# test_network_dns.py
# Interactive test for DNS module.
#
# Usage:
#   1. Start controller:  osken-manager --observe-links controller.py
#   2. Run this script:   sudo env "PATH=$PATH" python test_network_dns.py

import time
import re
import socket

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


# ==========================================================================
# Config
# ==========================================================================
DNS_SERVER = "10.0.0.1"


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
# Topology
# ==========================================================================

class DNSTopo(Topo):
    """Two hosts, one switch.  IPs assigned via DHCP.

       h1 --- s1 --- h2
    """
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        h1 = self.addHost('h1', ip='no ip defined/8')
        h2 = self.addHost('h2', ip='no ip defined/8')
        self.addLink(h1, s1)
        self.addLink(h2, s1)


# ==========================================================================
# Main
# ==========================================================================

def run_mininet():
    topo = DNSTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(2)

    h1 = net.get('h1')
    h2 = net.get('h2')

    # ---- DHCP ----
    print('--- Getting IPs via DHCP ---')
    dhclient(h1, timeout_s=20)
    dhclient(h2, timeout_s=20)
    time.sleep(2)

    ip1 = h1.defaultIntf().updateIP()
    ip2 = h2.defaultIntf().updateIP()
    print('  h1: %s' % ip1)
    print('  h2: %s' % ip2)
    print()

    # ---- ARP to register with DNS ----
    send_arp(h1)
    send_arp(h2)
    time.sleep(2)

    # ---- DNS Tests ----
    print('--- DNS Verification ---')
    all_ok = True

    # A record: resolve known hosts
    resolved = dig_a(h1, 'h2.local')
    all_ok &= run_one_test(
        'h1 resolves h2.local -> %s' % resolved,
        resolved == ip2)

    resolved = dig_a(h2, 'h1.local')
    all_ok &= run_one_test(
        'h2 resolves h1.local -> %s' % resolved,
        resolved == ip1)

    # NXDOMAIN: unknown hostname
    resolved = dig_a(h1, 'nonexistent.local')
    all_ok &= run_one_test(
        'nonexistent.local -> NXDOMAIN',
        resolved == 'NXDOMAIN')

    # PTR: reverse lookup
    ptr = dig_ptr(h1, ip2)
    all_ok &= run_one_test(
        'PTR %s -> %s' % (ip2, ptr),
        ptr is not None and 'h2' in str(ptr).lower())

    ptr = dig_ptr(h2, ip1)
    all_ok &= run_one_test(
        'PTR %s -> %s' % (ip1, ptr),
        ptr is not None and 'h1' in str(ptr).lower())

    print('  -> %s' % ('ALL PASSED' if all_ok else 'SOME FAILED'))
    print()

    # ---- Drop into CLI for manual testing ----
    print('Try in CLI: h1 dig @%s h2.local A' % DNS_SERVER)
    print('           h1 dig @%s -x %s' % (DNS_SERVER, ip2))
    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()
