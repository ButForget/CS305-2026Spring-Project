# -*- coding: utf-8 -*-
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def ping(host, dst, count=1, timeout=1):
    return host.cmd('ping -c %s -W %s %s' % (count, timeout, dst))

def send_arp(node, count=1):
    node.cmd('arping -c %s -A -I %s-eth0 %s' % (count, node.name, node.IP()))

def send_dhcp(node):
    print('Sending DHCP request dhclient -v %s-eth0 '% (node.name))
    node.cmd('dhclient -v %s-eth0' % (node.name))


def do_arp_all(net):
    for h in net.hosts:
        send_arp(h)

class MeshTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # Four switches in a ring with a diagonal for alternate paths
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')
        h4 = self.addHost('h4')

        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(h4, s4)

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, s1)
        self.addLink(s1, s3)


class TriangleTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)

        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s1)


class GridTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # 2x3 grid of switches
        # s1 -- s2 -- s3
        # |     |     |
        # s4 -- s5 -- s6
        s = {}
        for i in range(1, 7):
            s[i] = self.addSwitch('s%d' % i)

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        self.addLink(h1, s[1])
        self.addLink(h2, s[3])
        self.addLink(h3, s[6])

        # Horizontal links
        self.addLink(s[1], s[2])
        self.addLink(s[2], s[3])
        self.addLink(s[4], s[5])
        self.addLink(s[5], s[6])

        # Vertical links
        self.addLink(s[1], s[4])
        self.addLink(s[2], s[5])
        self.addLink(s[3], s[6])


class DiamondTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # s1 -- s2 -- s4
        #  \        /
        #    s3 ----
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, s1)
        self.addLink(h2, s4)

        self.addLink(s1, s2)
        self.addLink(s1, s3)
        self.addLink(s2, s4)
        self.addLink(s3, s4)


class LineTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # h1 -- s1 -- s2 -- s3 -- s4 -- h2
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s4)
        self.addLink(s4, h2)


def ping_all_pairs(hosts, count=2, timeout=1):
    results = {}
    for i, src in enumerate(hosts):
        for dst in hosts[i + 1:]:
            out = ping(src, dst.IP(), count=count, timeout=timeout)
            results[(src.name, dst.name)] = out
    return results


def print_ping_results(results, title):
    print("\n========== %s ==========" % title)
    for (src, dst), out in results.items():
        print("%s -> %s: %s" % (src, dst, out.strip()))


def count_failures(results):
    failures = 0
    for out in results.values():
        if " 0% packet loss" not in out:
            failures += 1
    return failures


def has_link(net, left, right):
    for link in net.links:
        n1 = link.intf1.node.name
        n2 = link.intf2.node.name
        if {n1, n2} == {left, right}:
            return True
    return False


def run_scenario(net, hosts, name, links_down, expect_connected):
    import time
    for a, b in links_down:
        if not has_link(net, a, b):
            print("\n========== %s (SKIP: no link %s-%s) ==========" % (name, a, b))
            return True

    expect_label = "expect CONNECTED" if expect_connected else "expect DISCONNECTED"
    print("\n========== %s (%s) ==========" % (name, expect_label))
    for a, b in links_down:
        net.configLinkStatus(a, b, 'down')

    time.sleep(3)
    results = ping_all_pairs(hosts)
    print_ping_results(results, "Connectivity after link change")

    failed_pairs = count_failures(results)
    if expect_connected:
        ok = (failed_pairs == 0)
    else:
        ok = (failed_pairs > 0)

    for a, b in links_down:
        net.configLinkStatus(a, b, 'up')
    time.sleep(2)

    if ok:
        print("SCENARIO RESULT: PASS")
    else:
        print("SCENARIO RESULT: FAIL (%d failing pairs)" % failed_pairs)
    return ok


def run_tests(net, topo_name):
    import time
    hosts = net.hosts
    failures = 0

    print("\n========== Waiting for topology discovery ==========")
    time.sleep(3)
    do_arp_all(net)
    time.sleep(4)

    results = ping_all_pairs(hosts)
    print_ping_results(results, "Test 1: full-mesh connectivity")
    if count_failures(results) == 0:
        print("BASELINE RESULT: PASS")
    else:
        print("BASELINE RESULT: FAIL")
        failures += 1

    print("\n========== Test 2: dump flows ==========")
    for s in net.switches:
        print(f"\n--- {s.name} ---")
        print(s.cmd('ovs-ofctl dump-flows %s --no-stats' % s.name))

    if topo_name == 'grid':
        scenarios = [
            ("Grid: break s2-s3", [('s2', 's3')], True),
            ("Grid: break s2-s5", [('s2', 's5')], True),
            ("Grid: partition core", [('s2', 's3'), ('s2', 's5'), ('s3', 's6')], False),
        ]
    elif topo_name == 'mesh':
        scenarios = [
            ("Mesh: break s2-s3", [('s2', 's3')], True),
            ("Mesh: break diagonal s1-s3", [('s1', 's3')], True),
            ("Mesh: break s1-s2 and s3-s4", [('s1', 's2'), ('s3', 's4')], False),
        ]
    elif topo_name == 'triangle':
        scenarios = [
            ("Triangle: break s1-s2", [('s1', 's2')], True),
            ("Triangle: break s2-s3", [('s2', 's3')], True),
            ("Triangle: break s1-s2 and s2-s3", [('s1', 's2'), ('s2', 's3')], False),
        ]
    elif topo_name == 'diamond':
        scenarios = [
            ("Diamond: break s1-s2", [('s1', 's2')], True),
            ("Diamond: break s1-s3", [('s1', 's3')], True),
            ("Diamond: break both branches", [('s1', 's2'), ('s1', 's3')], False),
        ]
    elif topo_name == 'line':
        scenarios = [
            ("Line: break s2-s3", [('s2', 's3')], False),
            ("Line: break s1-s2", [('s1', 's2')], False),
        ]
    else:
        scenarios = []

    for name, links_down, expect_connected in scenarios:
        ok = run_scenario(net, hosts, name, links_down, expect_connected)
        if not ok:
            failures += 1

    print("\n========== All tests complete ==========")
    if failures == 0:
        print("RESULT: PASS")
    else:
        print("RESULT: FAIL (%d scenarios failed)" % failures)

def run_mininet(topo_name):
    import time
    if topo_name == 'mesh':
        topo = MeshTopo()
    elif topo_name == 'grid':
        topo = GridTopo()
    elif topo_name == 'triangle':
        topo = TriangleTopo()
    elif topo_name == 'diamond':
        topo = DiamondTopo()
    elif topo_name == 'line':
        topo = LineTopo()
    else:
        topo = GridTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)
    for h in net.hosts:
        disable_ipv6(h)
    for h in net.switches:
        disable_ipv6(h)
    
    net.start()
    time.sleep(1)
    do_arp_all(net)

    # automatic tests
    run_tests(net, topo_name)

    # then enter CLI for manual tests
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    import sys
    topo_arg = 'grid'
    if len(sys.argv) >= 2:
        topo_arg = sys.argv[1].strip().lower()
    if topo_arg not in ['grid', 'mesh', 'triangle', 'diamond', 'line']:
        print("Usage: %s [grid|mesh|triangle|diamond|line]" % sys.argv[0])
        sys.exit(2)
    run_mininet(topo_arg)