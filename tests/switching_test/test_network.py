# -*- coding: utf-8 -*-
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo
import time
import sys


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def ping(host, dst, count=1, timeout=1):
    return host.cmd('ping -c %s -W %s %s' % (count, timeout, dst))


def send_arp(node, count=1):
    node.cmd('arping -c %s -A -I %s-eth0 %s' % (count, node.name, node.IP()))


def send_dhcp(node):
    print('Sending DHCP request dhclient -v %s-eth0 ' % (node.name))
    node.cmd('dhclient -v %s-eth0' % (node.name))


def do_arp_all(net):
    for h in net.hosts:
        send_arp(h)


# ------------------------------------------------------------------ #
#  Topologies                                                         #
# ------------------------------------------------------------------ #

class MeshTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
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
        s = {}
        for i in range(1, 7):
            s[i] = self.addSwitch('s%d' % i)

        h1 = self.addHost('h1')
        h2 = self.addHost('h2')
        h3 = self.addHost('h3')

        self.addLink(h1, s[1])
        self.addLink(h2, s[3])
        self.addLink(h3, s[6])

        self.addLink(s[1], s[2])
        self.addLink(s[2], s[3])
        self.addLink(s[4], s[5])
        self.addLink(s[5], s[6])

        self.addLink(s[1], s[4])
        self.addLink(s[2], s[5])
        self.addLink(s[3], s[6])


class DiamondTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
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


# ------------------------------------------------------------------ #
#  Generic test helpers                                               #
# ------------------------------------------------------------------ #

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
        loss_line = [l for l in out.split('\n') if 'packet loss' in l]
        summary = loss_line[0].strip() if loss_line else out.strip()
        print("  %s -> %s: %s" % (src, dst, summary))


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


# ------------------------------------------------------------------ #
#  Link-down scenario runner (existing)                               #
# ------------------------------------------------------------------ #

def run_scenario(net, hosts, name, links_down, expect_connected):
    for a, b in links_down:
        if not has_link(net, a, b):
            print("\n========== %s (SKIP: no link %s-%s) ==========" % (name, a, b))
            return True

    expect_label = "expect CONNECTED" if expect_connected else "expect DISCONNECTED"
    print("\n========== %s (%s) ==========" % (name, expect_label))
    for a, b in links_down:
        net.configLinkStatus(a, b, 'down')
        print("  [LINK-DOWN] %s <--> %s" % (a, b))

    time.sleep(3)
    do_arp_all(net)
    time.sleep(2)

    results = ping_all_pairs(hosts)
    print_ping_results(results, "Connectivity after link change")

    failed_pairs = count_failures(results)
    if expect_connected:
        ok = (failed_pairs == 0)
    else:
        ok = (failed_pairs > 0)

    for a, b in links_down:
        net.configLinkStatus(a, b, 'up')
        print("  [LINK-UP]   %s <--> %s" % (a, b))
    time.sleep(2)
    do_arp_all(net)
    time.sleep(2)

    if ok:
        print("  SCENARIO RESULT: PASS")
    else:
        print("  SCENARIO RESULT: FAIL (%d failing pairs)" % failed_pairs)
    return ok


# ------------------------------------------------------------------ #
#  Port-modify helpers  (NEW)                                         #
# ------------------------------------------------------------------ #

def get_switch_intf(net, switch_name, peer_name):
    """Return the interface name on *switch_name* that faces *peer_name*."""
    for link in net.links:
        if link.intf1.node.name == switch_name and link.intf2.node.name == peer_name:
            return link.intf1.name
        if link.intf2.node.name == switch_name and link.intf1.node.name == peer_name:
            return link.intf2.name
    return None


def get_node(net, name):
    """Return the Mininet node object for *name* (switch or host)."""
    for n in list(net.switches) + list(net.hosts):
        if n.name == name:
            return n
    return None


def run_port_modify_scenario(net, hosts, name, port_mods, expect_connected):
    """
    Apply OpenFlow port-config changes via  ovs-ofctl mod-port  and verify
    connectivity.

    Args
    ----
    port_mods : list of (switch_name, peer_name, action)
        *action* is one of: 'down', 'no-forward', 'no-receive', 'no-flood'.
    expect_connected : bool
        True  → every host pair should still reach each other.
        False → at least one pair should be unreachable.

    Returns True when the scenario outcome matches the expectation.
    """
    RESTORE_MAP = {
        'down':       'up',
        'no-forward': 'forward',
        'no-receive': 'receive',
        'no-flood':   'flood',
    }

    # ---- resolve interface names ----
    resolved = []
    for sw_name, peer_name, action in port_mods:
        intf = get_switch_intf(net, sw_name, peer_name)
        if intf is None:
            print("\n========== %s (SKIP: no link %s->%s) ==========" %
                  (name, sw_name, peer_name))
            return True
        sw_node = get_node(net, sw_name)
        if sw_node is None:
            print("\n========== %s (SKIP: no node %s) ==========" %
                  (name, sw_name))
            return True
        resolved.append((sw_node, sw_name, intf, action))

    expect_label = "expect CONNECTED" if expect_connected else "expect DISCONNECTED"
    print("\n========== %s (%s) ==========" % (name, expect_label))

    # ---- apply modifications ----
    for sw_node, sw_name, intf, action in resolved:
        cmd = 'ovs-ofctl mod-port %s %s %s' % (sw_name, intf, action)
        print("  [MOD-PORT] %s %s -> %s" % (sw_name, intf, action))
        out = sw_node.cmd(cmd)
        if out.strip():
            print("    cmd output: %s" % out.strip())

    time.sleep(4)
    do_arp_all(net)
    time.sleep(2)

    # ---- show port state ----
    print("  --- port-desc after modification ---")
    seen_sw = set()
    for sw_node, sw_name, intf, action in resolved:
        if sw_name not in seen_sw:
            desc = sw_node.cmd('ovs-ofctl dump-ports-desc %s' % sw_name)
            for line in desc.split('\n'):
                if intf in line:
                    print("    %s" % line.strip())
            seen_sw.add(sw_name)

    # ---- ping test ----
    results = ping_all_pairs(hosts)
    print_ping_results(results, "Connectivity after port_modify")

    failed_pairs = count_failures(results)
    if expect_connected:
        ok = (failed_pairs == 0)
    else:
        ok = (failed_pairs > 0)

    # ---- restore ----
    for sw_node, sw_name, intf, action in resolved:
        restore = RESTORE_MAP.get(action, 'up')
        cmd = 'ovs-ofctl mod-port %s %s %s' % (sw_name, intf, restore)
        print("  [RESTORE]  %s %s -> %s" % (sw_name, intf, restore))
        sw_node.cmd(cmd)

    time.sleep(3)
    do_arp_all(net)
    time.sleep(2)

    # ---- verify recovery ----
    recovery = ping_all_pairs(hosts)
    recovery_fail = count_failures(recovery)

    if ok and recovery_fail == 0:
        print("  SCENARIO RESULT: PASS (connectivity correct, recovery OK)")
    elif ok and recovery_fail > 0:
        print("  SCENARIO RESULT: PASS (connectivity correct, recovery FAIL %d pairs)"
              % recovery_fail)
    else:
        print("  SCENARIO RESULT: FAIL (failed pairs: %d)" % failed_pairs)
    return ok


def run_port_flap_scenario(net, hosts, name, sw_name, peer_name,
                           flaps=3, interval=1):
    """
    Rapidly toggle a port  down / up  several times, then check that the
    controller recovers and full connectivity is restored.
    """
    intf = get_switch_intf(net, sw_name, peer_name)
    if intf is None:
        print("\n========== %s (SKIP: no link %s->%s) ==========" %
              (name, sw_name, peer_name))
        return True

    sw_node = get_node(net, sw_name)

    print("\n========== %s ==========" % name)
    print("  Flapping %s %s (%d cycles, interval %.1fs)" %
          (sw_name, intf, flaps, interval))

    for i in range(flaps):
        sw_node.cmd('ovs-ofctl mod-port %s %s down' % (sw_name, intf))
        print("  [FLAP %d] %s %s -> down" % (i + 1, sw_name, intf))
        time.sleep(interval)
        sw_node.cmd('ovs-ofctl mod-port %s %s up' % (sw_name, intf))
        print("  [FLAP %d] %s %s -> up" % (i + 1, sw_name, intf))
        time.sleep(interval)

    # allow controller to stabilise
    time.sleep(4)
    do_arp_all(net)
    time.sleep(2)

    results = ping_all_pairs(hosts)
    print_ping_results(results, "Connectivity after port flap")

    failed_pairs = count_failures(results)
    if failed_pairs == 0:
        print("  SCENARIO RESULT: PASS (stable after %d flaps)" % flaps)
        return True
    else:
        print("  SCENARIO RESULT: FAIL (%d pairs failing after flap)" % failed_pairs)
        return False


# ------------------------------------------------------------------ #
#  Main test driver                                                   #
# ------------------------------------------------------------------ #

def run_tests(net, topo_name):
    hosts = net.hosts
    failures = 0
    total = 0

    print("\n" + "=" * 60)
    print("  Topology: %s" % topo_name)
    print("  Switches: %s" % [s.name for s in net.switches])
    print("  Hosts:    %s" % [(h.name, h.IP()) for h in net.hosts])
    print("=" * 60)

    # ============================================================== #
    # Phase 0  –  wait for topology discovery                        #
    # ============================================================== #
    print("\n========== Waiting for topology discovery ==========")
    time.sleep(3)
    do_arp_all(net)
    time.sleep(4)

    # ============================================================== #
    # Test 1  –  baseline full-mesh connectivity                     #
    # ============================================================== #
    total += 1
    results = ping_all_pairs(hosts)
    print_ping_results(results, "Test 1: full-mesh connectivity")
    if count_failures(results) == 0:
        print("  BASELINE RESULT: PASS")
    else:
        print("  BASELINE RESULT: FAIL")
        failures += 1

    # ============================================================== #
    # Test 2  –  flow table dump                                     #
    # ============================================================== #
    print("\n========== Test 2: dump flows ==========")
    for s in net.switches:
        print("\n--- %s ---" % s.name)
        print(s.cmd('ovs-ofctl dump-flows %s --no-stats' % s.name))

    # ============================================================== #
    # Test 3-N  –  link-down scenarios  (existing)                   #
    # ============================================================== #
    if topo_name == 'grid':
        link_scenarios = [
            ("Grid: break s2-s3", [('s2', 's3')], True),
            ("Grid: break s2-s5", [('s2', 's5')], True),
            ("Grid: partition core",
             [('s2', 's3'), ('s2', 's5'), ('s3', 's6')], False),
        ]
    elif topo_name == 'mesh':
        link_scenarios = [
            ("Mesh: break s2-s3", [('s2', 's3')], True),
            ("Mesh: break diagonal s1-s3", [('s1', 's3')], True),
            ("Mesh: break s1-s2 and s3-s4",
             [('s1', 's2'), ('s3', 's4')], False),
        ]
    elif topo_name == 'triangle':
        link_scenarios = [
            ("Triangle: break s1-s2", [('s1', 's2')], True),
            ("Triangle: break s2-s3", [('s2', 's3')], True),
            ("Triangle: break s1-s2 and s2-s3",
             [('s1', 's2'), ('s2', 's3')], False),
        ]
    elif topo_name == 'diamond':
        link_scenarios = [
            ("Diamond: break s1-s2", [('s1', 's2')], True),
            ("Diamond: break s1-s3", [('s1', 's3')], True),
            ("Diamond: break both branches",
             [('s1', 's2'), ('s1', 's3')], False),
        ]
    elif topo_name == 'line':
        link_scenarios = [
            ("Line: break s2-s3", [('s2', 's3')], False),
            ("Line: break s1-s2", [('s1', 's2')], False),
        ]
    else:
        link_scenarios = []

    print("\n" + "=" * 60)
    print("  Link-down scenarios")
    print("=" * 60)
    for name, links_down, expect_connected in link_scenarios:
        total += 1
        ok = run_scenario(net, hosts, name, links_down, expect_connected)
        if not ok:
            failures += 1

    # ============================================================== #
    # Port-modify scenarios  (NEW)                                   #
    # ============================================================== #
    print("\n" + "=" * 60)
    print("  Port-modify scenarios  (ovs-ofctl mod-port)")
    print("=" * 60)

    if topo_name == 'grid':
        # Grid hosts: h1->s1, h2->s3, h3->s6
        # Grid links: s1-s2,s2-s3 (top), s4-s5,s5-s6 (bot), s1-s4,s2-s5,s3-s6 (vert)
        port_scenarios = [
            # --- admin down (OFPPC_PORT_DOWN) ---
            # Single port down on s2 facing s3; alternative path exists
            ("PortMod: s2 port->s3 down (reroute via bottom row)",
             [('s2', 's3', 'down')], True),

            # Host-facing port down: s1's port toward h1 -> h1 isolated
            ("PortMod: s1 port->h1 down (isolate h1)",
             [('s1', 'h1', 'down')], False),

            # Isolate s3: bring down both switch-facing ports on s3
            ("PortMod: isolate s3 (s3->s2 down, s3->s6 down)",
             [('s3', 's2', 'down'), ('s3', 's6', 'down')], False),

            # --- no-forward (OFPPC_NO_FWD) ---
            # s2 port toward s5 set to no-forward; path via top or other verticals
            ("PortMod: s2 port->s5 no-forward (reroute)",
             [('s2', 's5', 'no-forward')], True),

            # --- no-receive (OFPPC_NO_RECV) ---
            # s5 port toward s2 set to no-receive; s5 drops packets from s2
            ("PortMod: s5 port->s2 no-receive (reroute)",
             [('s5', 's2', 'no-receive')], True),

            # --- combined: no-forward + down on different switches ---
            ("PortMod: s2->s3 no-forward AND s3->s6 down (isolate s3)",
             [('s2', 's3', 'no-forward'), ('s3', 's6', 'down')], False),
        ]

    elif topo_name == 'mesh':
        # Mesh hosts: h1->s1, h2->s2, h3->s3, h4->s4
        # Mesh links: s1-s2, s2-s3, s3-s4, s4-s1 (ring) + s1-s3 (diagonal)
        port_scenarios = [
            ("PortMod: s1 port->s2 down (ring+diag provide path)",
             [('s1', 's2', 'down')], True),

            ("PortMod: s2 port->s3 no-forward (reroute via ring)",
             [('s2', 's3', 'no-forward')], True),

            ("PortMod: s3 port->s2 no-receive (reroute)",
             [('s3', 's2', 'no-receive')], True),

            # Isolate s4: s4 connects to s3 and s1 only
            ("PortMod: isolate s4 (s4->s3 down, s4->s1 down)",
             [('s4', 's3', 'down'), ('s4', 's1', 'down')], False),

            # Isolate s2: s2 connects to s1 and s3
            ("PortMod: isolate s2 (s2->s1 no-forward, s2->s3 down)",
             [('s2', 's1', 'no-forward'), ('s2', 's3', 'down')], False),
        ]

    elif topo_name == 'triangle':
        # Triangle hosts: h1->s1, h2->s2, h3->s3
        # Triangle links: s1-s2, s2-s3, s3-s1
        port_scenarios = [
            ("PortMod: s1 port->s2 down (path via s3)",
             [('s1', 's2', 'down')], True),

            ("PortMod: s2 port->s3 no-forward (path via s1)",
             [('s2', 's3', 'no-forward')], True),

            # Isolate s1: both ports down
            ("PortMod: isolate s1 (s1->s2 down, s1->s3 down)",
             [('s1', 's2', 'down'), ('s1', 's3', 'down')], False),

            # Asymmetric: s1->s2 no-receive, s2->s3 no-forward
            ("PortMod: s1->s2 no-receive AND s2->s3 no-forward",
             [('s1', 's2', 'no-receive'), ('s2', 's3', 'no-forward')], True),
        ]

    elif topo_name == 'diamond':
        # Diamond hosts: h1->s1, h2->s4
        # Diamond links: s1-s2, s1-s3, s2-s4, s3-s4
        port_scenarios = [
            ("PortMod: s1 port->s2 down (path s1-s3-s4)",
             [('s1', 's2', 'down')], True),

            ("PortMod: s2 port->s4 no-forward (path s1-s3-s4)",
             [('s2', 's4', 'no-forward')], True),

            ("PortMod: s3 port->s4 no-receive (path s1-s2-s4)",
             [('s3', 's4', 'no-receive')], True),

            # Isolate s1: both outgoing switch ports down
            ("PortMod: isolate s1 (s1->s2 down, s1->s3 down)",
             [('s1', 's2', 'down'), ('s1', 's3', 'down')], False),
        ]

    elif topo_name == 'line':
        # Line hosts: h1->s1, h2->s4
        # Line links: s1-s2, s2-s3, s3-s4  (no redundancy)
        port_scenarios = [
            ("PortMod: s2 port->s3 down (cuts the line)",
             [('s2', 's3', 'down')], False),

            ("PortMod: s1 port->s2 no-forward (cuts the line)",
             [('s1', 's2', 'no-forward')], False),

            ("PortMod: s3 port->s2 no-receive (cuts the line)",
             [('s3', 's2', 'no-receive')], False),
        ]

    else:
        port_scenarios = []

    for name, port_mods, expect_connected in port_scenarios:
        total += 1
        ok = run_port_modify_scenario(net, hosts, name,
                                      port_mods, expect_connected)
        if not ok:
            failures += 1

    # ============================================================== #
    # Port-flap stability test  (NEW)                                #
    # ============================================================== #
    flap_links = {
        'grid':     ('s2', 's5'),
        'mesh':     ('s1', 's2'),
        'triangle': ('s1', 's2'),
        'diamond':  ('s1', 's2'),
        'line':     ('s2', 's3'),
    }
    if topo_name in flap_links:
        total += 1
        sw, peer = flap_links[topo_name]
        ok = run_port_flap_scenario(
            net, hosts,
            "PortFlap: %s->%s (3 rapid cycles)" % (sw, peer),
            sw, peer, flaps=3, interval=1)
        if not ok:
            failures += 1

    # ============================================================== #
    # Final recovery verification                                    #
    # ============================================================== #
    total += 1
    print("\n========== Final: full recovery verification ==========")
    time.sleep(3)
    do_arp_all(net)
    time.sleep(3)
    results = ping_all_pairs(hosts, count=3, timeout=2)
    print_ping_results(results, "Full connectivity after all tests")
    recovery_fail = count_failures(results)
    if recovery_fail == 0:
        print("  RECOVERY RESULT: PASS")
    else:
        print("  RECOVERY RESULT: FAIL (%d pairs)" % recovery_fail)
        failures += 1

    # ============================================================== #
    # Summary                                                        #
    # ============================================================== #
    print("\n" + "=" * 60)
    print("  TEST SUMMARY  (%s topology)" % topo_name)
    print("=" * 60)
    print("  Total scenarios : %d" % total)
    print("  Passed          : %d" % (total - failures))
    print("  Failed          : %d" % failures)
    print("=" * 60)
    if failures == 0:
        print("  OVERALL RESULT: PASS")
    else:
        print("  OVERALL RESULT: FAIL")
    print("=" * 60)


def run_mininet(topo_name):
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

    # Print topology info
    print("\n========== Topology Info ==========")
    print("  Switches: %s" % [s.name for s in net.switches])
    print("  Hosts: %s" % [(h.name, h.IP()) for h in net.hosts])
    print("  Links: %d total" % len(net.links))
    for link in net.links:
        print("    %s <--> %s" % (link.intf1.node.name, link.intf2.node.name))

    # Run automated tests
    run_tests(net, topo_name)

    # Clear all flows so manual pings in CLI re-trigger path computation
    print("\n========== Clearing flow tables for manual testing ==========")
    for s in net.switches:
        s.cmd('ovs-ofctl del-flows %s' % s.name)
    time.sleep(1)
    do_arp_all(net)
    time.sleep(2)
    print("Flows cleared. Manual pings will now show shortest-path in controller log.")
    print("Try in CLI: h1 ping h2\n")

    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topo_arg = 'grid'
    if len(sys.argv) >= 2:
        topo_arg = sys.argv[1].strip().lower()
    if topo_arg not in ['grid', 'mesh', 'triangle', 'diamond', 'line']:
        print("Usage: %s [grid|mesh|triangle|diamond|line]" % sys.argv[0])
        sys.exit(2)
    run_mininet(topo_arg)