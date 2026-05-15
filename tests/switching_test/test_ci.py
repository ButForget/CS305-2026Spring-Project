"""
Non-interactive CI test for the shortest-path switching module.

Replaces the interactive CLI of test_network.py with automated assertions.
Expects the os-ken controller to already be running (osken-manager --observe-links controller.py).
"""

import sys
import time
import re

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_arp(node, count=1):
    node.cmd("arping -c %s -A -I %s-eth0 %s 2>/dev/null" % (count, node.name, node.IP()))


def do_arp_all(net):
    for h in net.hosts:
        send_arp(h)


class TriangleTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        s3 = self.addSwitch("s3")
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)
        self.addLink(s1, s2)
        self.addLink(s2, s3)
        self.addLink(s3, s1)


def run_test():
    topo = TriangleTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(3)
    do_arp_all(net)
    time.sleep(3)

    result = net.pingAll()
    net.stop()

    loss_pattern = re.compile(r"(\d+)% dropped")
    match = loss_pattern.search(result)
    if match:
        dropped = int(match.group(1))
    else:
        print("FAIL: could not parse pingAll output")
        print(result)
        return False

    if dropped == 0:
        print("OK: pingAll 0%% packet loss")
        return True
    else:
        print("FAIL: pingAll %d%% packet loss" % dropped)
        return False


if __name__ == "__main__":
    setLogLevel("info")
    ok = run_test()
    sys.exit(0 if ok else 1)
