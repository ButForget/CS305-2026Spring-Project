"""
Non-interactive CI test for the DHCP module.

Replaces the interactive CLI of test_network.py with automated assertions.
Expects the os-ken controller to already be running (osken-manager --observe-links controller.py).
"""

import sys
import time
import socket
import struct

from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")


def send_dhcp(node):
    node.cmd("dhclient -v %s-eth0 2>/dev/null" % node.name)


def ip_to_int(ip_str):
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


class DHCPTestTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        h1 = self.addHost("h1", ip="no ip defined/8")
        h2 = self.addHost("h2", ip="no ip defined/8")
        s1 = self.addSwitch("s1")
        self.addLink(h1, s1)
        self.addLink(h2, s1)


def run_test():
    topo = DHCPTestTopo()
    net = Mininet(topo=topo, autoSetMacs=True, controller=RemoteController)

    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)

    net.start()
    time.sleep(2)

    for h in net.hosts:
        send_dhcp(h)

    time.sleep(3)

    passed = True
    start_ip = ip_to_int("192.168.1.1")
    end_ip = ip_to_int("192.168.1.100")

    for h in net.hosts:
        ip_str = h.IP()
        if ip_str is None:
            print("FAIL: %s has no IP address" % h.name)
            passed = False
            continue

        ip_int = ip_to_int(ip_str)
        if start_ip < ip_int <= end_ip:
            print("OK: %s assigned IP %s" % (h.name, ip_str))
        else:
            print("FAIL: %s assigned IP %s (expected 192.168.1.2–192.168.1.100)" % (h.name, ip_str))
            passed = False

    net.stop()
    return passed


if __name__ == "__main__":
    setLogLevel("info")
    ok = run_test()
    sys.exit(0 if ok else 1)
