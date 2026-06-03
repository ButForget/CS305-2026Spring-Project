# test_firewall.py

import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


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


class FirewallTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)

        h1 = self.addHost('h1', ip='192.168.117.2/24')
        h2 = self.addHost('h2', ip='192.168.117.3/24')
        h3 = self.addHost('h3', ip='192.168.117.4/24')

        s1 = self.addSwitch('s1')

        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)


def run_mininet():
    topo = FirewallTopo()

    net = Mininet(
        topo=topo,
        autoSetMacs=True,
        controller=RemoteController
    )

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

    for _ in range(3):
        do_arp_all(net)
        time.sleep(1)

    # print('\n===== Start HTTP servers on h2 =====')
    h2.cmd('pkill -f "python3 -m http.server" || true')
    h2.cmd('python3 -m http.server 80 --bind 192.168.117.3 >/tmp/h2-http80.log 2>&1 &')
    h2.cmd('python3 -m http.server 8080 --bind 192.168.117.3 >/tmp/h2-http8080.log 2>&1 &')
    time.sleep(1)

    # Test 1: h1 -> h2 ICMP should FAIL
    print(h1.cmd('ping -c 2 -W 1 192.168.117.3'))

    # Test 2: h1 -> h3 ICMP should PASS
    print(h1.cmd('ping -c 2 -W 1 192.168.117.4'))

    # Test 3: h1 -> h2 TCP/80 should FAIL
    print(curl(h1, 'http://192.168.117.3:80/'))

    # Test 4: h1 -> h2 TCP/8080 should PASS
    print(curl(h1, 'http://192.168.117.3:8080/'))

    # Flow table on s1
    # print(s1.cmd('ovs-ofctl -O OpenFlow10 dump-flows s1'))

    # Ping all hosts to show firewall filtering effect
    print('\n===== Ping All Test (expect h1->h2 blocked) =====')
    net.pingAll()

    CLI(net)

    h2.cmd('pkill -f "python3 -m http.server" || true')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()