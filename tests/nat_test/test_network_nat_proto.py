# test_network_nat_proto.py
# NAT protocol coverage test: ICMP + UDP + TCP through NAT.
#
# Topology:
#   h1 (10.0.1.2) -- s1 -- s2 -- h2 (10.0.2.2)
#   (internal)             (external)
#
# Tests ICMP flow tracking (identifier-based, portless),
# UDP datagram translation (connectionless, port-mapped), and
# TCP stream translation (connection-oriented, port-mapped).
#
# Usage:
#   1. Start controller:  osken-manager --observe-links controller.py
#   2. Run this script:   sudo env "PATH=$PATH" python test_network_nat_proto.py

import time
import re

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo


NAT_EXTERNAL_IP = "10.0.2.100"


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


class NATTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        h1 = self.addHost('h1', ip='10.0.1.2/16')
        h2 = self.addHost('h2', ip='10.0.2.2/16')
        self.addLink(h1, s1)
        self.addLink(s1, s2)
        self.addLink(s2, h2)


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
    print()

    for _ in range(3):
        for h in net.hosts:
            send_garp(h)
        time.sleep(1)

    # ---- Tests ----
    print('--- ICMP + UDP + TCP NAT Verification ---')
    all_ok = True

    # ===== ICMP Tests =====
    print('  [ICMP]')

    # Single ICMP flow
    all_ok &= run_one_test('h1->h2 ping (1 flow)',
                           ping_ok(h1, h2.IP()))
    all_ok &= run_one_test('h2->h1 ping (reverse)',
                           ping_ok(h2, h1.IP()))

    # Concurrent ICMP: two pings from h1 simultaneously, both should get replies
    h1.cmd('ping -c 4 -W 2 %s > /tmp/p1.txt 2>&1 &' % h2.IP())
    time.sleep(0.2)
    h1.cmd('ping -c 4 -W 2 %s > /tmp/p2.txt 2>&1 &' % h2.IP())
    time.sleep(12)
    r1 = h1.cmd('cat /tmp/p1.txt 2>/dev/null')
    r2 = h1.cmd('cat /tmp/p2.txt 2>/dev/null')
    h1.cmd('rm -f /tmp/p1.txt /tmp/p2.txt')
    p1 = ' 0% packet loss' in r1 or bool(re.search(r'[1-9]\d* received', r1))
    p2 = ' 0% packet loss' in r2 or bool(re.search(r'[1-9]\d* received', r2))
    all_ok &= run_one_test('h1->h2 2 concurrent pings (flow A)', p1)
    all_ok &= run_one_test('h1->h2 2 concurrent pings (flow B)', p2)

    # ===== UDP Tests =====
    print('  [UDP]')

    # Start UDP echo server on h2
    server_script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('', 22348))\n"
        "s.settimeout(6)\n"
        "try:\n"
        "    data, addr = s.recvfrom(1024)\n"
        "    s.sendto(b'ECHO:' + data, addr)\n"
        "    print('GOT:' + str(addr[1]))\n"
        "except socket.timeout:\n"
        "    print('TIMEOUT')\n"
        "finally:\n"
        "    s.close()\n"
    )
    h2.cmd("echo '%s' > /tmp/udp_srv.py" % server_script.replace("'", "'\"'\"'"))
    h2.cmd("python3 /tmp/udp_srv.py > /tmp/udp_out.txt 2>/dev/null &")
    time.sleep(0.5)

    # h1 sends UDP datagram and receives echo
    client_script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "s.settimeout(4)\n"
        "s.sendto(b'HELLO', ('%s', 22348))\n"
        "try:\n"
        "    data, addr = s.recvfrom(1024)\n"
        "    print(data.decode())\n"
        "except socket.timeout:\n"
        "    print('TIMEOUT')\n"
        "finally:\n"
        "    s.close()\n" % h2.IP()
    )
    h1.cmd("echo '%s' > /tmp/udp_cli.py" % client_script.replace("'", "'\"'\"'"))
    udp_result = h1.cmd("python3 /tmp/udp_cli.py 2>/dev/null").strip()
    h2.cmd("pkill -f udp_srv.py 2>/dev/null; true")
    h1.cmd("rm -f /tmp/udp_cli.py")
    h2.cmd("rm -f /tmp/udp_srv.py /tmp/udp_out.txt")

    all_ok &= run_one_test('UDP h1->h2 echo (expect ECHO:HELLO)',
                           'ECHO:HELLO' in udp_result)

    # ===== TCP Tests =====
    print('  [TCP]')

    # Start TCP echo server on h2
    tcp_server_script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "s.bind(('', 22349))\n"
        "s.listen(1)\n"
        "s.settimeout(6)\n"
        "try:\n"
        "    conn, addr = s.accept()\n"
        "    data = conn.recv(1024)\n"
        "    conn.sendall(b'ECHO:' + data)\n"
        "    conn.close()\n"
        "    print('GOT:' + str(addr[1]))\n"
        "except socket.timeout:\n"
        "    print('TIMEOUT')\n"
        "finally:\n"
        "    s.close()\n"
    )
    h2.cmd("echo '%s' > /tmp/tcp_srv.py" % tcp_server_script.replace("'", "'\"'\"'"))
    h2.cmd("python3 /tmp/tcp_srv.py > /tmp/tcp_out.txt 2>/dev/null &")
    time.sleep(0.5)

    # h1 connects via TCP and receives echo
    tcp_client_script = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "s.settimeout(4)\n"
        "s.connect(('%s', 22349))\n"
        "s.sendall(b'HELLO')\n"
        "data = s.recv(1024)\n"
        "print(data.decode())\n"
        "s.close()\n" % h2.IP()
    )
    h1.cmd("echo '%s' > /tmp/tcp_cli.py" % tcp_client_script.replace("'", "'\"'\"'"))
    tcp_result = h1.cmd("python3 /tmp/tcp_cli.py 2>/dev/null").strip()
    h2.cmd("pkill -f tcp_srv.py 2>/dev/null; true")
    h1.cmd("rm -f /tmp/tcp_cli.py")
    h2.cmd("rm -f /tmp/tcp_srv.py /tmp/tcp_out.txt")

    all_ok &= run_one_test('TCP h1->h2 echo (expect ECHO:HELLO)',
                           'ECHO:HELLO' in tcp_result)

    print('  -> %s' % ('ALL PASSED' if all_ok else 'SOME FAILED'))
    print()

    print('Try in CLI: h1 ping %s' % h2.IP())
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run_mininet()
