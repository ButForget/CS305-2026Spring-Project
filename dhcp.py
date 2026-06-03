from os_ken.lib import addrconv
from os_ken.lib.packet import packet
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import udp
from os_ken.lib.packet import dhcp
from os_ken.ofproto import ether
from os_ken.ofproto import inet
import collections
import socket
import struct
import time
if not hasattr(dhcp, 'DHCP_RELEASE'):
    dhcp.DHCP_RELEASE = 7
if not hasattr(dhcp, 'DHCP_NAK'):
    dhcp.DHCP_NAK = 6

class Config():
    controller_macAddr = '7e:49:b3:f0:f9:99'
    dns = '8.8.8.8'
    start_ip = '10.0.0.10'
    end_ip = '10.0.0.13'
    netmask = '255.255.255.0'
    lease_time = 86400
    server_ip = '192.168.1.1'


class DHCPServer():
    hardware_addr = Config.controller_macAddr
    start_ip = Config.start_ip
    end_ip = Config.end_ip
    netmask = Config.netmask
    dns = Config.dns

    _ip_pool = None
    _ip_pool_set = None
    _leases = {}
    _mac_bindings = {}
    _offered = {}
    _mac_offers = {}
    _pool_initialized = False

    @classmethod
    def _init_pool(cls):
        if cls._pool_initialized:
            return
        cls._ip_pool = collections.deque()
        cls._ip_pool_set = set()
        start = struct.unpack('!I', socket.inet_aton(Config.start_ip))[0]
        end = struct.unpack('!I', socket.inet_aton(Config.end_ip))[0]
        for i in range(start, end + 1):
            ip = socket.inet_ntoa(struct.pack('!I', i))
            cls._ip_pool.append(ip)
            cls._ip_pool_set.add(ip)
        cls._pool_initialized = True

    @classmethod
    def _select_ip(cls, mac, xid):
        if not cls._ip_pool:
            return None
        if mac in cls._mac_offers:
            ip = cls._mac_offers[mac]
            cls._offered[ip] = (mac, xid, time.time())
            return ip
        for _ in range(len(cls._ip_pool)):
            ip = cls._ip_pool[0]
            cls._ip_pool.rotate(-1)
            if ip not in cls._leases and ip not in cls._offered:
                cls._mac_offers[mac] = ip
                cls._offered[ip] = (mac, xid, time.time())
                return ip
        return None

    @classmethod
    def _release_ip(cls, ip):
        mac = None
        if ip in cls._leases:
            mac = cls._leases[ip].get('mac')
            del cls._leases[ip]
        if mac and mac in cls._mac_bindings and cls._mac_bindings[mac] == ip:
            del cls._mac_bindings[mac]
        if ip not in cls._ip_pool_set:
            cls._ip_pool.append(ip)
            cls._ip_pool_set.add(ip)

    @classmethod
    def _is_pool_ip(cls, ip):
        try:
            ip_int = struct.unpack('!I', socket.inet_aton(ip))[0]
            start_int = struct.unpack('!I', socket.inet_aton(Config.start_ip))[0]
            end_int = struct.unpack('!I', socket.inet_aton(Config.end_ip))[0]
        except (OSError, TypeError):
            return False
        return start_int <= ip_int <= end_int

    @classmethod
    def _is_ip_available(cls, ip, mac):
        if ip not in cls._leases:
            return True
        if cls._leases[ip]['mac'] == mac:
            return True
        return False

    @classmethod
    def _expire_leases(cls):
        now = time.time()
        expired = []
        for ip, lease in list(cls._leases.items()):
            if lease['start_time'] + lease['lease_time'] < now:
                expired.append(ip)
        for ip in expired:
            cls._release_ip(ip)

    @classmethod
    def _expire_offers(cls):
        now = time.time()
        timeout = 30
        expired = [ip for ip, (_, _, ts) in cls._offered.items()
                   if ts + timeout < now]
        for ip in expired:
            mac = cls._offered[ip][0]
            cls._mac_offers.pop(mac, None)
            del cls._offered[ip]

    @classmethod
    def handle_dhcp(cls, datapath, port, pkt):
        cls._init_pool()
        cls._expire_leases()
        cls._expire_offers()

        dhcp_objs = pkt.get_protocols(dhcp.dhcp)
        if not dhcp_objs:
            return
        dhcp_obj = dhcp_objs[0]

        msg_type_opts = [opt for opt in dhcp_obj.options.option_list
                         if opt.tag == dhcp.DHCP_MESSAGE_TYPE_OPT]
        if not msg_type_opts:
            return
        val = msg_type_opts[0].value
        msg_type = val[0] if isinstance(val, bytes) else ord(val)

        if msg_type == dhcp.DHCP_DISCOVER:
            offered_ip = cls._select_ip(dhcp_obj.chaddr, dhcp_obj.xid)
            if offered_ip:
                offer = cls.assemble_offer(pkt, datapath, offered_ip)
                cls._send_packet(datapath, port, offer)

        elif msg_type == dhcp.DHCP_REQUEST:
            client_mac = dhcp_obj.chaddr
            req_ip_opts = [opt for opt in dhcp_obj.options.option_list
                           if opt.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT]
            if req_ip_opts:
                requested_ip = addrconv.ipv4.bin_to_text(req_ip_opts[0].value)
            else:
                if dhcp_obj.ciaddr == '0.0.0.0':
                    return
                requested_ip = dhcp_obj.ciaddr
            if cls._is_ip_available(requested_ip, client_mac):
                if not cls._is_pool_ip(requested_ip):
                    nak = cls.assemble_nak(pkt, datapath)
                    cls._send_packet(datapath, port, nak)
                    return
                if requested_ip in cls._offered:
                    offered_mac = cls._offered[requested_ip][0]
                    if offered_mac != client_mac:
                        nak = cls.assemble_nak(pkt, datapath)
                        cls._send_packet(datapath, port, nak)
                        return
                    cls._mac_offers.pop(client_mac, None)
                    del cls._offered[requested_ip]
                try:
                    cls._ip_pool.remove(requested_ip)
                except ValueError:
                    pass
                cls._ip_pool_set.discard(requested_ip)
                if client_mac in cls._mac_bindings:
                    old_ip = cls._mac_bindings[client_mac]
                    if old_ip != requested_ip:
                        cls._release_ip(old_ip)
                cls._leases[requested_ip] = {
                    'mac': client_mac,
                    'start_time': time.time(),
                    'lease_time': Config.lease_time
                }
                cls._mac_bindings[client_mac] = requested_ip
                ack = cls.assemble_ack(pkt, datapath, port)
                cls._send_packet(datapath, port, ack)
            else:
                nak = cls.assemble_nak(pkt, datapath)
                cls._send_packet(datapath, port, nak)

        elif msg_type == dhcp.DHCP_RELEASE:
            client_mac = dhcp_obj.chaddr
            if client_mac in cls._mac_bindings:
                cls._release_ip(cls._mac_bindings[client_mac])

    @classmethod
    def assemble_offer(cls, pkt, datapath, offered_ip):
        dhcp_obj = pkt.get_protocols(dhcp.dhcp)[0]
        client_mac = dhcp_obj.chaddr
        xid = dhcp_obj.xid

        option_list = []
        option_list.append(dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                        value=b'\x02'))
        option_list.append(dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.netmask)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_GATEWAY_ADDR_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.server_ip)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.dns)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                                        value=struct.pack('!I', Config.lease_time)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.server_ip)))
        options = dhcp.options(option_list=option_list)

        pkt_out = packet.Packet()
        pkt_out.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',
            src=Config.controller_macAddr,
            ethertype=ether.ETH_TYPE_IP))
        pkt_out.add_protocol(ipv4.ipv4(
            dst='255.255.255.255',
            src=Config.server_ip,
            proto=inet.IPPROTO_UDP))
        pkt_out.add_protocol(udp.udp(
            src_port=67,
            dst_port=68))
        pkt_out.add_protocol(dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            htype=1,
            hlen=6,
            xid=xid,
            yiaddr=offered_ip,
            siaddr=Config.server_ip,
            chaddr=client_mac,
            options=options))
        return pkt_out

    @classmethod
    def assemble_ack(cls, pkt, datapath, port):
        dhcp_obj = pkt.get_protocols(dhcp.dhcp)[0]
        client_mac = dhcp_obj.chaddr
        xid = dhcp_obj.xid

        req_ip_opts = [opt for opt in dhcp_obj.options.option_list
                       if opt.tag == dhcp.DHCP_REQUESTED_IP_ADDR_OPT]
        if req_ip_opts:
            ack_ip = addrconv.ipv4.bin_to_text(req_ip_opts[0].value)
        elif dhcp_obj.ciaddr and dhcp_obj.ciaddr != '0.0.0.0':
            ack_ip = dhcp_obj.ciaddr
        else:
            ack_ip = '0.0.0.0'

        option_list = []
        option_list.append(dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                        value=b'\x05'))
        option_list.append(dhcp.option(tag=dhcp.DHCP_SUBNET_MASK_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.netmask)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_GATEWAY_ADDR_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.server_ip)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_DNS_SERVER_ADDR_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.dns)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_IP_ADDR_LEASE_TIME_OPT,
                                        value=struct.pack('!I', Config.lease_time)))
        option_list.append(dhcp.option(tag=dhcp.DHCP_SERVER_IDENTIFIER_OPT,
                                        value=addrconv.ipv4.text_to_bin(Config.server_ip)))
        options = dhcp.options(option_list=option_list)

        pkt_out = packet.Packet()
        pkt_out.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',
            src=Config.controller_macAddr,
            ethertype=ether.ETH_TYPE_IP))
        pkt_out.add_protocol(ipv4.ipv4(
            dst='255.255.255.255',
            src=Config.server_ip,
            proto=inet.IPPROTO_UDP))
        pkt_out.add_protocol(udp.udp(
            src_port=67,
            dst_port=68))
        pkt_out.add_protocol(dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            htype=1,
            hlen=6,
            xid=xid,
            yiaddr=ack_ip,
            siaddr=Config.server_ip,
            chaddr=client_mac,
            options=options))
        return pkt_out

    @classmethod
    def assemble_nak(cls, pkt, datapath):
        dhcp_obj = pkt.get_protocols(dhcp.dhcp)[0]
        client_mac = dhcp_obj.chaddr
        xid = dhcp_obj.xid

        option_list = []
        option_list.append(dhcp.option(tag=dhcp.DHCP_MESSAGE_TYPE_OPT,
                                        value=b'\x06'))
        option_list.append(dhcp.option(tag=dhcp.DHCP_MESSAGE_OPT,
                                        value=b'Requested address not available'))
        options = dhcp.options(option_list=option_list)

        pkt_out = packet.Packet()
        pkt_out.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff',
            src=Config.controller_macAddr,
            ethertype=ether.ETH_TYPE_IP))
        pkt_out.add_protocol(ipv4.ipv4(
            dst='255.255.255.255',
            src=Config.server_ip,
            proto=inet.IPPROTO_UDP))
        pkt_out.add_protocol(udp.udp(
            src_port=67,
            dst_port=68))
        pkt_out.add_protocol(dhcp.dhcp(
            op=dhcp.DHCP_BOOT_REPLY,
            htype=1,
            hlen=6,
            xid=xid,
            yiaddr='0.0.0.0',
            siaddr=Config.server_ip,
            chaddr=client_mac,
            options=options))
        return pkt_out

    @classmethod
    def _send_packet(cls, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if isinstance(pkt, str):
            pkt = pkt.encode()
        pkt.serialize()
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)
