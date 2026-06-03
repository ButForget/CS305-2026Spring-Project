"""
NAT (Network Address Translation) module for the SDN controller.

Implements SNAT/DNAT between an internal subnet and an external subnet.
The controller intercepts IP packets crossing subnet boundaries, rewrites
source/destination IP addresses, and maintains a connection-tracking table
for reverse translation.

Configuration:
  - Internal subnet:  10.0.1.0/24
  - External subnet:  10.0.2.0/24
  - NAT external IP:  10.0.2.100

Supports ICMP, TCP, and UDP protocols.
"""

import struct
import socket
import time

from os_ken.lib.packet import ethernet, ipv4, icmp, tcp, udp


class NAT:
    """SNAT/DNAT implementation for the SDN controller."""

    # Subnet definitions
    INTERNAL_SUBNET = "10.0.1.0"
    INTERNAL_NETMASK = "255.255.255.0"
    EXTERNAL_SUBNET = "10.0.2.0"
    EXTERNAL_NETMASK = "255.255.255.0"
    NAT_EXTERNAL_IP = "10.0.2.100"

    # Connection tracking: {(proto, internal_ip, internal_port, external_ip, external_port): nat_port}
    _connections = {}

    # For ICMP: {(proto, internal_ip, 0, external_ip, 0): (icmp_id, timestamp)}
    # (reuses the same 5-tuple key shape as _connections with zero placeholders)
    _icmp_connections = {}

    # Next available NAT port for TCP/UDP (ephemeral range)
    _next_nat_port = 50000
    _nat_port_max = 60000

    # Timeout for idle connections (seconds)
    CONNECTION_TIMEOUT = 300

    @classmethod
    def _ip_in_subnet(cls, ip, subnet, netmask):
        """Check if an IP address is within a subnet."""
        try:
            ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
            sub_int = struct.unpack("!I", socket.inet_aton(subnet))[0]
            mask_int = struct.unpack("!I", socket.inet_aton(netmask))[0]
            return (ip_int & mask_int) == (sub_int & mask_int)
        except Exception:
            return False

    @classmethod
    def is_internal(cls, ip):
        """Return True if the IP is in the internal subnet."""
        return cls._ip_in_subnet(ip, cls.INTERNAL_SUBNET, cls.INTERNAL_NETMASK)

    @classmethod
    def is_external(cls, ip):
        """Return True if the IP is in the external subnet."""
        return cls._ip_in_subnet(ip, cls.EXTERNAL_SUBNET, cls.EXTERNAL_NETMASK)

    @classmethod
    def needs_nat(cls, src_ip, dst_ip):
        """Return True if the packet crosses from internal to external or vice versa."""
        src_internal = cls.is_internal(src_ip)
        dst_external = cls.is_external(dst_ip)
        src_external = cls.is_external(src_ip)
        dst_internal = cls.is_internal(dst_ip)

        # Internal → External (SNAT) or External → NAT IP (DNAT)
        return (src_internal and dst_external) or \
               (src_external and dst_ip == cls.NAT_EXTERNAL_IP) or \
               (src_external and dst_internal)

    @classmethod
    def _get_nat_port(cls):
        """Allocate a NAT port for TCP/UDP translation (skip ports already in use)."""
        used_ports = {info["nat_port"] for info in cls._connections.values()}
        for _ in range(cls._nat_port_max - 50000 + 1):
            port = cls._next_nat_port
            cls._next_nat_port += 1
            if cls._next_nat_port > cls._nat_port_max:
                cls._next_nat_port = 50000
            if port not in used_ports:
                return port
        # Fallback (all ports exhausted — extremely unlikely)
        port = cls._next_nat_port
        cls._next_nat_port += 1
        if cls._next_nat_port > cls._nat_port_max:
            cls._next_nat_port = 50000
        return port

    @classmethod
    def _cleanup_expired(cls):
        """Remove expired connection entries (TCP/UDP and ICMP)."""
        now = time.time()
        expired_keys = [
            k for k, v in cls._connections.items()
            if now - v.get("timestamp", 0) > cls.CONNECTION_TIMEOUT
        ]
        for k in expired_keys:
            del cls._connections[k]

        # Also expire ICMP connection entries
        expired_icmp = [
            k for k, (_, ts) in cls._icmp_connections.items()
            if now - ts > cls.CONNECTION_TIMEOUT
        ]
        for k in expired_icmp:
            del cls._icmp_connections[k]

    @classmethod
    def handle_nat(cls, datapath, in_port, pkt, hosts, arp_table, controller_mac):
        """
        Process a packet that needs NAT translation.
        Returns (out_port, raw_packet_bytes) or (None, None).

        Args:
            datapath: switch datapath
            in_port: input port
            pkt: parsed packet
            hosts: {mac: (dpid, port, ip)} host location dict
            arp_table: {ip: mac} mapping
            controller_mac: controller's MAC address
        """
        import logging
        logger = logging.getLogger(__name__)

        eth = pkt.get_protocol(ethernet.ethernet)
        ip_hdr = pkt.get_protocol(ipv4.ipv4)

        if not eth or not ip_hdr:
            return None, None

        src_ip = ip_hdr.src
        dst_ip = ip_hdr.dst
        proto = ip_hdr.proto

        cls._cleanup_expired()

        # --- Outbound: Internal → External (SNAT) ---
        if cls.is_internal(src_ip) and cls.is_external(dst_ip):
            return cls._handle_snat(datapath, in_port, pkt, eth, ip_hdr,
                                    hosts, arp_table, controller_mac, logger)

        # --- Inbound: External → Internal (DNAT) ---
        if cls.is_external(src_ip) and (cls.is_internal(dst_ip) or dst_ip == cls.NAT_EXTERNAL_IP):
            return cls._handle_dnat(datapath, in_port, pkt, eth, ip_hdr,
                                    hosts, arp_table, controller_mac, logger)

        # --- Inbound to NAT IP (fallback) ---
        if dst_ip == cls.NAT_EXTERNAL_IP:
            return cls._handle_dnat(datapath, in_port, pkt, eth, ip_hdr,
                                    hosts, arp_table, controller_mac, logger)

        return None, None

    @classmethod
    def _find_host_port(cls, ip, hosts, arp_table):
        """Find the output port for a given destination IP."""
        if ip in arp_table:
            mac = arp_table[ip]
            if mac in hosts:
                _, port, _ = hosts[mac]
                return port
        return None

    @classmethod
    def _handle_snat(cls, datapath, in_port, pkt, eth, ip_hdr,
                     hosts, arp_table, controller_mac, logger):
        """SNAT: rewrite src IP to NAT_EXTERNAL_IP and adjust MACs."""
        pkt.serialize()
        raw = bytearray(pkt.data)

        old_src_ip = ip_hdr.src
        new_src_ip = cls.NAT_EXTERNAL_IP
        dst_ip = ip_hdr.dst

        # Find output port for destination
        out_port = cls._find_host_port(dst_ip, hosts, arp_table)
        if out_port is None:
            logger.debug("SNAT: cannot find output port for %s", dst_ip)
            return None, None

        # Get destination MAC
        dst_mac = arp_table.get(dst_ip, None)
        if not dst_mac:
            logger.debug("SNAT: cannot find MAC for %s", dst_ip)
            return None, None

        proto = ip_hdr.proto
        old_src_port = 0
        new_src_port = 0

        tcp_hdr = pkt.get_protocol(tcp.tcp)
        udp_hdr = pkt.get_protocol(udp.udp)

        # Track connection for TCP/UDP
        if tcp_hdr:
            old_src_port = tcp_hdr.src_port
            conn_key = (proto, old_src_ip, old_src_port, dst_ip, tcp_hdr.dst_port)
            if conn_key in cls._connections:
                new_src_port = cls._connections[conn_key]["nat_port"]
                cls._connections[conn_key]["timestamp"] = time.time()
            else:
                new_src_port = cls._get_nat_port()
                cls._connections[conn_key] = {
                    "nat_port": new_src_port,
                    "timestamp": time.time(),
                    "dst_ip": dst_ip,
                }
        elif udp_hdr:
            old_src_port = udp_hdr.src_port
            conn_key = (proto, old_src_ip, old_src_port, dst_ip, udp_hdr.dst_port)
            if conn_key in cls._connections:
                new_src_port = cls._connections[conn_key]["nat_port"]
                cls._connections[conn_key]["timestamp"] = time.time()
            else:
                new_src_port = cls._get_nat_port()
                cls._connections[conn_key] = {
                    "nat_port": new_src_port,
                    "timestamp": time.time(),
                    "dst_ip": dst_ip,
                }
        else:
            icmp_hdr = pkt.get_protocol(icmp.icmp)
            if icmp_hdr:
                conn_key = (proto, old_src_ip, 0, dst_ip, 0)
                cls._icmp_connections[conn_key] = (0, time.time())

        # Rewrite source IP FIRST (so TCP/UDP checksum uses new IP)
        raw = cls._rewrite_ip_src(raw, old_src_ip, new_src_ip)

        # Then rewrite TCP/UDP ports (which recomputes checksum with new IP)
        if tcp_hdr:
            raw = cls._rewrite_tcp_ports(raw, old_src_port, new_src_port,
                                         tcp_hdr.dst_port, tcp_hdr.dst_port)
        elif udp_hdr:
            raw = cls._rewrite_udp_ports(raw, old_src_port, new_src_port,
                                         udp_hdr.dst_port, udp_hdr.dst_port)

        # Rewrite Ethernet MACs: src=controller_mac, dst=actual_dst_mac
        raw = cls._rewrite_eth_macs(raw, controller_mac, dst_mac)

        logger.info("SNAT: %s:%d -> %s:%d (to %s:%d, out_port=%d)",
                     old_src_ip, old_src_port, new_src_ip, new_src_port,
                     dst_ip, tcp_hdr.dst_port if tcp_hdr else (udp_hdr.dst_port if udp_hdr else 0), out_port)

        return out_port, bytes(raw)

    @classmethod
    def _handle_dnat(cls, datapath, in_port, pkt, eth, ip_hdr,
                     hosts, arp_table, controller_mac, logger):
        """DNAT: rewrite dst IP back to original internal IP and adjust MACs."""
        pkt.serialize()
        raw = bytearray(pkt.data)

        proto = ip_hdr.proto
        dst_ip = ip_hdr.dst
        src_ip = ip_hdr.src

        tcp_hdr = pkt.get_protocol(tcp.tcp)
        udp_hdr = pkt.get_protocol(udp.udp)

        # Find the original connection (get IP and ports first)
        original_ip = None
        original_port = 0
        original_src_port = 0
        has_ports = False

        if tcp_hdr:
            has_ports = True
            dst_port = tcp_hdr.dst_port
            src_port = tcp_hdr.src_port
            for conn_key, info in cls._connections.items():
                (p, oip, oport, eip, eport) = conn_key
                if (info["nat_port"] == dst_port and p == proto
                        and eip == src_ip and eport == src_port):
                    original_ip = oip
                    original_port = oport
                    original_src_port = eport
                    info["timestamp"] = time.time()
                    break
        elif udp_hdr:
            has_ports = True
            dst_port = udp_hdr.dst_port
            src_port = udp_hdr.src_port
            for conn_key, info in cls._connections.items():
                (p, oip, oport, eip, eport) = conn_key
                if (info["nat_port"] == dst_port and p == proto
                        and eip == src_ip and eport == src_port):
                    original_ip = oip
                    original_port = oport
                    original_src_port = eport
                    info["timestamp"] = time.time()
                    break
        else:
            for (p, oip, oport, eip, eport), info in cls._connections.items():
                if eip == src_ip and p == proto:
                    original_ip = oip
                    info["timestamp"] = time.time()
                    break
            if not original_ip:
                for conn_key, (icmp_id, ts) in cls._icmp_connections.items():
                    (p, oip, oport, eip, eport) = conn_key
                    if eip == src_ip:
                        original_ip = oip
                        cls._icmp_connections[conn_key] = (icmp_id, time.time())
                        break

        if not original_ip:
            logger.debug("DNAT: no connection found for dst=%s src=%s", dst_ip, src_ip)
            return None, None

        # Rewrite destination IP FIRST
        raw = cls._rewrite_ip_dst(raw, dst_ip, original_ip)

        # Then rewrite TCP/UDP ports (checksum uses new IP)
        if has_ports:
            if tcp_hdr:
                # Keep source port unchanged, rewrite destination port from NAT_PORT to original_port
                raw = cls._rewrite_tcp_ports(raw,
                                             src_port, src_port,
                                             dst_port, original_port)
            else:
                raw = cls._rewrite_udp_ports(raw,
                                             src_port, src_port,
                                             dst_port, original_port)
        original_mac = arp_table.get(original_ip, None)
        if not original_mac:
            logger.debug("DNAT: cannot find MAC for original IP %s", original_ip)
            return None, None

        raw = cls._rewrite_eth_macs(raw, controller_mac, original_mac)

        # Find output port for original host
        out_port = cls._find_host_port(original_ip, hosts, arp_table)
        if out_port is None:
            logger.debug("DNAT: cannot find output port for %s", original_ip)
            return None, None

        logger.info("DNAT: %s -> %s (from %s, out_port=%d)",
                     dst_ip, original_ip, src_ip, out_port)

        return out_port, bytes(raw)

    # ------------------------------------------------------------------
    # Raw packet rewriting helpers
    # ------------------------------------------------------------------

    @classmethod
    def _rewrite_eth_macs(cls, raw, src_mac_str, dst_mac_str):
        """Rewrite Ethernet source and destination MAC addresses."""
        src_bytes = cls._mac_to_bytes(src_mac_str)
        dst_bytes = cls._mac_to_bytes(dst_mac_str)
        # Ethernet header: dst MAC (6 bytes), src MAC (6 bytes)
        raw[0:6] = dst_bytes
        raw[6:12] = src_bytes
        return raw

    @staticmethod
    def _mac_to_bytes(mac_str):
        """Convert 'aa:bb:cc:dd:ee:ff' to bytes."""
        return bytes(int(b, 16) for b in mac_str.split(":"))

    @classmethod
    def _rewrite_ip_src(cls, raw, old_ip, new_ip):
        """Rewrite source IP at exact offset 26 (14 eth + 12) and update IP checksum."""
        new_bytes = socket.inet_aton(new_ip)
        src_offset = 26  # 14 (Ethernet) + 12 (offset of src IP in IP header)
        raw[src_offset:src_offset + 4] = new_bytes
        cls._update_ip_checksum(raw, 14)
        return raw

    @classmethod
    def _rewrite_ip_dst(cls, raw, old_ip, new_ip):
        """Rewrite destination IP at exact offset 30 (14 eth + 16) and update IP checksum."""
        new_bytes = socket.inet_aton(new_ip)
        dst_offset = 30  # 14 (Ethernet) + 16 (offset of dst IP in IP header)
        raw[dst_offset:dst_offset + 4] = new_bytes
        cls._update_ip_checksum(raw, 14)
        return raw

    @classmethod
    def _rewrite_tcp_ports(cls, raw, old_src_port, new_src_port,
                           old_dst_port, new_dst_port):
        """Rewrite TCP source/destination ports and update TCP checksum."""
        # Find TCP header (after IP header)
        ip_start = 14
        ip_hdr_len = (raw[ip_start] & 0x0F) * 4
        tcp_start = ip_start + ip_hdr_len

        # Source port at offset 0 of TCP header, dest port at offset 2
        struct.pack_into("!H", raw, tcp_start, new_src_port)
        struct.pack_into("!H", raw, tcp_start + 2, new_dst_port)

        # Update TCP checksum (offset 16 of TCP header)
        # Set checksum to 0 first, then recalculate
        struct.pack_into("!H", raw, tcp_start + 16, 0)

        # TCP checksum includes pseudo-header
        src_ip = socket.inet_ntoa(bytes(raw[ip_start + 12:ip_start + 16]))
        dst_ip = socket.inet_ntoa(bytes(raw[ip_start + 16:ip_start + 20]))
        ip_total_len = struct.unpack("!H", raw[ip_start + 2:ip_start + 4])[0]
        ip_hdr_len = (raw[ip_start] & 0x0F) * 4
        tcp_len = ip_total_len - ip_hdr_len
        pseudo = cls._tcp_udp_pseudo_header(src_ip, dst_ip, 6, tcp_len)
        tcp_segment = bytes(raw[tcp_start:tcp_start + tcp_len])
        csum = cls._checksum(pseudo + tcp_segment)
        struct.pack_into("!H", raw, tcp_start + 16, csum)

        return raw

    @classmethod
    def _rewrite_udp_ports(cls, raw, old_src_port, new_src_port,
                           old_dst_port, new_dst_port):
        """Rewrite UDP source/destination ports and update UDP checksum."""
        ip_start = 14
        ip_hdr_len = (raw[ip_start] & 0x0F) * 4
        udp_start = ip_start + ip_hdr_len

        struct.pack_into("!H", raw, udp_start, new_src_port)
        struct.pack_into("!H", raw, udp_start + 2, new_dst_port)

        # Update UDP checksum (offset 6 of UDP header)
        struct.pack_into("!H", raw, udp_start + 6, 0)
        src_ip = socket.inet_ntoa(bytes(raw[ip_start + 12:ip_start + 16]))
        dst_ip = socket.inet_ntoa(bytes(raw[ip_start + 16:ip_start + 20]))
        ip_total_len = struct.unpack("!H", raw[ip_start + 2:ip_start + 4])[0]
        ip_hdr_len = (raw[ip_start] & 0x0F) * 4
        udp_len = ip_total_len - ip_hdr_len
        pseudo = cls._tcp_udp_pseudo_header(src_ip, dst_ip, 17, udp_len)
        udp_segment = bytes(raw[udp_start:udp_start + udp_len])
        if len(udp_segment) % 2:
            udp_segment += b"\x00"
        csum = cls._checksum(pseudo + udp_segment)
        if csum == 0:
            csum = 0xFFFF  # RFC 768: 0 means no checksum, use 0xFFFF
        struct.pack_into("!H", raw, udp_start + 6, csum)

        return raw

    @classmethod
    def _update_ip_checksum(cls, raw, ip_start):
        """Recalculate the IP header checksum."""
        # Zero out the existing checksum (bytes 10-11 of IP header)
        struct.pack_into("!H", raw, ip_start + 10, 0)
        ip_hdr_len = (raw[ip_start] & 0x0F) * 4
        ip_hdr = bytes(raw[ip_start:ip_start + ip_hdr_len])
        csum = cls._checksum(ip_hdr)
        struct.pack_into("!H", raw, ip_start + 10, csum)

    @classmethod
    def _tcp_udp_pseudo_header(cls, src_ip, dst_ip, protocol, length):
        """Build the 12-byte pseudo-header for TCP/UDP checksum calculation."""
        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)
        return struct.pack("!4s4sBBH", src, dst, 0, protocol, length)

    @staticmethod
    def _checksum(data):
        """Compute 16-bit one's complement checksum."""
        if len(data) % 2:
            data += b"\x00"
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF
