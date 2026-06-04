"""
DNS Server module for the SDN controller.

Intercepts DNS queries (UDP port 53) addressed to the controller's DNS server IP
(192.168.1.1) and returns responses for registered hostnames.  Hostnames are
automatically registered when the controller learns host locations via ARP/IP
traffic (in controller.py:_learn_host_from_packet).  Static mappings can also be
added via register_host().

Supports:
  - A record queries (hostname -> IP)
  - PTR record queries (IP -> hostname, reverse lookup)
  - NXDOMAIN for unknown hostnames
"""

import struct
import socket



class DNSServer:
    """Simple DNS server that runs inside the SDN controller."""

    # DNS constants
    TYPE_A = 1          # A 记录：域名 → IPv4
    TYPE_PTR = 12       # PTR 记录：IP → 域名（反向解析）
    CLASS_IN = 1        # Internet 类，DNS 查询几乎都是 IN
    RCODE_NOERROR = 0   # 响应码：成功
    RCODE_NXDOMAIN = 3  # 响应码：域名不存在
    RCODE_SERVFAIL = 2  # 响应码：服务器失败（不支持该查询类型）

    # DNS server IP (must match Config.server_ip)
    server_ip = '192.168.1.1'

    # Reserved for future DNS forwarding support
    upstream_dns = "8.8.8.8"

    # Hostname -> IP mappings
    _hostname_to_ip = {}

    # IP -> Hostname mappings (for PTR)
    _ip_to_hostname = {}

    @classmethod
    def register_host(cls, hostname, ip):
        """Register a hostname-to-IP mapping (e.g., after DHCP lease)."""
        # 当控制器通过 ARP 学到某个 IP 的主机名，或 DHCP 分配了租约后，会调用此方法注册映射
        if not hostname or not ip:
            return
        cls._hostname_to_ip[hostname] = ip
        cls._ip_to_hostname[ip] = hostname

    @classmethod
    def handle_dns(cls, datapath, in_port, pkt, raw_data=None):
        """
        Process a DNS query packet.
        Returns raw response bytes, or None.
        """
        from os_ken.lib.packet import ethernet, ipv4, udp

        eth = pkt.get_protocol(ethernet.ethernet)
        ip_hdr = pkt.get_protocol(ipv4.ipv4)
        udp_hdr = pkt.get_protocol(udp.udp)

        # Ethernet + IPv4 + UDP port
        if not eth or not ip_hdr or not udp_hdr:
            return None

        if ip_hdr.dst != cls.server_ip:
            return None
        if udp_hdr.dst_port != 53:
            return None

        try:
            dns_data = cls._get_raw_payload(raw_data)
            if not dns_data or len(dns_data) < 12: # dns header is 12 bytes
                return None

            # build response package
            response = cls._build_response(
                dns_data, 
                src_mac=eth.dst, 
                dst_mac=eth.src,
                
                src_ip=ip_hdr.dst, 
                dst_ip=ip_hdr.src,
                
                src_port=udp_hdr.dst_port, 
                dst_port=udp_hdr.src_port
            )
            return response

        except Exception:
            return None

    @classmethod
    def _get_raw_payload(cls, raw_data):
        """Extract DNS payload bytes from the original PacketIn raw data."""
        if not raw_data or len(raw_data) < 42: # 42 = eth_min(14) + ip(20) + udp(8)
            return None

        # Ethernet: 14 bytes. IP header length is in lower nibble of byte 0 of IP.
        ip_hdr_len = (raw_data[14] & 0x0F) * 4 # ip_head_len is at last half of the ip datagram
        # UDP header starts after Ethernet + IP header
        udp_start = 14 + ip_hdr_len            # udp start bit
        # DNS payload starts after UDP header (8 bytes)
        dns_start = udp_start + 8              # dns start bit

        # UDP length field at offset 4 of UDP header
        if udp_start + 6 > len(raw_data):
            return None
        udp_len = struct.unpack("!H", raw_data[udp_start + 4:udp_start + 6])[0]
        dns_len = udp_len - 8  # minus UDP header bytes

        if dns_len <= 0:
            return None
        if dns_start + dns_len > len(raw_data):
            dns_len = len(raw_data) - dns_start # minus other data

        return raw_data[dns_start:dns_start + dns_len] # return dns data

    @classmethod
    def _build_response(cls, dns_query, src_mac, dst_mac,
                        src_ip, dst_ip, src_port, dst_port):
        """Build DNS response as raw bytes using os-ken serialization."""
        # trans_id	事务 ID，响应必须原样返回，客户端用它匹配请求和响应
        # flags	标志位（QR/Opcode/AA/TC/RD/RA/Z/RCODE）
        # qdcount	Question 数量（查询通常为 1）
        # ancount	Answer 数量（查询中为 0）
        # nscount	Authority 数量
        # arcount	Additional 数量

        if len(dns_query) < 12:
            return None

        trans_id, flags, qdcount, ancount, nscount, arcount = \
            struct.unpack("!HHHHHH", dns_query[:12])

        qr = (flags >> 15) & 1
        if qr != 0: 
            return None

        # Only support single-question queries
        if qdcount != 1: # no action when is response
            return None

        pos = 12         # data after host
        qname_labels = []
        qname_raw_start = pos
        ended_on_pointer = False

        # QNAME
        # dns encode with label like : \x03 w w w \x07 e x a m p l e \x03 c o m \x00
        # dns encode wtth ptr   like : \x03 w w w 0xC0 0x0C
        while pos < len(dns_query) and dns_query[pos] != 0:

            # ptr than break
            if (dns_query[pos] & 0xC0) == 0xC0:
                pos += 2
                ended_on_pointer = True
                break

            # label than work
            length = dns_query[pos]
            pos += 1
            if pos + length > len(dns_query):
                return None
            qname_labels.append(dns_query[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        
        # join with .
        qname = ".".join(qname_labels)
        if not ended_on_pointer:
            pos += 1  # Skip the zero terminator (only when name ended normally)
        

        if pos + 4 > len(dns_query):
            return None
        qtype, qclass = struct.unpack("!HH", dns_query[pos:pos + 4]) # get tpye
        qname_raw = dns_query[qname_raw_start:pos]

        #  QTYPE 
        response_answers = b""    # answer section
        rcode = cls.RCODE_NOERROR # decode no error

        # rr :  │  NAME   │ TYPE │CLASS │  TTL   │RDLEN │    RDATA     │
        if qtype == cls.TYPE_A:   
            # A type :
            ip = cls._hostname_to_ip.get(qname)
            if ip:
                name_enc = b"\xc0\x0c"         # 答案的 NAME 用压缩指针，指向偏移 12
                rdata = socket.inet_aton(ip)   # IP 地址转为 4 字节
                rdlen = 4
                response_answers += struct.pack("!HHIH", cls.TYPE_A, cls.CLASS_IN, 300, rdlen)
                response_answers += rdata
                response_answers = name_enc + response_answers
            else:
                rcode = cls.RCODE_NXDOMAIN    # 域名不存在

        elif qtype == cls.TYPE_PTR:
            # NAME -> Ip

            ip = cls._reverse_ptr_to_ip(qname)  # 从 "x.x.x.x.in-addr.arpa" 中提取 IP 字符串
            if ip and ip in cls._ip_to_hostname:
                hostname = cls._ip_to_hostname[ip]
                name_enc = b"\xc0\x0c"
                host_labels = hostname.encode("ascii").split(b".")
                rdata = b"".join(bytes([len(l)]) + l for l in host_labels) + b"\x00"
                rdlen = len(rdata)
                response_answers += struct.pack("!HHIH", cls.TYPE_PTR, cls.CLASS_IN, 300, rdlen)
                response_answers += rdata
                response_answers = name_enc + response_answers
            else:
                rcode = cls.RCODE_NXDOMAIN  # 域名不存在
        else:
            rcode = cls.RCODE_SERVFAIL      # 服务器失败

        # According rcode to send rcode
        ans_count = 1 if rcode == cls.RCODE_NOERROR else 0 
        resp_flags = 0x8180
        #0x8180 = 1000 0001 1000 0000
        #         ↑          ↑
        #         QR=1 (响应) RA=0 (不支持递归)
        #                 ↑
        #                 RD=1 (递归期望，原样回传)

        if rcode == cls.RCODE_NXDOMAIN:
            resp_flags = 0x8183
        elif rcode == cls.RCODE_SERVFAIL:
            resp_flags = 0x8182

        dns_header = struct.pack("!HHHHHH", trans_id, resp_flags, qdcount, ans_count, 0, 0)
        dns_body = qname_raw + struct.pack("!HH", qtype, qclass) + response_answers
        dns_payload = dns_header + dns_body

        return cls._build_raw_packet(
            dst_mac, src_mac, dst_ip, src_ip,
            src_port, dst_port, dns_payload
        )

    @classmethod
    def _build_raw_packet(cls, dst_mac, src_mac, dst_ip, src_ip,
                          src_port, dst_port, dns_payload):
        """Build complete Ethernet/IP/UDP/DNS packet as raw bytes (like NAT does)."""
        # Ethernet header: dst(6) + src(6) + type(2)
        eth_dst = bytes(int(b, 16) for b in dst_mac.split(':'))
        eth_src = bytes(int(b, 16) for b in src_mac.split(':'))
        eth_type = struct.pack('!H', 0x0800)

        # IP header: 20 bytes (no options)
        ip_ver_ihl = 0x45
        ip_tos = 0
        ip_total_len = 20 + 8 + len(dns_payload)
        ip_id = 0
        ip_flags_offset = 0x4000  # Don't fragment
        ip_ttl = 64
        ip_proto = 17  # UDP
        ip_src = socket.inet_aton(src_ip)
        ip_dst = socket.inet_aton(dst_ip)

        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ver_ihl, ip_tos, ip_total_len,
            ip_id, ip_flags_offset,
            ip_ttl, ip_proto, 0,
            ip_src, ip_dst)

        # Compute IP checksum
        ip_csum = cls._checksum(ip_header)
        ip_header = struct.pack('!BBHHHBBH4s4s',
            ip_ver_ihl, ip_tos, ip_total_len,
            ip_id, ip_flags_offset,
            ip_ttl, ip_proto, ip_csum,
            ip_src, ip_dst)

        # UDP header
        udp_len = 8 + len(dns_payload)
        udp_header = struct.pack('!HHHH',
            src_port, dst_port, udp_len, 0)

        return eth_dst + eth_src + eth_type + ip_header + udp_header + dns_payload

    @staticmethod
    def _checksum(data):
        """Compute 16-bit one's complement checksum."""
        if len(data) % 2:
            data += b'\x00'
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    @classmethod
    def _reverse_ptr_to_ip(cls, ptr_name):
        """Convert '4.3.2.1.in-addr.arpa' -> '1.2.3.4'."""
        if not ptr_name.endswith(".in-addr.arpa"):
            return None
        prefix = ptr_name[:-len(".in-addr.arpa")]
        parts = prefix.split(".")
        if len(parts) != 4:
            return None
        try:
            parts_rev = list(reversed(parts))
            ip = ".".join(parts_rev)
            socket.inet_aton(ip)
            return ip
        except Exception:
            return None
