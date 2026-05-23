from os_ken.lib.packet import arp, ethernet, packet


class ARPHandler:
    def __init__(self, logger, arp_table, hosts, datapaths, send_packet_out, flood_packet):
        self.logger = logger
        self.arp_table = arp_table
        self.hosts = hosts
        self.datapaths = datapaths
        self.send_packet_out = send_packet_out
        self.flood_packet = flood_packet

    def learn(self, ip, mac):
        if ip and mac:
            self.arp_table[ip] = mac

    def lookup(self, ip):
        return self.arp_table.get(ip)

    def handle_arp(self, datapath, in_port, pkt, pkt_arp):
        src_ip = pkt_arp.src_ip
        src_mac = pkt_arp.src_mac
        dst_ip = pkt_arp.dst_ip

        self.learn(src_ip, src_mac)

        if pkt_arp.opcode == arp.ARP_REQUEST:
            self._handle_request(datapath, in_port, pkt, src_ip, src_mac, dst_ip)
        elif pkt_arp.opcode == arp.ARP_REPLY:
            self._handle_reply(datapath, in_port, pkt, pkt_arp)
        else:
            self.flood_packet(datapath, in_port, pkt.data)

    def _handle_request(self, datapath, in_port, pkt, src_ip, src_mac, dst_ip):
        dst_mac = self.lookup(dst_ip)
        if dst_mac:
            self.logger.info(f"ARP proxy reply: {dst_ip} is at {dst_mac}")
            reply_pkt = self._build_arp_reply(src_ip, src_mac, dst_ip, dst_mac)
            self.send_packet_out(datapath, in_port, reply_pkt.data)
        else:
            self.logger.info(f"ARP request for {dst_ip} flooded (unknown target)")
            self.flood_packet(datapath, in_port, pkt.data)

    def _handle_reply(self, datapath, in_port, pkt, pkt_arp):
        self.learn(pkt_arp.src_ip, pkt_arp.src_mac)

        dst_mac = pkt_arp.dst_mac
        if dst_mac in self.hosts:
            dst_dpid, dst_port, _ = self.hosts[dst_mac]
            if dst_dpid in self.datapaths:
                dp = self.datapaths[dst_dpid]
                self.send_packet_out(dp, dst_port, pkt.data)
                return
        self.flood_packet(datapath, in_port, pkt.data)

    def _build_arp_reply(self, target_ip, target_mac, sender_ip, sender_mac):
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=0x0806,
            dst=target_mac,
            src=sender_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=sender_mac,
            src_ip=sender_ip,
            dst_mac=target_mac,
            dst_ip=target_ip
        ))
        pkt.serialize()
        return pkt
