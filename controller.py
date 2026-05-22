from os_ken.base import app_manager
from os_ken.controller import ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from os_ken.controller.handler import set_ev_cls
from os_ken.topology import event
from os_ken.topology.switches import Switch, Host, HostState, Port, PortState, PortData, PortDataState, Link, LinkState
from os_ken.topology.switches import Switches
from os_ken.ofproto import ofproto_v1_0, ether, inet
from os_ken.lib.packet import packet, ethernet, ether_types, arp
from os_ken.lib.packet import dhcp
from os_ken.lib.packet import ethernet
from os_ken.lib.packet import ipv4
from os_ken.lib.packet import packet
from os_ken.lib.packet import udp
from dhcp import DHCPServer
from collections import defaultdict
import time
from ofctl_utilis import OfCtl, OfCtl_v1_0, OfCtl_after_v1_2, VLANID_NONE
import logging
import copy
import heapq
from firewall import Firewall


class ControllerApp(app_manager.OSKenApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ControllerApp, self).__init__(*args, **kwargs)
        self.topology_graph = defaultdict(dict)  # {dpid: {neighbor_dpid: port_no}}
        self.hosts = {}  # {mac: (dpid, port_no, ip)}
        self.datapaths = {}  # {dpid: datapath}
        self.arp_table = {}  # {ip: mac}

    @set_ev_cls(event.EventSwitchEnter)
    def handle_switch_add(self, ev):
        """
        Event handler indicating a switch has come online.
        """
        dp = ev.switch.dp
        self.datapaths[dp.id] = dp
        if dp.id not in self.topology_graph:
            self.topology_graph[dp.id] = {}
        # Install table-miss rule: unmatched packets are sent to the controller
        self.install_table_miss(dp)
        self.logger.info(f"Switch {dp.id} has entered the network.")

    @set_ev_cls(event.EventSwitchLeave)
    def handle_switch_delete(self, ev):
        """
        Event handler indicating a switch has been removed.
        """
        dp = ev.switch.dp
        if dp.id in self.datapaths:
            del self.datapaths[dp.id]
        if dp.id in self.topology_graph:
            del self.topology_graph[dp.id]
        for other_dpid in list(self.topology_graph.keys()):
            if dp.id in self.topology_graph[other_dpid]:
                del self.topology_graph[other_dpid][dp.id]
        # Remove hosts connected to this switch
        hosts_to_remove = [mac for mac, (dpid, _, _) in self.hosts.items() if dpid == dp.id]
        for mac in hosts_to_remove:
            del self.hosts[mac]
        self.update_all_paths()
        self.logger.info(f"Switch {dp.id} has left the network.")

    @set_ev_cls(event.EventHostAdd)
    def handle_host_add(self, ev):
        """
        Event handler indicating a host has joined the network.
        """
        host = ev.host
        # host.ipv4 is a list, take the first IP
        ip = host.ipv4[0] if host.ipv4 else None
        self.hosts[host.mac] = (host.port.dpid, host.port.port_no, ip)
        if ip:
            self.arp_table[ip] = host.mac
        self.logger.info(f"Host {host.mac} (IP={ip}) added at s{host.port.dpid}:{host.port.port_no}")
        self.update_all_paths()

    @set_ev_cls(event.EventLinkAdd)
    def handle_link_add(self, ev):
        """
        Event handler indicating a link between two switches has been added.
        """
        src = ev.link.src  # src.dpid, src.port_no
        dst = ev.link.dst  # dst.dpid, dst.port_no
        self.topology_graph[src.dpid][dst.dpid] = src.port_no
        self.topology_graph[dst.dpid][src.dpid] = dst.port_no
        self.logger.info(f"Link added: s{src.dpid}:{src.port_no} <-> s{dst.dpid}:{dst.port_no}")
        self.update_all_paths()

    @set_ev_cls(event.EventLinkDelete)
    def handle_link_delete(self, ev):
        """
        Event handler indicating a link between two switches has been deleted.
        """
        src = ev.link.src
        dst = ev.link.dst
        if dst.dpid in self.topology_graph.get(src.dpid, {}):
            del self.topology_graph[src.dpid][dst.dpid]
        if src.dpid in self.topology_graph.get(dst.dpid, {}):
            del self.topology_graph[dst.dpid][src.dpid]
        self.logger.info(f"Link deleted: s{src.dpid}:{src.port_no} <-> s{dst.dpid}:{dst.port_no}")
        self.update_all_paths()

    @set_ev_cls(event.EventPortModify)
    def handle_port_modify(self, ev):
        """
        Event handler for when any switch port changes state.
        """
        port = ev.port
        dpid = port.dpid
        self.logger.info(f"Port modified: s{dpid}:{port.port_no}")

        if port.is_down():
            self.logger.info(
                f"Port down detected: s{dpid}:{port.port_no}, cleaning up related links and hosts"
            )
            self._remove_links_for_port(dpid, port.port_no)
            self._remove_hosts_for_port(dpid, port.port_no)
        self.update_all_paths()

    def _remove_links_for_port(self, dpid, port_no):
        """
        Remove all switch-to-switch links that use the given port.
        """
        neighbors = [
            neighbor_dpid
            for neighbor_dpid, neighbor_port in self.topology_graph.get(dpid, {}).items()
            if neighbor_port == port_no
        ]
        for neighbor_dpid in neighbors:
            del self.topology_graph[dpid][neighbor_dpid]
            if dpid in self.topology_graph.get(neighbor_dpid, {}):
                del self.topology_graph[neighbor_dpid][dpid]

    def _remove_hosts_for_port(self, dpid, port_no):
        """
        Remove hosts attached to the given switch port.
        """
        hosts_to_remove = [
            mac
            for mac, (host_dpid, host_port, _) in self.hosts.items()
            if host_dpid == dpid and host_port == port_no
        ]
        for mac in hosts_to_remove:
            ip = self.hosts[mac][2]
            if ip in self.arp_table and self.arp_table[ip] == mac:
                del self.arp_table[ip]
            del self.hosts[mac]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle PacketIn message: ARP proxy reply + DHCP relay
        """
        try:
            msg = ev.msg
            datapath = msg.datapath
            pkt = packet.Packet(data=msg.data)
            in_port = msg.in_port

            pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
            if pkt_dhcp:
                DHCPServer.handle_dhcp(datapath, in_port, pkt)
                return

            # Handle ARP packet
            pkt_arp = pkt.get_protocol(arp.arp)
            if pkt_arp:
                self.handle_arp(datapath, in_port, pkt, pkt_arp)
                return

        except Exception as e:
            self.logger.error(f"PacketIn handler error: {e}")

    def handle_arp(self, datapath, in_port, pkt, pkt_arp):
        """
        Handle ARP request: If the target IP's MAC is known, reply on behalf; otherwise, flood.
        """
        # Learn sender's IP-MAC mapping
        src_ip = pkt_arp.src_ip
        src_mac = pkt_arp.src_mac
        self.arp_table[src_ip] = src_mac

        if pkt_arp.opcode == arp.ARP_REQUEST:
            dst_ip = pkt_arp.dst_ip
            if dst_ip in self.arp_table:
                # Proxy ARP Reply
                dst_mac = self.arp_table[dst_ip]
                self.send_arp_reply(datapath, in_port, dst_mac, dst_ip, src_mac, src_ip)
                self.logger.info(f"ARP proxy reply: {dst_ip} is at {dst_mac}")
            else:
                # Unknown target MAC, flood ARP request
                self.flood_packet(datapath, in_port, pkt)
                self.logger.info(f"ARP request for {dst_ip} flooded (unknown target)")
        elif pkt_arp.opcode == arp.ARP_REPLY:
            # ARP Reply is directly forwarded to the target host
            dst_mac = pkt_arp.dst_mac
            if dst_mac in self.hosts:
                dst_dpid, dst_port, _ = self.hosts[dst_mac]
                if dst_dpid in self.datapaths:
                    dp = self.datapaths[dst_dpid]
                    self.send_packet_out(dp, dst_port, pkt)

    def send_arp_reply(self, datapath, out_port, src_mac, src_ip, dst_mac, dst_ip):
        """
        Construct and send ARP Reply packet
        """
        ofproto = datapath.ofproto
        # ¹¹Ôì ARP Reply °ü
        pkt_reply = packet.Packet()
        pkt_reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac
        ))
        pkt_reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=dst_mac,
            dst_ip=dst_ip
        ))
        pkt_reply.serialize()

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_NONE,
            actions=actions,
            data=pkt_reply.data
        )
        datapath.send_msg(out)

    def flood_packet(self, datapath, in_port, pkt):
        """
        Flood the packet out of all ports (except the input port)
        """
        ofproto = datapath.ofproto
        pkt.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)

    def send_packet_out(self, datapath, out_port, pkt):
        """
        Send packet out from the specified port
        """
        ofproto = datapath.ofproto
        pkt.serialize()
        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_NONE,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)

    def install_table_miss(self, datapath):
        """
        Install table-miss flow entry: priority 0, send unmatched packets to controller
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()  # Match all packets
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        """
        Install a flow entry to the switch
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        try:
            dpid = datapath.id
        except Exception:
            dpid = getattr(datapath, 'id', 'unknown')
        # Log flow install attempt for debugging
        try:
            self.logger.info(f"Installing flow on s{dpid}: priority={priority} match={match} actions={actions} idle={idle_timeout} hard={hard_timeout}")
        except Exception:
            self.logger.info(f"Installing flow on s{dpid}: priority={priority} idle={idle_timeout} hard={hard_timeout}")
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=match,
            command=ofproto.OFPFC_ADD,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
            priority=priority,
            actions=actions
        )
        datapath.send_msg(mod)

    def delete_flows(self, datapath):
        """
        Delete all non-table-miss flow entries on the switch
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            match=parser.OFPMatch(),
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_NONE,
            priority=1
        )
        datapath.send_msg(mod)

    def update_all_paths(self):
        """
        Recalculate the shortest path between all host pairs and install flow entries.
        """
        # First clear old forwarding rules on all switches
        for dpid, dp in self.datapaths.items():
            self.delete_flows(dp)
            # Reinstall table-miss so PacketIn still reaches controller.
            self.install_table_miss(dp)
        self.logger.info(f"Recomputing paths for hosts: {list(self.hosts.keys())}")

        # For each host pair, calculate and install path
        for src_mac, (src_dpid, src_port, src_ip) in self.hosts.items():
            for dst_mac, (dst_dpid, dst_port, dst_ip) in self.hosts.items():
                if src_mac == dst_mac:
                    continue
                self.logger.info(f"Compute path: {src_mac} (s{src_dpid}) -> {dst_mac} (s{dst_dpid})")
                if src_dpid == dst_dpid:
                    # Source and destination are on the same switch, direct forwarding
                    self.install_single_switch_path(src_dpid, dst_mac, dst_port)
                else:
                    path = self.get_path(src_dpid, dst_dpid)
                    self.logger.info(f"Path found for s{src_dpid} -> s{dst_dpid}: {path}")
                    if path and len(path) >= 2:
                        self.install_path(path, dst_mac, dst_port)

    def install_single_switch_path(self, dpid, dst_mac, dst_port):
        """
        Install direct forwarding rule when source and destination are on the same switch
        """
        if dpid not in self.datapaths:
            return
        dp = self.datapaths[dpid]
        parser = dp.ofproto_parser
        match = parser.OFPMatch(dl_dst=dst_mac)
        actions = [parser.OFPActionOutput(dst_port)]
        self.logger.info(f"Install single-switch flow s{dpid} -> out:{dst_port} for dst_mac={dst_mac}")
        self.add_flow(dp, 1, match, actions)

    def install_path(self, path, dst_mac, dst_port):
        """
        Install flow entries along the path.
        path: [src_dpid, ..., dst_dpid] list of switch dpids
        dst_mac: destination host's MAC address
        dst_port: port number where the destination host connects on the last switch
        """
        for i in range(len(path)):
            dpid = path[i]
            if dpid not in self.datapaths:
                continue
            dp = self.datapaths[dpid]
            parser = dp.ofproto_parser

            if i < len(path) - 1:
                # Intermediate or first switch: forward out the port to the next hop
                next_dpid = path[i + 1]
                out_port = self.topology_graph[dpid][next_dpid]
            else:
                # Last switch: forward out the port to the destination host
                out_port = dst_port

            match = parser.OFPMatch(dl_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.logger.info(f"Install path flow on s{dpid}: out={out_port} dst_mac={dst_mac}")
            self.add_flow(dp, 1, match, actions)

    def dijkstra(self, src_dpid):
        """
        Calculate the shortest path from src_dpid to all other switches (all weights = 1)
        Return: {dst_dpid: [src_dpid, ..., dst_dpid]}
        """
        dist = {src_dpid: 0}
        prev = {src_dpid: None}
        visited = set()
        heap = [(0, src_dpid)]

        while heap:
            d, u = heapq.heappop(heap)
            if u in visited:
                continue
            visited.add(u)
            for v in self.topology_graph.get(u, {}):
                if v not in visited:
                    new_dist = d + 1
                    if v not in dist or new_dist < dist[v]:
                        dist[v] = new_dist
                        prev[v] = u
                        heapq.heappush(heap, (new_dist, v))

        # Backtrack path
        paths = {}
        for dst in dist:
            path = []
            node = dst
            while node is not None:
                path.append(node)
                node = prev[node]
            path.reverse()
            paths[dst] = path
        return paths

    def get_path(self, src_dpid, dst_dpid):
        """Get the shortest path between two switches"""
        if src_dpid == dst_dpid:
            return [src_dpid]
        paths = self.dijkstra(src_dpid)
        return paths.get(dst_dpid, [])