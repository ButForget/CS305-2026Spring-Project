# firewall.py

import json
import os
from dataclasses import dataclass

from os_ken.ofproto import ether, inet


@dataclass(frozen=True)
class FirewallRule:
    src_ip: str = None
    dst_ip: str = None
    proto: str = None
    src_port: object = None
    dst_port: object = None
    action: str = "deny"
    src_mask: int = 32
    dst_mask: int = 32


class Firewall:
    COOKIE = 0x305F
    PRIORITY = 60000

    PROTO_MAP = {
        None: 0,
        "": 0,
        "*": 0,
        "any": 0,
        "icmp": inet.IPPROTO_ICMP, # 1
        "tcp": inet.IPPROTO_TCP,   # 6
        "udp": inet.IPPROTO_UDP,   # 17
    }

    def __init__(self, rule_file="firewall_rules.json"):
        # Ensure we always find the rules file relative to this script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.rule_file = os.path.join(base_dir, rule_file)
        self.rules = self._load_rules(self.rule_file)
        self.installed = set()

    # Some helper functions that may be useful
    def _normalize_any(self, value):
        # ip 统配 none
        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() in ["", "*", "any"]:
            return None
        return value

    def _normalize_proto(self, proto):
        # TCP -> tcp
        proto = self._normalize_any(proto)
        if proto is None:
            return None
        return str(proto).lower()

    def _proto_to_number(self, proto):
        # tcp -> proto num
        proto = self._normalize_proto(proto)
        return self.PROTO_MAP.get(proto, 0)

    def _normalize_port(self, value):
        # prot 统配 0
        value = self._normalize_any(value)
        if value is None:
            return 0
        return int(value)

    @staticmethod
    def _parse_cidr(value):
        """Parse CIDR notation like '192.168.0.0/16' into (ip_str, mask_int).
        Returns (value, 32) if no mask is present."""

        # mask code using
        if not value or not isinstance(value, str):
            return value, 32
        if '/' in value:
            parts = value.split('/', 1)
            ip_part = parts[0].strip() or None
            try:
                mask = int(parts[1])
            except (ValueError, IndexError):
                mask = 32
            return ip_part, mask
        return value, 32

    def _load_rules(self, rule_file):
        """
        Load firewall rules from firewall_rules.json and return a list of FirewallRule.
        """
        rules = []

        try:
            with open(rule_file, 'r') as f:
                data = json.load(f)
                # handle both {"rules": [...]} dict format and [...] list format
                items = data.get("rules", []) if isinstance(data, dict) else data
                for item in items:
                    src_ip_raw = item.get("src_ip")
                    dst_ip_raw = item.get("dst_ip")
                    src_ip, src_mask = Firewall._parse_cidr(src_ip_raw)
                    dst_ip, dst_mask = Firewall._parse_cidr(dst_ip_raw)
                    rules.append(FirewallRule(
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        proto=item.get("proto"),
                        src_port=item.get("src_port"),
                        dst_port=item.get("dst_port"),
                        action=item.get("action", "deny"),
                        src_mask=src_mask,
                        dst_mask=dst_mask,
                    ))
        except (FileNotFoundError, json.JSONDecodeError):
            print(f"Error: Failed to load firewall rules from {rule_file}\n")     

        return rules

    def clear_installed_rules_for_switch(self, dpid):
        """
        Clear the installed rules cache for a specific switch.
        """
        to_remove = [key for key in self.installed if key[0] == dpid]
        for key in to_remove:
            self.installed.remove(key)

    def install_rules(self, ofctls):
        """
        Install firewall rules to all switches.
        """
        for dpid, ofctl in ofctls.items():
            for rule in self.rules:

                # TODO: only handle deny rules
                if rule.action != "deny":
                    continue

                # TODO: convert protocol name to protocol number
                proto_num = self._proto_to_number(rule.proto)

                # TODO: normalize source and destination ports
                src_port = self._normalize_port(rule.src_port)
                dst_port = self._normalize_port(rule.dst_port)

                # normalize IPs as well
                src_ip = self._normalize_any(rule.src_ip)
                dst_ip = self._normalize_any(rule.dst_ip)
                src_mask = rule.src_mask
                dst_mask = rule.dst_mask

                # TODO: skip invalid port rules
                if (src_port or dst_port) and not proto_num:
                    # have port but no proto
                    continue
                if (src_port or dst_port) and proto_num not in (inet.IPPROTO_TCP, inet.IPPROTO_UDP):
                    # have port but icmp need no port
                    continue

                # TODO: avoid duplicated flow installation
                rule_key = (dpid, src_ip, dst_ip, proto_num, src_port, dst_port, src_mask, dst_mask)
                if rule_key in self.installed:
                    continue
                self.installed.add(rule_key)

                # For ICMP: block only Echo Requests (type=8), not Echo Replies (type=0).
                # This allows bidirectional ping to work: h1->h2 ping is blocked,
                # but h2->h1 ping succeeds because the Echo Reply (src=h1) is allowed.
                if proto_num == inet.IPPROTO_ICMP and src_port == 0:
                    src_port = 8  # ICMP type 8 = Echo Request

                # TODO: use ofctl.set_flow() to install a high-priority drop flow
                ofctl.set_flow(
                    cookie=self.COOKIE,
                    priority=self.PRIORITY,
                    dl_type=ether.ETH_TYPE_IP,
                    nw_src=src_ip if src_ip else 0,
                    src_mask=src_mask,
                    nw_dst=dst_ip if dst_ip else 0,
                    dst_mask=dst_mask,
                    nw_proto=proto_num,
                    tp_src=src_port,
                    tp_dst=dst_port,
                    actions=[] # 空动作 = DROP
                )