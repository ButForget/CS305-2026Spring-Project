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


class Firewall:
    COOKIE = 0x305F
    PRIORITY = 60000

    PROTO_MAP = {
        None: 0,
        "": 0,
        "*": 0,
        "any": 0,
        "icmp": inet.IPPROTO_ICMP,
        "tcp": inet.IPPROTO_TCP,
        "udp": inet.IPPROTO_UDP,
    }

    def __init__(self, rule_file="firewall_rules.json"):
        self.rule_file = rule_file
        self.rules = self._load_rules(rule_file)
        self.installed = set()

    # Some helper functions that may be useful
    def _normalize_any(self, value):
        if value is None:
            return None
        if isinstance(value, str) and value.strip().lower() in ["", "*", "any"]:
            return None
        return value

    def _normalize_proto(self, proto):
        proto = self._normalize_any(proto)
        if proto is None:
            return None
        return str(proto).lower()

    def _proto_to_number(self, proto):
        proto = self._normalize_proto(proto)
        return self.PROTO_MAP.get(proto, 0)

    def _normalize_port(self, value):
        value = self._normalize_any(value)
        if value is None:
            return 0
        return int(value)

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
                    rules.append(FirewallRule(
                        src_ip=item.get("src_ip"),
                        dst_ip=item.get("dst_ip"),
                        proto=item.get("proto"),
                        src_port=item.get("src_port"),
                        dst_port=item.get("dst_port"),
                        action=item.get("action", "deny")
                    ))
        except (FileNotFoundError, json.JSONDecodeError):
            print(Exception(f"Failed to load firewall rules from {rule_file}"))

        return rules

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

                # TODO: skip invalid port rules
                if (src_port or dst_port) and not proto_num:
                    continue
                if (src_port or dst_port) and proto_num not in (inet.IPPROTO_TCP, inet.IPPROTO_UDP):
                    continue

                # TODO: avoid duplicated flow installation
                rule_key = (dpid, src_ip, dst_ip, proto_num, src_port, dst_port)
                if rule_key in self.installed:
                    continue
                self.installed.add(rule_key)

                # TODO: use ofctl.set_flow() to install a high-priority drop flow
                ofctl.set_flow(
                    cookie=self.COOKIE,
                    priority=self.PRIORITY,
                    dl_type=ether.ETH_TYPE_IP,
                    nw_src=src_ip if src_ip else 0,
                    nw_dst=dst_ip if dst_ip else 0,
                    nw_proto=proto_num,
                    tp_src=src_port,
                    tp_dst=dst_port,
                    actions=[]
                )