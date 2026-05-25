# Firewall Module Interface

## 1. FirewallRule Dataclass

Rule data structure. Immutable (`frozen=True`).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `src_ip` | `str` | `None` | Source IP to match (`None` = wildcard) |
| `dst_ip` | `str` | `None` | Destination IP to match (`None` = wildcard) |
| `proto` | `str` | `None` | Protocol name (`"icmp"`, `"tcp"`, `"udp"`, `"*"` = any) |
| `src_port` | `object` | `None` | Source port (`None`/`"*"` = any) |
| `dst_port` | `object` | `None` | Destination port (`None`/`"*"` = any) |
| `action` | `str` | `"deny"` | Action: `"deny"` or `"allow"` (only `deny` is implemented) |

---

## 2. Firewall Class

### 2.1 Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `COOKIE` | `0x305F` | Unique cookie ID for all installed flows |
| `PRIORITY` | `60000` | High priority (overrides default forwarding rules) |

### 2.2 PROTO_MAP

Maps protocol name strings to IP protocol numbers:

| Key | Value |
|-----|-------|
| `None`, `""`, `"*"`, `"any"` | `0` (any protocol) |
| `"icmp"` | `inet.IPPROTO_ICMP` (1) |
| `"tcp"` | `inet.IPPROTO_TCP` (6) |
| `"udp"` | `inet.IPPROTO_UDP` (17) |

---

## 3. Public Methods

### 3.1 `__init__(self, rule_file="firewall_rules.json")`

Loads rules from JSON file on instantiation.

- Parses both `{"rules": [...]}` dict format and `[...]` list format
- Silently returns empty rule list if file not found or JSON is malformed

### 3.2 `install_rules(self, ofctls: dict) -> None`

Installs deny flows on all switches via `ofctl.set_flow()`.

**Input:** `ofctls` — `{dpid: OfCtl}` mapping from switch DPID to its OfCtl instance.

**Logic per rule:**
1. Skip non-deny rules
2. Normalize protocol → IP proto number, ports → int, IPs → string/None
3. Skip invalid rules (port without protocol, or port with non-TCP/UDP proto)
4. Deduplicate by `(dpid, src_ip, dst_ip, proto, src_port, dst_port)` key
5. Install a high-priority drop flow with empty actions list

---

## 4. Private Helpers

| Method | Input | Returns | Description |
|--------|-------|---------|-------------|
| `_normalize_any(value)` | `str` / `None` | `str` / `None` | Maps `"*"`, `"any"`, `""` to `None` |
| `_normalize_proto(proto)` | `str` / `None` | `str` / `None` | Lowercases protocol name; wildcards → `None` |
| `_proto_to_number(proto)` | `str` / `None` | `int` | Converts protocol name to IP protocol number via `PROTO_MAP` |
| `_normalize_port(value)` | `str` / `int` / `None` | `int` | Converts port to `int`; wildcards → `0` |
| `_load_rules(rule_file)` | `str` | `list[FirewallRule]` | Loads and parses firewall rules from JSON file |

---

## 5. Rule File Format (`firewall_rules.json`)

```json
{
  "rules": [
    {
      "src_ip": "192.168.117.2",
      "dst_ip": "192.168.117.3",
      "proto": "icmp",
      "src_port": "*",
      "dst_port": "*",
      "action": "deny"
    },
    {
      "src_ip": "192.168.117.2",
      "dst_ip": "192.168.117.3",
      "proto": "tcp",
      "src_port": "*",
      "dst_port": 80,
      "action": "deny"
    }
  ]
}
```

- `src_ip` / `dst_ip`: Set to `null` or omit to match any IP
- `proto`: `"icmp"`, `"tcp"`, `"udp"`, `"*"`, or omit for any protocol
- `src_port` / `dst_port`: Set to `"*"` or omit for any port (only meaningful with TCP/UDP)
- `action`: Currently only `"deny"` is enforced; `"allow"` rules are ignored

---

## 6. Flow Installation Details

Each matching rule installs an OpenFlow 1.0 flow with:

| Match Field | Value |
|-------------|-------|
| `dl_type` | `0x0800` (IPv4) |
| `nw_src` | Source IP or `0.0.0.0` (wildcard) |
| `nw_dst` | Destination IP or `0.0.0.0` (wildcard) |
| `nw_proto` | IP protocol number or `0` (any) |
| `tp_src` | TCP/UDP source port or `0` (any) |
| `tp_dst` | TCP/UDP destination port or `0` (any) |
| **Actions** | Empty (drop) |

Flows are identified by cookie `0x305F` and can be cleaned up by deleting all flows matching this cookie.
