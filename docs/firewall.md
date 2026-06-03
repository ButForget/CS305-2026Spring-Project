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

# 防火墙模块接口文档

## 1. FirewallRule 数据类

规则数据结构。不可变 (`frozen=True`)。

| 字段 | 类型 | 默认值 | 描述 |
|-------|------|---------|-------------|
| `src_ip` | `str` | `None` | 匹配的源 IP 地址（`None` = 通配） |
| `dst_ip` | `str` | `None` | 匹配的目的 IP 地址（`None` = 通配） |
| `proto` | `str` | `None` | 协议名称（`"icmp"`、`"tcp"`、`"udp"`、`"*"` = 任意） |
| `src_port` | `object` | `None` | 源端口（`None`/`"*"` = 任意） |
| `dst_port` | `object` | `None` | 目的端口（`None`/`"*"` = 任意） |
| `action` | `str` | `"deny"` | 动作：`"deny"`（拒绝）或 `"allow"`（允许，仅 `deny` 已实现） |

---

## 2. Firewall 类

### 2.1 常量

| 常量 | 值 | 描述 |
|----------|-------|-------------|
| `COOKIE` | `0x305F` | 所有已安装流表的唯一 Cookie 标识 |
| `PRIORITY` | `60000` | 高优先级（覆盖默认转发规则） |

### 2.2 PROTO_MAP

协议名称字符串到 IP 协议号的映射：

| 键 | 值 |
|-----|-------|
| `None`、`""`、`"*"`、`"any"` | `0`（任意协议） |
| `"icmp"` | `inet.IPPROTO_ICMP` (1) |
| `"tcp"` | `inet.IPPROTO_TCP` (6) |
| `"udp"` | `inet.IPPROTO_UDP` (17) |

---

## 3. 公开方法

### 3.1 `__init__(self, rule_file="firewall_rules.json")`

实例化时从 JSON 文件加载规则。

- 同时支持 `{"rules": [...]}` 字典格式和 `[...]` 列表格式
- 若文件未找到或 JSON 格式错误，静默返回空规则列表

### 3.2 `install_rules(self, ofctls: dict) -> None`

通过 `ofctl.set_flow()` 在所有交换机上安装拒绝流表。

**输入：** `ofctls` — `{dpid: OfCtl}` 映射，将交换机 DPID 映射到其 OfCtl 实例。

**每条规则的处理逻辑：**
1. 跳过非 deny 规则
2. 规范化：协议 → IP 协议号，端口 → int，IP → string/None
3. 跳过无效规则（有端口但无协议，或端口对应非 TCP/UDP 协议）
4. 通过 `(dpid, src_ip, dst_ip, proto, src_port, dst_port)` 键去重
5. 安装高优先级丢包流表（actions 为空列表）

---

## 4. 私有辅助方法

| 方法 | 输入 | 返回 | 描述 |
|--------|-------|---------|-------------|
| `_normalize_any(value)` | `str` / `None` | `str` / `None` | 将 `"*"`、`"any"`、`""` 映射为 `None` |
| `_normalize_proto(proto)` | `str` / `None` | `str` / `None` | 将协议名转为小写；通配符 → `None` |
| `_proto_to_number(proto)` | `str` / `None` | `int` | 通过 `PROTO_MAP` 将协议名转为 IP 协议号 |
| `_normalize_port(value)` | `str` / `int` / `None` | `int` | 将端口转为 `int`；通配符 → `0` |
| `_load_rules(rule_file)` | `str` | `list[FirewallRule]` | 从 JSON 文件加载并解析防火墙规则 |

---

## 5. 规则文件格式 (`firewall_rules.json`)

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

- `src_ip` / `dst_ip`：设为 `null` 或省略表示匹配任意 IP
- `proto`：`"icmp"`、`"tcp"`、`"udp"`、`"*"` 或省略表示任意协议
- `src_port` / `dst_port`：设为 `"*"` 或省略表示任意端口（仅对 TCP/UDP 有意义）
- `action`：目前仅 `"deny"` 生效；`"allow"` 规则被忽略

---

## 6. 流表安装详情

每条匹配规则安装一条 OpenFlow 1.0 流表，具体参数如下：

| 匹配字段 | 值 |
|-------------|-------|
| `dl_type` | `0x0800` (IPv4) |
| `nw_src` | 源 IP 或 `0.0.0.0`（通配） |
| `nw_dst` | 目的 IP 或 `0.0.0.0`（通配） |
| `nw_proto` | IP 协议号或 `0`（任意） |
| `tp_src` | TCP/UDP 源端口或 `0`（任意） |
| `tp_dst` | TCP/UDP 目的端口或 `0`（任意） |
| **动作** | 空（丢包） |

所有流表通过 Cookie `0x305F` 标识，可通过删除匹配该 Cookie 的所有流表来清理规则。
