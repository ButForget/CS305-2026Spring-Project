# NAT Module Interface

## 1. Overview

The NAT module implements SNAT (Source NAT) and DNAT (Destination NAT) between
an internal subnet (`10.0.1.0/24`) and an external subnet (`10.0.2.0/24`).
The controller intercepts IP packets crossing subnet boundaries, rewrites
source/destination IP addresses and TCP/UDP ports, and maintains a
connection-tracking table for reverse translation.

**Supported protocols:** ICMP, TCP, UDP.

---

## 2. Configuration

| Constant | Value | Description |
|----------|-------|-------------|
| `INTERNAL_SUBNET` | `"10.0.1.0"` | Internal network address |
| `INTERNAL_NETMASK` | `"255.255.255.0"` | Internal subnet mask |
| `EXTERNAL_SUBNET` | `"10.0.2.0"` | External network address |
| `EXTERNAL_NETMASK` | `"255.255.255.0"` | External subnet mask |
| `NAT_EXTERNAL_IP` | `"10.0.2.100"` | Source IP after SNAT |
| `CONNECTION_TIMEOUT` | `300` | Idle connection timeout (seconds) |

### 2.1 Ephemeral Port Range

| Constant | Value | Description |
|----------|-------|-------------|
| `_next_nat_port` | `50000` | Start of ephemeral port range |
| `_nat_port_max` | `60000` | End of ephemeral port range |

### 2.2 Internal State

| Attribute | Type | Description |
|-----------|------|-------------|
| `_connections` | `dict` | TCP/UDP connection tracking: `{(proto, int_ip, int_port, ext_ip, ext_port): {"nat_port": N, "timestamp": T}}` |
| `_icmp_connections` | `dict` | ICMP connection tracking: `{(proto, int_ip, icmp_id, ext_ip): (nat_icmp_id, timestamp)}` |

---

## 3. Public Methods

### 3.1 `is_internal(ip: str) -> bool`

Check if an IP address is in the internal subnet (`10.0.1.0/24`).

### 3.2 `is_external(ip: str) -> bool`

Check if an IP address is in the external subnet (`10.0.2.0/24`).

### 3.3 `needs_nat(src_ip: str, dst_ip: str) -> bool`

Determine if a packet requires NAT translation. Returns `True` when:

| Direction | Condition |
|-----------|-----------|
| Internal → External (SNAT) | `is_internal(src_ip) and is_external(dst_ip)` |
| External → Internal (DNAT) | `is_external(src_ip) and is_internal(dst_ip)` |
| External → NAT IP (DNAT) | `is_external(src_ip) and dst_ip == NAT_EXTERNAL_IP` |

### 3.4 `handle_nat(datapath, in_port, pkt, hosts, arp_table, controller_mac) -> (int, bytes) | (None, None)`

Process a packet that needs NAT translation.

| Parameter | Type | Description |
|-----------|------|-------------|
| `datapath` | `Datapath` | Switch datapath |
| `in_port` | `int` | Input port number |
| `pkt` | `Packet` | Parsed os-ken packet |
| `hosts` | `dict` | `{mac: (dpid, port, ip)}` host location dict |
| `arp_table` | `dict` | `{ip: mac}` ARP mapping |
| `controller_mac` | `str` | Controller's MAC address |

**Returns:** `(output_port, raw_bytes)` on success, `(None, None)` otherwise.

**Processing flow:**
1. Determine direction (SNAT or DNAT)
2. SNAT: rewrite source IP to `NAT_EXTERNAL_IP`, allocate NAT port for TCP/UDP
3. DNAT: lookup connection table, restore original destination IP and port
4. Rewrite Ethernet MACs (src → controller, dst → actual destination)
5. Return rewritten raw bytes for controller to send via `_send_raw_packet()`

---

## 4. Private Methods

### 4.1 Packet Rewriting Helpers

| Method | Description |
|--------|-------------|
| `_rewrite_ip_src(raw, old_ip, new_ip)` | Rewrite source IP at offset 26, update IP checksum |
| `_rewrite_ip_dst(raw, old_ip, new_ip)` | Rewrite destination IP at offset 30, update IP checksum |
| `_rewrite_eth_macs(raw, src_mac, dst_mac)` | Rewrite Ethernet source/destination MAC addresses |
| `_rewrite_tcp_ports(raw, old_src, new_src, old_dst, new_dst)` | Rewrite TCP ports and recompute TCP checksum |
| `_rewrite_udp_ports(raw, old_src, new_src, old_dst, new_dst)` | Rewrite UDP ports and recompute UDP checksum |
| `_update_ip_checksum(raw, ip_start)` | Recalculate IP header checksum |

### 4.2 Connection Tracking

| Method | Description |
|--------|-------------|
| `_get_nat_port()` | Allocate next available NAT port from ephemeral range |
| `_cleanup_expired()` | Remove idle connections older than `CONNECTION_TIMEOUT` |

### 4.3 Lookup Helpers

| Method | Description |
|--------|-------------|
| `_ip_in_subnet(ip, subnet, netmask)` | Check if IP is within a given subnet |
| `_find_host_port(ip, hosts, arp_table)` | Find output port for a destination IP |

### 4.4 Checksum

| Method | Description |
|--------|-------------|
| `_checksum(data)` | Compute 16-bit one's complement checksum (RFC 1071) |
| `_tcp_udp_pseudo_header(src_ip, dst_ip, protocol, length)` | Build 12-byte pseudo-header for TCP/UDP checksum |

---

## 5. SNAT Processing (`_handle_snat`)

### Transformation

| Header | Before | After |
|--------|--------|-------|
| Source IP | `10.0.1.x` | `10.0.2.100` |
| Source Port (TCP/UDP) | `ephemeral` | `NAT_PORT` (50000–60000) |
| Source MAC | `host_mac` | `controller_mac` |
| Destination MAC | `controller_mac` | `actual_dst_mac` |

### Order of Operations

1. Rewrite source IP (so TCP/UDP checksum uses new IP)
2. Rewrite TCP/UDP ports (recomputes checksum with new IP in pseudo-header)
3. Rewrite Ethernet MACs

---

## 6. DNAT Processing (`_handle_dnat`)

### Transformation

| Header | Before | After |
|--------|--------|-------|
| Destination IP | `10.0.2.100` (NAT IP) or `10.0.2.x` | `10.0.1.x` (original internal IP) |
| Destination Port (TCP/UDP) | `NAT_PORT` | `original_port` |
| Source MAC | `external_host_mac` | `controller_mac` |
| Destination MAC | `controller_mac` | `original_host_mac` |

### Connection Lookup

Connection key: `(proto, internal_ip, internal_port, external_ip, external_port)`.

DNAT searches `_connections` for an entry where:
- `info["nat_port"] == packet_dst_port`
- `external_ip == packet_src_ip`

---

## 7. Integration Points

| Caller | Method | When |
|--------|--------|------|
| `controller.py:packet_in_handler` | `needs_nat()`, `handle_nat()` | IP packet crossing subnet boundary |
| `controller.py:handle_arp` | `is_internal()`, `is_external()` | ARP proxy for cross-subnet traffic |

### Controller-side NAT handler (controller.py):
```python
if pkt_ipv4 and NAT.needs_nat(pkt_ipv4.src, pkt_ipv4.dst):
    nat_port, nat_data = NAT.handle_nat(
        datapath, in_port, pkt, self.hosts, self.arp_table,
        self.controller_mac
    )
    if nat_data:
        self._send_raw_packet(datapath, nat_port, nat_data)
        return
```

### ARP Proxy for Cross-Subnet (controller.py):
```python
if NAT.is_internal(src_ip) and NAT.is_external(dst_ip):
    self.send_arp_reply(..., self.controller_mac, ...)
```

---

## 8. Addressing Notes

Hosts must use `/16` netmask (e.g., `10.0.1.2/16`) so they consider
`10.0.2.2` as on the same L2 network and ARP directly. The controller
proxies ARP for cross-subnet destinations, returning `controller_mac`,
so all cross-subnet traffic flows through the controller for NAT processing.

# NAT 模块接口文档

## 1. 概述

NAT 模块实现内部子网（`10.0.1.0/24`）与外部子网（`10.0.2.0/24`）之间的
SNAT（源地址转换）和 DNAT（目的地址转换）。控制器拦截跨子网的 IP 数据包，
重写源/目的 IP 地址和 TCP/UDP 端口，并维护连接跟踪表用于反向转换。

**支持的协议：** ICMP、TCP、UDP。

---

## 2. 配置

| 常量 | 值 | 描述 |
|----------|-------|-------------|
| `INTERNAL_SUBNET` | `"10.0.1.0"` | 内部网络地址 |
| `INTERNAL_NETMASK` | `"255.255.255.0"` | 内部子网掩码 |
| `EXTERNAL_SUBNET` | `"10.0.2.0"` | 外部网络地址 |
| `EXTERNAL_NETMASK` | `"255.255.255.0"` | 外部子网掩码 |
| `NAT_EXTERNAL_IP` | `"10.0.2.100"` | SNAT 后的源 IP |
| `CONNECTION_TIMEOUT` | `300` | 空闲连接超时（秒） |

### 2.1 临时端口范围

| 常量 | 值 | 描述 |
|----------|-------|-------------|
| `_next_nat_port` | `50000` | 临时端口起始值 |
| `_nat_port_max` | `60000` | 临时端口结束值 |

### 2.2 内部状态

| 属性 | 类型 | 描述 |
|-----------|------|-------------|
| `_connections` | `dict` | TCP/UDP 连接跟踪：`{(proto, int_ip, int_port, ext_ip, ext_port): {"nat_port": N, "timestamp": T}}` |
| `_icmp_connections` | `dict` | ICMP 连接跟踪：`{(proto, int_ip, icmp_id, ext_ip): (nat_icmp_id, timestamp)}` |

---

## 3. 公开方法

### 3.1 `is_internal(ip: str) -> bool`

检查 IP 地址是否在内部子网（`10.0.1.0/24`）中。

### 3.2 `is_external(ip: str) -> bool`

检查 IP 地址是否在外部子网（`10.0.2.0/24`）中。

### 3.3 `needs_nat(src_ip: str, dst_ip: str) -> bool`

判断数据包是否需要进行 NAT 转换。以下情况返回 `True`：

| 方向 | 条件 |
|-----------|-----------|
| 内部 → 外部（SNAT） | `is_internal(src_ip) and is_external(dst_ip)` |
| 外部 → 内部（DNAT） | `is_external(src_ip) and is_internal(dst_ip)` |
| 外部 → NAT IP（DNAT） | `is_external(src_ip) and dst_ip == NAT_EXTERNAL_IP` |

### 3.4 `handle_nat(datapath, in_port, pkt, hosts, arp_table, controller_mac) -> (int, bytes) | (None, None)`

处理需要 NAT 转换的数据包。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `datapath` | `Datapath` | 交换机 datapath |
| `in_port` | `int` | 入端口号 |
| `pkt` | `Packet` | os-ken 解析后的数据包 |
| `hosts` | `dict` | `{mac: (dpid, port, ip)}` 主机位置字典 |
| `arp_table` | `dict` | `{ip: mac}` ARP 映射 |
| `controller_mac` | `str` | 控制器 MAC 地址 |

**返回值：** 成功返回 `(output_port, raw_bytes)`，否则返回 `(None, None)`。

**处理流程：**
1. 判断方向（SNAT 或 DNAT）
2. SNAT：将源 IP 重写为 `NAT_EXTERNAL_IP`，为 TCP/UDP 分配 NAT 端口
3. DNAT：查找连接表，还原原始目的 IP 和端口
4. 重写 Ethernet MAC（src → controller，dst → 实际目的地）
5. 返回重写后的原始字节，由控制器通过 `_send_raw_packet()` 发送

---

## 4. 私有方法

### 4.1 数据包重写辅助方法

| 方法 | 描述 |
|--------|-------------|
| `_rewrite_ip_src(raw, old_ip, new_ip)` | 在偏移 26 处重写源 IP，更新 IP 校验和 |
| `_rewrite_ip_dst(raw, old_ip, new_ip)` | 在偏移 30 处重写目的 IP，更新 IP 校验和 |
| `_rewrite_eth_macs(raw, src_mac, dst_mac)` | 重写 Ethernet 源/目的 MAC 地址 |
| `_rewrite_tcp_ports(raw, old_src, new_src, old_dst, new_dst)` | 重写 TCP 端口并重新计算 TCP 校验和 |
| `_rewrite_udp_ports(raw, old_src, new_src, old_dst, new_dst)` | 重写 UDP 端口并重新计算 UDP 校验和 |
| `_update_ip_checksum(raw, ip_start)` | 重新计算 IP 头校验和 |

### 4.2 连接跟踪

| 方法 | 描述 |
|--------|-------------|
| `_get_nat_port()` | 从临时端口范围分配下一个可用 NAT 端口 |
| `_cleanup_expired()` | 移除超过 `CONNECTION_TIMEOUT` 的空闲连接 |

### 4.3 查找辅助方法

| 方法 | 描述 |
|--------|-------------|
| `_ip_in_subnet(ip, subnet, netmask)` | 检查 IP 是否在指定子网内 |
| `_find_host_port(ip, hosts, arp_table)` | 查找目的 IP 对应的输出端口 |

### 4.4 校验和

| 方法 | 描述 |
|--------|-------------|
| `_checksum(data)` | 计算 16 位二进制反码校验和（RFC 1071） |
| `_tcp_udp_pseudo_header(src_ip, dst_ip, protocol, length)` | 构建 TCP/UDP 校验和所需的 12 字节伪头部 |

---

## 5. SNAT 处理 (`_handle_snat`)

### 转换对照

| 头部 | 转换前 | 转换后 |
|--------|--------|-------|
| 源 IP | `10.0.1.x` | `10.0.2.100` |
| 源端口（TCP/UDP） | `临时端口` | `NAT_PORT`（50000–60000） |
| 源 MAC | `host_mac` | `controller_mac` |
| 目的 MAC | `controller_mac` | `actual_dst_mac` |

### 操作顺序

1. 重写源 IP（以便 TCP/UDP 校验和使用新 IP）
2. 重写 TCP/UDP 端口（用伪头部中的新 IP 重新计算校验和）
3. 重写 Ethernet MAC

---

## 6. DNAT 处理 (`_handle_dnat`)

### 转换对照

| 头部 | 转换前 | 转换后 |
|--------|--------|-------|
| 目的 IP | `10.0.2.100`（NAT IP）或 `10.0.2.x` | `10.0.1.x`（原始内部 IP） |
| 目的端口（TCP/UDP） | `NAT_PORT` | `original_port` |
| 源 MAC | `external_host_mac` | `controller_mac` |
| 目的 MAC | `controller_mac` | `original_host_mac` |

### 连接查找

连接键：`(proto, internal_ip, internal_port, external_ip, external_port)`。

DNAT 在 `_connections` 中搜索满足以下条件的条目：
- `info["nat_port"] == packet_dst_port`
- `external_ip == packet_src_ip`

---

## 7. 集成点

| 调用方 | 方法 | 时机 |
|--------|--------|------|
| `controller.py:packet_in_handler` | `needs_nat()`、`handle_nat()` | IP 包跨越子网边界时 |
| `controller.py:handle_arp` | `is_internal()`、`is_external()` | 跨子网流量的 ARP 代理 |

### 控制器侧 NAT 处理 (controller.py):
```python
if pkt_ipv4 and NAT.needs_nat(pkt_ipv4.src, pkt_ipv4.dst):
    nat_port, nat_data = NAT.handle_nat(
        datapath, in_port, pkt, self.hosts, self.arp_table,
        self.controller_mac
    )
    if nat_data:
        self._send_raw_packet(datapath, nat_port, nat_data)
        return
```

### 跨子网 ARP 代理 (controller.py):
```python
if NAT.is_internal(src_ip) and NAT.is_external(dst_ip):
    self.send_arp_reply(..., self.controller_mac, ...)
```

---

## 8. 寻址说明

主机须使用 `/16` 掩码（如 `10.0.1.2/16`），使其认为
`10.0.2.2` 在同一 L2 网络中，从而直接发送 ARP 请求。
控制器代理跨子网目的地址的 ARP，返回 `controller_mac`，
因此所有跨子网流量都通过控制器进行 NAT 处理。
