# DNS Server Module Interface

## 1. Overview

The DNS module implements a lightweight DNS server inside the SDN controller.
It intercepts DNS queries (UDP port 53) addressed to `192.168.1.1`, maintains
a hostname↔IP mapping table (populated automatically when the controller learns
hosts via ARP and IP traffic), and returns DNS responses via PacketOut through
the OpenFlow switch.

**Supported query types:** A (hostname → IP), PTR (IP → hostname), NXDOMAIN.

---

## 2. Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `TYPE_A` | `1` | DNS A record (hostname → IPv4) |
| `TYPE_PTR` | `12` | DNS PTR record (IPv4 → hostname) |
| `CLASS_IN` | `1` | Internet class |
| `RCODE_NOERROR` | `0` | No error (success) |
| `RCODE_NXDOMAIN` | `3` | Name does not exist |
| `RCODE_SERVFAIL` | `2` | Server failure |
| `server_ip` | `"192.168.1.1"` | DNS server IP (must match `Config.server_ip` in dhcp.py) |
| `upstream_dns` | `"8.8.8.8"` | Upstream DNS for forwarded queries (reserved) |

### 2.1 Internal State

| Attribute | Type | Description |
|-----------|------|-------------|
| `_hostname_to_ip` | `dict` | `{hostname: ip}` forward mapping |
| `_ip_to_hostname` | `dict` | `{ip: hostname}` reverse mapping |

---

## 3. Public Methods

### 3.1 `register_host(hostname: str, ip: str) -> None`

Register a hostname-to-IP mapping. Called automatically when the controller
learns a host's IP via gratuitous ARP (`_learn_host_from_packet` in controller.py).

| Parameter | Type | Description |
|-----------|------|-------------|
| `hostname` | `str` | Hostname (e.g. `"h2.local"`) |
| `ip` | `str` | IPv4 address (e.g. `"192.168.1.4"`) |

Static entries are also registered on startup:
```python
DNSServer.register_host("dhcp.local", "192.168.1.1")
DNSServer.register_host("dns.local", "192.168.1.1")
```

### 3.2 `handle_dns(datapath, in_port, pkt, raw_data=None) -> bytes | None`

Process a DNS query packet. Called from `controller.py`'s `packet_in_handler`
when a UDP/53 packet destined to the DNS server IP is received.

| Parameter | Type | Description |
|-----------|------|-------------|
| `datapath` | `Datapath` | Switch datapath |
| `in_port` | `int` | Input port number |
| `pkt` | `Packet` | Parsed os-ken packet |
| `raw_data` | `bytes` | Original raw PacketIn data (`msg.data`) |

**Returns:** Raw Ethernet/IP/UDP/DNS response bytes, or `None`.

**Processing flow:**
1. Verify IP destination = `server_ip` and UDP destination port = 53
2. Extract DNS query payload from raw PacketIn data
3. Build DNS response via `_build_response()`
4. Return raw bytes for controller to send via `_send_raw_packet()`

---

## 4. Private Methods

### 4.1 `_get_raw_payload(raw_data: bytes) -> bytes | None`

Extract DNS payload bytes from raw PacketIn data by computing offsets:
Ethernet (14) + IP header (variable) + UDP header (8) → DNS payload.

| Parameter | Type | Description |
|-----------|------|-------------|
| `raw_data` | `bytes` | Original `msg.data` from PacketIn event |

### 4.2 `_build_response(dns_query, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port) -> bytes | None`

Parse DNS query, look up answer from mapping tables, build complete DNS response
including Ethernet/IP/UDP headers as raw bytes.

| Parameter | Type | Description |
|-----------|------|-------------|
| `dns_query` | `bytes` | Raw DNS query payload |
| `src_mac` / `dst_mac` | `str` | Ethernet MAC addresses (swapped for reply) |
| `src_ip` / `dst_ip` | `str` | IP addresses (swapped for reply) |
| `src_port` / `dst_port` | `int` | UDP ports (swapped for reply) |

**Logic:**
- Parse DNS header: transaction ID, flags, question count
- Parse QNAME (domain name in label format)
- For A queries: lookup `_hostname_to_ip`, return IP or set RCODE=NXDOMAIN
- For PTR queries: reverse IP → hostname via `_reverse_ptr_to_ip()`
- Build DNS response header + question echo + answer section
- Build raw Ethernet/IP/UDP/DNS packet via `_build_raw_packet()`

### 4.3 `_build_raw_packet(dst_mac, src_mac, dst_ip, src_ip, src_port, dst_port, dns_payload) -> bytes`

Construct complete Ethernet (14) + IP (20) + UDP (8) + DNS (variable) packet
as raw bytes with correct checksums.

### 4.4 `_reverse_ptr_to_ip(ptr_name: str) -> str | None`

Convert PTR query name to IP address.
`"4.3.2.1.in-addr.arpa"` → `"1.2.3.4"`.

### 4.5 `_checksum(data: bytes) -> int`

Compute 16-bit one's complement checksum (RFC 1071) for IP header.

---

## 5. Integration Points

| Caller | Method | When |
|--------|--------|------|
| `controller.py:_learn_host_from_packet` | `register_host()` | Host IP learned from ARP/IP packets |
| `controller.py:__init__` | `register_host()` | Static entries on startup |
| `controller.py:packet_in_handler` | `handle_dns()` | UDP/53 packet received |

### Controller-side DNS handler (controller.py):
```python
pkt_udp = pkt.get_protocol(udp.udp)
if pkt_udp and pkt_udp.dst_port == 53:
    dns_response = DNSServer.handle_dns(datapath, in_port, pkt, msg.data)
    if dns_response:
        self._send_raw_packet(datapath, in_port, dns_response)
    return
```

### ARP Proxy (controller.py):
DNS server IP `192.168.1.1` is proxied in `handle_arp()`:
```python
if dst_ip == self.dns_server_ip:
    self.send_arp_reply(datapath, in_port, self.controller_mac,
                        dst_ip, src_mac, src_ip)
```

---

## 6. Hostname Registration

Hostnames are derived from MAC addresses using `_mac_to_hostname()` in controller.py.
Mininet auto-assigns MACs like `00:00:00:00:00:01` for h1, `00:00:00:00:00:02` for h2.

| MAC | Hostname |
|-----|----------|
| `00:00:00:00:00:01` | `h1.local`, `h1` |
| `00:00:00:00:00:02` | `h2.local`, `h2` |

Registration happens automatically when a host's gratuitous ARP is received.

# DNS 服务器模块接口文档

## 1. 概述

DNS 模块在 SDN 控制器内部实现了一个轻量级 DNS 服务器。
它拦截发往 `192.168.1.1` 的 DNS 查询（UDP 端口 53），维护
hostname↔IP 映射表（通过 DHCP 和 gratuitous ARP 自动填充），
并通过 OpenFlow PacketOut 返回 DNS 响应。

**支持的查询类型：** A（主机名 → IP）、PTR（IP → 主机名）、NXDOMAIN。

---

## 2. 常量

| 常量 | 值 | 描述 |
|----------|-------|-------------|
| `TYPE_A` | `1` | DNS A 记录（主机名 → IPv4） |
| `TYPE_PTR` | `12` | DNS PTR 记录（IPv4 → 主机名） |
| `CLASS_IN` | `1` | Internet 类 |
| `RCODE_NOERROR` | `0` | 无错误（成功） |
| `RCODE_NXDOMAIN` | `3` | 域名不存在 |
| `RCODE_SERVFAIL` | `2` | 服务器故障 |
| `server_ip` | `"192.168.1.1"` | DNS 服务器 IP（须与 dhcp.py 中 `Config.server_ip` 一致） |
| `upstream_dns` | `"8.8.8.8"` | 上游 DNS（预留，用于转发查询） |

### 2.1 内部状态

| 属性 | 类型 | 描述 |
|-----------|------|-------------|
| `_hostname_to_ip` | `dict` | `{hostname: ip}` 正向映射 |
| `_ip_to_hostname` | `dict` | `{ip: hostname}` 反向映射 |

---

## 3. 公开方法

### 3.1 `register_host(hostname: str, ip: str) -> None`

注册主机名到 IP 的映射。当控制器通过 gratuitous ARP
（controller.py 中的 `_learn_host_from_packet`）学习到主机 IP 时自动调用。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `hostname` | `str` | 主机名（如 `"h2.local"`） |
| `ip` | `str` | IPv4 地址（如 `"192.168.1.4"`） |

启动时也会注册静态条目：
```python
DNSServer.register_host("dhcp.local", "192.168.1.1")
DNSServer.register_host("dns.local", "192.168.1.1")
```

### 3.2 `handle_dns(datapath, in_port, pkt, raw_data=None) -> bytes | None`

处理 DNS 查询数据包。由 controller.py 的 `packet_in_handler`
在收到发往 DNS 服务器 IP 的 UDP/53 数据包时调用。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `datapath` | `Datapath` | 交换机 datapath |
| `in_port` | `int` | 入端口号 |
| `pkt` | `Packet` | os-ken 解析后的数据包 |
| `raw_data` | `bytes` | 原始 PacketIn 数据（`msg.data`） |

**返回值：** 原始 Ethernet/IP/UDP/DNS 响应字节，或 `None`。

**处理流程：**
1. 验证 IP 目的地址 = `server_ip` 且 UDP 目的端口 = 53
2. 从原始 PacketIn 数据中提取 DNS 查询载荷
3. 通过 `_build_response()` 构建 DNS 响应
4. 返回原始字节，由控制器通过 `_send_raw_packet()` 发送

---

## 4. 私有方法

### 4.1 `_get_raw_payload(raw_data: bytes) -> bytes | None`

通过计算偏移量从原始 PacketIn 数据中提取 DNS 载荷字节：
Ethernet (14) + IP 头 (变长) + UDP 头 (8) → DNS 载荷。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `raw_data` | `bytes` | PacketIn 事件的原始 `msg.data` |

### 4.2 `_build_response(dns_query, src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port) -> bytes | None`

解析 DNS 查询，从映射表中查找答案，构建包含 Ethernet/IP/UDP
头的完整 DNS 响应原始字节。

| 参数 | 类型 | 描述 |
|-----------|------|-------------|
| `dns_query` | `bytes` | 原始 DNS 查询载荷 |
| `src_mac` / `dst_mac` | `str` | Ethernet MAC 地址（回复时交换） |
| `src_ip` / `dst_ip` | `str` | IP 地址（回复时交换） |
| `src_port` / `dst_port` | `int` | UDP 端口（回复时交换） |

**逻辑：**
- 解析 DNS 头：transaction ID、flags、问题计数
- 解析 QNAME（标签格式的域名）
- A 查询：查找 `_hostname_to_ip`，返回 IP 或设置 RCODE=NXDOMAIN
- PTR 查询：通过 `_reverse_ptr_to_ip()` 反向查询 IP → 主机名
- 构建 DNS 响应头 + 问题回显 + 应答部分
- 通过 `_build_raw_packet()` 构建原始 Ethernet/IP/UDP/DNS 包

### 4.3 `_build_raw_packet(dst_mac, src_mac, dst_ip, src_ip, src_port, dst_port, dns_payload) -> bytes`

构造包含正确校验和的完整 Ethernet (14) + IP (20) + UDP (8) + DNS (变长) 原始字节包。

### 4.4 `_reverse_ptr_to_ip(ptr_name: str) -> str | None`

将 PTR 查询名转换为 IP 地址。
`"4.3.2.1.in-addr.arpa"` → `"1.2.3.4"`。

### 4.5 `_checksum(data: bytes) -> int`

计算 16 位二进制反码校验和（RFC 1071），用于 IP 头。

---

## 5. 集成点

| 调用方 | 方法 | 时机 |
|--------|--------|------|
| `controller.py:_learn_host_from_packet` | `register_host()` | 从 ARP/IP 包学习到主机 IP 时 |
| `controller.py:__init__` | `register_host()` | 启动时注册静态条目 |
| `controller.py:packet_in_handler` | `handle_dns()` | 收到 UDP/53 包时 |

### 控制器侧 DNS 处理 (controller.py):
```python
pkt_udp = pkt.get_protocol(udp.udp)
if pkt_udp and pkt_udp.dst_port == 53:
    dns_response = DNSServer.handle_dns(datapath, in_port, pkt, msg.data)
    if dns_response:
        self._send_raw_packet(datapath, in_port, dns_response)
    return
```

### ARP 代理 (controller.py):
DNS 服务器 IP `192.168.1.1` 在 `handle_arp()` 中代理：
```python
if dst_ip == self.dns_server_ip:
    self.send_arp_reply(datapath, in_port, self.controller_mac,
                        dst_ip, src_mac, src_ip)
```

---

## 6. 主机名注册

主机名通过 controller.py 中的 `_mac_to_hostname()` 从 MAC 地址推导。
Mininet 自动为 h1 分配 MAC `00:00:00:00:00:01`，为 h2 分配 `00:00:00:00:00:02`。

| MAC | 主机名 |
|-----|----------|
| `00:00:00:00:00:01` | `h1.local`、`h1` |
| `00:00:00:00:00:02` | `h2.local`、`h2` |

收到主机的 gratuitous ARP 时自动注册。
