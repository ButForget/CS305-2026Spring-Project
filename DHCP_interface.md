# DHCP Module Interface

## 1. Config Class

Class-level configuration constants. Extend from the skeleton as needed.

| Attribute | Type | Default | Description |
|-----------|------|---------|-------------|
| `controller_macAddr` | `str` | `7e:49:b3:f0:f9:99` | Dummy MAC address for controller (do not modify) |
| `dns` | `str` | `8.8.8.8` | DNS server address offered to clients (do not modify) |
| `start_ip` | `str` | `192.168.1.2` | First IP in the allocation pool |
| `end_ip` | `str` | `192.168.1.100` | Last IP in the allocation pool |
| `netmask` | `str` | `255.255.255.0` | Subnet mask offered to clients |
| `lease_time` | `int` | `86400` | Lease duration in seconds (bonus: lease expiry) |
| `server_ip` | `str` | `192.168.1.1` | DHCP server's own IP (gateway/router address) |

---

## 2. DHCPServer — Internal State (class-level)

Initialized lazily on first `handle_dhcp()` call via `_init_pool()`.

| Attribute | Type | Description |
|-----------|------|-------------|
| `_ip_pool` | `collections.deque` | FIFO queue of available IP strings. Initialized from `start_ip` → `end_ip` inclusive. |
| `_leases` | `dict[str -> dict]` | Active leases: `{ip: {"mac": mac, "start_time": float, "lease_time": int}}` (bonus) |
| `_mac_bindings` | `dict[str -> str]` | Reverse mapping: `{mac: ip}` for fast duplicate detection (bonus) |

---

## 3. Public Methods

### 3.1 `handle_dhcp(cls, datapath, port, pkt) -> None`

Main entry point called from `controller.py:90`. Parse the DHCP message type and dispatch.

```
Input:
  datapath -- Switch datapath object (from PacketIn)
  port     -- Switch in_port (from PacketIn)
  pkt      -- Full packet.Packet (from PacketIn)
```

**Logic:**

1. Call `_expire_leases()` first (bonus: reclaim stale IPs before processing).
2. Extract `dhcp_obj` from `pkt.get_protocols(dhcp.dhcp)` (returns a list; take `[0]`).
3. Parse message type from `dhcp_obj.options.option_list` — look for option code `53` (DHCP message type).
4. Dispatch by message type:

| Type | Action |
|------|--------|
| `DISCOVER` (1) | `ip = _select_ip()` → `offer = assemble_offer(pkt, datapath, ip)` → `_send_packet(datapath, port, offer)` |
| `REQUEST` (3) | Extract requested IP from option `50`. Call `_is_ip_available(ip, mac)`. If available: `ack = assemble_ack(pkt, datapath, port)` → `_send_packet(...)` → record `_leases[ip]` and `_mac_bindings[mac]`. If unavailable (bonus): `nak = assemble_nak(pkt, datapath)` → `_send_packet(...)`. |
| `RELEASE` (7) | `_release_ip(ip)` (bonus). No response sent. |
| Other | Silently drop (no response). |

---

### 3.2 `assemble_offer(cls, pkt, datapath, offered_ip) -> packet.Packet`

Construct a DHCP OFFER packet in response to a DISCOVER.

```
Input:
  pkt          -- Received DISCOVER packet
  datapath     -- Switch datapath object
  offered_ip   -- IP string selected from the pool (passed from handle_dhcp)

Returns:
  packet.Packet ready to send via _send_packet
```

**Packet layers:**

| Layer | Field | Value |
|-------|-------|-------|
| `ethernet` | `dst` | `ff:ff:ff:ff:ff:ff` (broadcast) |
| | `src` | `Config.controller_macAddr` |
| | `ethertype` | `ETH_TYPE_IP` (0x0800) |
| `ipv4` | `dst` | `255.255.255.255` |
| | `src` | `Config.server_ip` |
| | `proto` | `IPPROTO_UDP` (17) |
| `udp` | `src_port` | 67 |
| | `dst_port` | 68 |
| `dhcp` | `op` | `BOOTREPLY` (2) |
| | `htype` | 1 (Ethernet) |
| | `hlen` | 6 |
| | `xid` | from received DISCOVER |
| | `yiaddr` | `offered_ip` |
| | `siaddr` | `Config.server_ip` |
| | `chaddr` | client MAC from received DISCOVER |
| | `options` | See DHCP Options table below |
| | `options/53` | `DHCP_OFFER` (2) |
| | `options/1` | `Config.netmask` |
| | `options/3` | `Config.server_ip` (router) |
| | `options/6` | `Config.dns` |
| | `options/51` | `Config.lease_time` |
| | `options/54` | `Config.server_ip` (server identifier) |

---

### 3.3 `assemble_ack(cls, pkt, datapath, port) -> packet.Packet`

Construct a DHCP ACK packet in response to a REQUEST. Structurally identical to OFFER except option `53` = `DHCP_ACK` (5).

```
Input:
  pkt      -- Received REQUEST packet
  datapath -- Switch datapath object
  port     -- Switch in_port

Returns:
  packet.Packet ready to send via _send_packet
```

Same layer structure and options as `assemble_offer`, with option `53` = `DHCP_ACK` (5).

---

### 3.4 `assemble_nak(cls, pkt, datapath) -> packet.Packet` *(bonus)*

Construct a DHCP NAK packet when a REQUEST is rejected (duplicate allocation).

Same Ethernet/IP/UDP wrapper as OFFER/ACK, but:

| Layer | Field | Value |
|-------|-------|-------|
| `dhcp` | `yiaddr` | `0.0.0.0` |
| `dhcp` | `options/53` | `DHCP_NAK` (6) |
| `dhcp` | `options/56` | Error message string ("Requested address not available") |

---

### 3.5 `_send_packet(cls, datapath, port, pkt) -> None` *(already implemented)*

Serializes `pkt` and sends `PacketOut` to the given `port`. Do not modify.

---

## 4. Private Helper Methods

### 4.1 `_init_pool(cls) -> None`

Generate all IPs from `Config.start_ip` to `Config.end_ip` (inclusive) and push to `_ip_pool` deque. Called once on the first `handle_dhcp()` call (guarded by a flag).

IP generation: convert start/end to integers via `struct.unpack('!I', socket.inet_aton(ip))`, iterate, convert back via `socket.inet_ntoa(struct.pack('!I', val))`.

---

### 4.2 `_select_ip(cls) -> str`

`popleft()` from `_ip_pool`. Returns `None` if pool is empty.

---

### 4.3 `_release_ip(cls, ip: str) -> None` *(bonus)*

Return `ip` to the pool (`_ip_pool.append(ip)`). Remove entry from `_leases` and `_mac_bindings`.

Called when:
- A DHCP RELEASE (type 7) is received.
- `_expire_leases()` finds a stale lease.

---

### 4.4 `_is_ip_available(cls, ip: str, mac: str) -> bool` *(bonus)*

Duplicate allocation check per RFC 2131:

- If `ip` is not in `_leases` → return `True` (free).
- If `ip` is in `_leases` and `_leases[ip]["mac"] == mac` → return `True` (renewal).
- If `ip` is in `_leases` and `_leases[ip]["mac"] != mac` → return `False` (conflict → send NAK).

---

### 4.5 `_expire_leases(cls) -> None` *(bonus)*

Called at the top of every `handle_dhcp()` invocation.

Iterate `_leases`, check `start_time + lease_time < time.time()`. For each expired lease, call `_release_ip(ip)`.

---

### 4.6 `_ip_to_int(ip: str) -> int` / `_int_to_ip(val: int) -> str`

Conversion helpers using `socket.inet_aton` / `socket.inet_ntoa` and `struct.pack` / `struct.unpack`.

---

## 5. DHCP Options Reference

| Code | Name | Used In | Value |
|------|------|---------|-------|
| 1 | Subnet Mask | OFFER, ACK | `Config.netmask` |
| 3 | Router | OFFER, ACK | `Config.server_ip` |
| 6 | DNS Server | OFFER, ACK | `Config.dns` |
| 50 | Requested IP | REQUEST (read) | Client's requested IP |
| 51 | Lease Time | OFFER, ACK | `Config.lease_time` |
| 53 | Message Type | All | 1=DISCOVER, 2=OFFER, 3=REQUEST, 5=ACK, 6=NAK, 7=RELEASE |
| 54 | Server Identifier | OFFER, ACK | `Config.server_ip` |
| 56 | Message | NAK (bonus) | Human-readable error string |

---

## 6. Call Flow

```
Host (dhclient)                    Controller (DHCPServer)
    |                                    |
    |-- DHCP DISCOVER (broadcast) ------>|
    |                                    | handle_dhcp()
    |                                    |   _expire_leases()        [bonus]
    |                                    |   _select_ip()
    |                                    |   assemble_offer(pkt, dp, ip)
    |                                    |     -> builds OFFER packet
    |                                    |   _send_packet(dp, port, offer)
    |<- DHCP OFFER ----------------------|
    |                                    |
    |-- DHCP REQUEST (broadcast) ------->|
    |                                    | handle_dhcp()
    |                                    |   _expire_leases()        [bonus]
    |                                    |   _is_ip_available(ip, mac) [bonus]
    |                                    |   OK:  assemble_ack(pkt, dp, port)
    |                                    |        record lease/mac    [bonus]
    |                                    |   NOK: assemble_nak(pkt, dp) [bonus]
    |                                    |   _send_packet(dp, port, resp)
    |<- DHCP ACK (or NAK) ---------------|
    |                                    |
    |-- DHCP RELEASE (unicast) --------->|  [bonus]
    |                                    | handle_dhcp()
    |                                    |   _release_ip(ip)         [bonus]
```

## 7. os-ken DHCP Module Constants

Imported from `os_ken.lib.packet.dhcp`:

```
dhcp.DHCP_DISCOVER       = 1
dhcp.DHCP_OFFER          = 2
dhcp.DHCP_REQUEST        = 3
dhcp.DHCP_ACK            = 5
dhcp.DHCP_NAK            = 6    # may be DHCP_NAK or DHCP_NACK
dhcp.DHCP_RELEASE        = 7
dhcp.DHCP_BOOT_REQUEST   = 1    # op field
dhcp.DHCP_BOOT_REPLY     = 2    # op field
dhcp.DHCP_MESSAGE_TYPE_OPT = 53
dhcp.DHCP_SUBNET_MASK_OPT  = 1
dhcp.DHCP_GATEWAY_OPT      = 3
dhcp.DHCP_DNS_OPT          = 6
dhcp.DHCP_REQUESTED_IP_OPT = 50
dhcp.DHCP_LEASE_TIME_OPT   = 51
dhcp.DHCP_SERVER_ID_OPT    = 54
dhcp.DHCP_MESSAGE_OPT      = 56
```

## 8. Integration with `controller.py`

```python
# controller.py packet_in_handler
pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
if not pkt_dhcp:
    # handle ARP, etc.
    pass
else:
    DHCPServer.handle_dhcp(datapath, inPort, pkt)
```

No changes needed in `controller.py` — the existing dispatch is sufficient.
