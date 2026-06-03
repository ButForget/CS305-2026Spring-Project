# Controller (Switching) Module Interface

## 1. Overview

`controller.py` is the core of the SDN application. It extends `app_manager.OSKenApp` and operates on OpenFlow 1.0. The controller performs three primary duties:

1. **Topology discovery** — tracks switches, links, and hosts as they appear/disappear.
2. **ARP proxy** — replies to ARP requests on behalf of known hosts, eliminating broadcast flooding.
3. **Shortest-path forwarding** — computes optimal inter-switch paths and installs flow entries on each switch along the path.

Supporting modules:
- `dhcp.py` — DHCP server, invoked from the PacketIn pipeline before ARP/switching logic.
- `firewall.py` — Firewall rule installer, invoked when a switch joins.
- `ofctl_utilis.py` — OpenFlow utility library (version-agnostic flow/packet helpers).

---

## 2. Class: `ControllerApp`

```
os_ken.base.app_manager.OSKenApp
  └── ControllerApp
```

### 2.1 OpenFlow Version

| Constant | Value |
|----------|-------|
| `OFP_VERSIONS` | `[ofproto_v1_0.OFP_VERSION]` (OpenFlow 1.0) |

---

## 3. Core Data Structures

All are instance attributes initialized in `__init__`.

| Attribute | Type | Description |
|-----------|------|-------------|
| `topology_graph` | `defaultdict(dict)` | Adjacency map: `{dpid: {neighbor_dpid: port_no}}`. Bidirectional — each link adds entries in both directions. |
| `hosts` | `dict` | Host location table: `{mac: (dpid, port_no, ip)}`. Populated via `EventHostAdd` and reactive packet learning. |
| `datapaths` | `dict` | Active switch datapath objects: `{dpid: datapath}`. Used for sending OpenFlow messages. |
| `arp_table` | `dict` | IP-to-MAC mapping: `{ip: mac}`. Built from ARP packets and host additions. Drives ARP proxy replies. |
| `path_algo` | `str` | Selected routing algorithm. One of: `"dijkstra"` (default), `"bellman-ford"`, `"floyd-warshall"`. |
| `ofctls` | `dict` | Per-switch OfCtl instances: `{dpid: OfCtl}`. Created on switch join; version dispatched (v1.0 vs v1.2+). |
| `firewall` | `Firewall` | Firewall module instance. Rules installed on each switch when it joins. |

---

## 4. Event Handlers

### 4.1 `handle_switch_add(ev)` — `EventSwitchEnter`

Triggered when a switch connects to the controller.

**Logic:**
1. Record the switch's datapath in `self.datapaths`.
2. Initialize `self.topology_graph[dpid]` as empty dict if new.
3. Create the version-appropriate `OfCtl` instance:
   - `OfCtl_v1_0` for OpenFlow 1.0
   - `OfCtl_after_v1_2` for OpenFlow ≥1.2
4. Call `self.firewall.install_rules(self.ofctls)` — installs deny rules on the new switch.
5. Call `self.install_table_miss(dp)` — installs priority-0 catch-all rule that sends unmatched packets to the controller.
6. Log: `Switch {dpid} has entered the network.`

---

### 4.2 `handle_switch_delete(ev)` — `EventSwitchLeave`

Triggered when a switch disconnects.

**Logic:**
1. Remove switch from `datapaths`, `ofctls`, and `topology_graph`.
2. Remove all edges referencing this switch from other switches' adjacency lists.
3. Remove all hosts attached to this switch (deleting from `hosts` and `arp_table`).
4. Call `self.update_all_paths()` to recompute forwarding rules.
5. Log: `Switch {dpid} has left the network.`

---

### 4.3 `handle_host_add(ev)` — `EventHostAdd`

Triggered when os-ken's topology module detects a new host.

**Logic:**
1. Extract `mac`, `ip` (first from `host.ipv4` list), `dpid`, `port_no`.
2. Skip if the host is already recorded at the same location (no-op on duplicate).
3. Store in `self.hosts[mac] = (dpid, port_no, ip)`.
4. Populate `self.arp_table[ip] = mac` if IP is known.
5. Call `self.update_all_paths()`.
6. Log: `Host {mac} (IP={ip}) added at s{dpid}:{port_no}`.

---

### 4.4 `handle_link_add(ev)` — `EventLinkAdd`

Triggered when a new inter-switch link is discovered.

**Logic:**
1. Add bidirectional entries: `topology_graph[src.dpid][dst.dpid] = src.port_no` and vice versa.
2. Call `self.update_all_paths()`.
3. Log: `Link added: s{src}:{port} <-> s{dst}:{port}`.

---

### 4.5 `handle_link_delete(ev)` — `EventLinkDelete`

Triggered when an inter-switch link goes down.

**Logic:**
1. Remove both directional entries from `topology_graph`.
2. Call `self.update_all_paths()`.
3. Log: `Link deleted: s{src}:{port} <-> s{dst}:{port}`.

---

### 4.6 `handle_port_modify(ev)` — `EventPortModify`

Triggered when any switch port changes state (up/down).

**Logic:**
1. Log the port status change.
2. If the port is **down**:
   - `_remove_links_for_port(dpid, port_no)` — delete all inter-switch links using this port.
   - `_remove_hosts_for_port(dpid, port_no)` — delete hosts attached to this port (also cleaning `arp_table`).
3. Call `self.update_all_paths()`.

---

### 4.7 `packet_in_handler(ev)` — `EventOFPPacketIn` (MAIN_DISPATCHER)

The central packet processing pipeline. Every packet the switch doesn't match in hardware is forwarded here.

**Processing order:**

```
PacketIn
  ├── DHCP? ──────────> DHCPServer.handle_dhcp() ──> return
  ├── LLDP? ──────────> return (ignore)
  ├── ARP? ───────────> _learn_host_from_packet()
  │                     handle_arp()
  │                       ├── ARP_REQUEST + known target → send_arp_reply() (proxy)
  │                       ├── ARP_REQUEST + unknown target → flood_packet()
  │                       └── ARP_REPLY → forward to target host
  │                     return
  └── Other (IP, etc.) ─> _learn_host_from_packet() (from IP header)
                           ├── dst known + same switch → send_packet_out() direct
                           ├── dst known + cross-switch → get_path() + install_path() + send_packet_out()
                           └── dst unknown → flood_packet()
```

**Key design note:** ARP learning (`_learn_host_from_packet` from ARP packets) makes the controller robust even when `EventHostAdd` fires late or doesn't fire. Both paths populate `self.hosts` and `self.arp_table`, with duplicate detection to avoid unnecessary `update_all_paths()` calls.

---

## 5. ARP Proxy

The controller eliminates broadcast ARP flooding by acting as a proxy. When a host sends an ARP request for another host's MAC, the controller replies directly if it knows the mapping.

### 5.1 `handle_arp(datapath, in_port, pkt, pkt_arp)`

| ARP Opcode | Condition | Action |
|------------|-----------|--------|
| `ARP_REQUEST` (1) | Target IP in `arp_table` | `send_arp_reply()` — proxy reply with known MAC |
| `ARP_REPLY` (2) | Target MAC in `hosts` | Forward to target's switch & port |

The sender's IP-MAC mapping is always learned: `self.arp_table[src_ip] = src_mac`.

### 5.2 `send_arp_reply(datapath, out_port, src_mac, src_ip, dst_mac, dst_ip)`

Constructs and sends an ARP Reply packet via `OFPPacketOut`:

| Layer | Field | Value |
|-------|-------|-------|
| Ethernet | `src` | `src_mac` (the target host's MAC) |
| Ethernet | `dst` | `dst_mac` (the requesting host's MAC) |
| Ethernet | `ethertype` | `ETH_TYPE_ARP` (0x0806) |
| ARP | `opcode` | `ARP_REPLY` (2) |
| ARP | `src_mac` | `src_mac` |
| ARP | `src_ip` | `src_ip` |
| ARP | `dst_mac` | `dst_mac` |
| ARP | `dst_ip` | `dst_ip` |

---

## 6. Reactive Host Learning

### 6.1 `_learn_host_from_packet(dpid, port, mac, ip)`

Learns host location from any packet (ARP or IP). This is the reactive fallback when `EventHostAdd` doesn't fire.

**Logic:**
1. Skip if the port is a switch-to-switch link (checked against `topology_graph` values).
2. If the host is already known at the same location with the same IP, return (no-op).
3. Otherwise, update `self.hosts[mac]` and `self.arp_table[ip]`.
4. Call `self.update_all_paths()`.

Called from:
- ARP packet processing (`handle_arp`)
- IP packet processing (extracts `src_mac` and `pkt_ipv4.src`)

---

## 7. Packet Forwarding Primitives

### 7.1 `send_packet_out(datapath, out_port, pkt, buffer_id=None)`

Sends a single packet out a specific port via `OFPPacketOut`. If `buffer_id` is provided (packet was buffered on the switch), no `data` field is included.

### 7.2 `install_table_miss(datapath)`

Installs the table-miss flow entry (priority 0, match all) that sends all unmatched packets to the controller. This is the foundation of reactive forwarding.

---

## 8. Shortest-Path Routing

The controller supports three routing algorithms, selectable via `self.path_algo`. All assume uniform link weight = 1.

### 8.1 Algorithm Selection

| `self.path_algo` | Method | Complexity | Notes |
|------------------|--------|------------|-------|
| `"dijkstra"` | `dijkstra(src)` | O((V+E) log V) | Default. Best for sparse topologies. |
| `"bellman-ford"` | `bellman_ford(src)` | O(VE) | Handles negative weights (not needed here, all =1). |
| `"floyd-warshall"` | `floyd_warshall(src)` | O(V³) | All-pairs precomputation. Triggers special cleanup logic in `update_all_paths()`. |

### 8.2 `get_path(src_dpid, dst_dpid) -> list`

Dispatches to the selected algorithm. Returns a list of DPIDs `[src, ..., dst]`, or `[]` if unreachable. For same-switch case, returns `[src_dpid]`.

### 8.3 `dijkstra(src_dpid) -> dict`

Standard Dijkstra using `heapq`. Returns `{dst_dpid: [path]}` for all reachable destinations. Path backtracking follows `prev` pointers from each destination to source.

### 8.4 `bellman_ford(src_dpid) -> dict`

Iterates `|V|-1` times over all edges with early termination when no updates occur. Returns the same path dictionary format.

### 8.5 `floyd_warshall(src_dpid) -> dict`

All-pairs shortest path using the Floyd-Warshall DP algorithm. Builds `dist` and `nxt` matrices for all node pairs, then extracts paths for `src_dpid` only.

---

## 9. Path Installation

### 9.1 `update_all_paths()`

Called after any topology change (switch/link/host add/remove, port down, new host learned).

**Floyd-Warshall mode:** First deletes all priority=1 flow entries on all switches (using `OFPFC_DELETE_STRICT`), since all paths are recomputed from scratch.

**Dijkstra / Bellman-Ford mode:** Installs new flows without explicit cleanup. Priority=1 flows for stale paths may persist but are superseded by newer flows.

**Logic for each host pair `(src_mac, dst_mac)`:**
- Same switch → `install_single_switch_path()`
- Different switches → `get_path()` then `install_path()` if path found

Calls `_log_host_path()` to log the computed route with hop count.

### 9.2 `install_single_switch_path(dpid, dst_mac, dst_port)`

Installs a single flow entry on `dpid`:

| Field | Value |
|-------|-------|
| Priority | 1 |
| Match | `dl_dst = dst_mac` |
| Action | `OUTPUT:dst_port` |

### 9.3 `install_path(path, dst_mac, dst_port)`

Installs flow entries on every switch along `path`:

| Switch Position | Match | Action |
|-----------------|-------|--------|
| First / Intermediate | `dl_dst = dst_mac` | `OUTPUT:<port to next switch>` |
| Last | `dl_dst = dst_mac` | `OUTPUT:dst_port` (host port) |

All entries use priority 1, matching on the destination MAC address. This enables hardware forwarding for subsequent packets.

### 9.4 `add_flow(datapath, priority, match, actions, idle_timeout=0, hard_timeout=0)`

Low-level flow installation via `OFPFlowMod` with `OFPFC_ADD`. Logs the installation for debugging.

### 9.5 `delete_flows(datapath)`

Deletes all flow entries from a switch (priority ≥1), preserving only the table-miss rule (priority 0).

---

## 10. Link Failover

When a link goes down (`EventLinkDelete` or `EventPortModify` with port down):

1. Topology edges are removed from `topology_graph`.
2. Hosts on affected ports are cleaned up.
3. `update_all_paths()` recalculates shortest paths on the new topology.
4. New flow entries are installed along alternate paths.

When a link comes back up, the controller recomputes paths again, potentially restoring shorter routes.

**Convergence time:** Immediate upon event delivery + path computation time. Typical O(V log V) for Dijkstra.

---

## 11. Host Path Logging

### 11.1 `_format_host(mac) -> str`

Formats a host identifier for logging: `IP(MAC)` if IP is known, otherwise raw `MAC`.

### 11.2 `_log_host_path(src_mac, dst_mac, path)`

Logs each computed path in the format:

```
Shortest path 10.0.0.1(00:00:00:00:00:01) -> 10.0.0.2(00:00:00:00:00:02): s1->s2->s4, length=2
```

---

## 12. Integration with `controller.py`

### 12.1 DHCP Dispatch

```python
# In packet_in_handler:
pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
if pkt_dhcp:
    DHCPServer.handle_dhcp(datapath, in_port, pkt)
    return
```

DHCP packets are intercepted first, before any ARP or switching logic. The DHCPServer responds directly and the pipeline returns.

### 12.2 Firewall Installation

```python
# In handle_switch_add:
self.firewall.install_rules(self.ofctls)
```

Firewall rules are installed at priority 60000 (above the priority-1 forwarding rules), so deny rules take precedence. Rules are reinstalled when a new switch joins.

### 12.3 OfCtl Factory

```python
# In handle_switch_add:
version = dp.ofproto.OFP_VERSION
if version == ofproto_v1_0.OFP_VERSION:
    self.ofctls[dp.id] = OfCtl_v1_0(dp, self.logger)
else:
    self.ofctls[dp.id] = OfCtl_after_v1_2(dp, self.logger)
```

---

## 13. Flow Table Layout

The OpenFlow pipeline on each switch has the following structure:

| Priority | Match | Actions | Installed By | Purpose |
|----------|-------|---------|-------------|---------|
| 60000 | `dl_type=0x0800, nw_src/dst/proto/ports` | `[]` (drop) | `Firewall.install_rules()` | Block denied traffic |
| 1 | `dl_dst=<host_mac>` | `OUTPUT:<port>` | `install_path()` / `install_single_switch_path()` | Forward to known destination |
| 0 | `*` (wildcard) | `OUTPUT:CONTROLLER` | `install_table_miss()` | Send unknown packets to controller |

---

## 14. Test Topologies

The interactive test script (`tests/switching_test/test_network.py`) defines five distinct topologies to validate shortest-path switching, link failover, and multi-path routing. Each topology targets different aspects of the controller.

---

### 14.1 Grid Topology (`GridTopo`)

A 2×3 switch mesh. Hosts attach at diagonal corners, creating paths with varying hop counts.

```
  h1               h2
  |                |
  s1 ---- s2 ---- s3
  |       |       |
  |       |       |
  s4 ---- s5 ---- s6
                  |
                  h3
```

**Link-down scenarios:**

| Scenario | Broken Links | Expect |
|----------|-------------|--------|
| Grid: break s2-s3 | (s2, s3) | CONNECTED — alternate path available |
| Grid: break s2-s5 | (s2, s5) | CONNECTED — alternate path available |
| Grid: partition core | (s2, s3), (s2, s5), (s3, s6) | DISCONNECTED — core partitioned |

---

### 14.2 Mesh Topology (`MeshTopo`)

Four switches in a ring with a diagonal link between s1 and s3, providing redundant paths.

```
  h1               h2
  |                |
  s1 ------------- s2
  |  \             |
  |    \           |
  |      \         |
  |        \       |
  s4 ------------- s3
  |                |
  h4               h3
```

**Link-down scenarios:**

| Scenario | Broken Links | Expect |
|----------|-------------|--------|
| Mesh: break s2-s3 | (s2, s3) | CONNECTED — path via s1 remains |
| Mesh: break diagonal s1-s3 | (s1, s3) | CONNECTED — ring path remains |
| Mesh: break s1-s2 and s3-s4 | (s1, s2), (s3, s4) | DISCONNECTED — graph split into two components |

---

### 14.3 Triangle Topology (`TriangleTopo`)

Three switches fully connected in a classic triangle/ring. Minimal redundant topology.

```
         h1
         |
         s1
        /  \
       /    \
      /      \
    s2 ------ s3
    |          |
    h2         h3
```

**Link-down scenarios:**

| Scenario | Broken Links | Expect |
|----------|-------------|--------|
| Triangle: break s1-s2 | (s1, s2) | CONNECTED — path via s3 remains |
| Triangle: break s2-s3 | (s2, s3) | CONNECTED — path via s1 remains |
| Triangle: break s1-s2 and s2-s3 | (s1, s2), (s2, s3) | DISCONNECTED — s2 isolated |

---

### 14.4 Diamond Topology (`DiamondTopo`)

Two parallel paths between s1 and s4 through s2 or s3. Classic topology for testing multi-path equal-cost routing.

```
            s2
          /    \
         /      \
  h1 -- s1      s4 -- h2
         \      /
          \    /
            s3
```

**Link-down scenarios:**

| Scenario | Broken Links | Expect |
|----------|-------------|--------|
| Diamond: break s1-s2 | (s1, s2) | CONNECTED — path via s3 remains |
| Diamond: break s1-s3 | (s1, s3) | CONNECTED — path via s2 remains |
| Diamond: break both branches | (s1, s2), (s1, s3) | DISCONNECTED — all paths severed |

---

### 14.5 Line Topology (`LineTopo`)

All four switches in series, hosts at each end. The simplest multi-hop topology — no redundancy.

```
  h1 --- s1 --- s2 --- s3 --- s4 --- h2
```

**Link-down scenarios:**

| Scenario | Broken Links | Expect |
|----------|-------------|--------|
| Line: break s2-s3 | (s2, s3) | DISCONNECTED — no alternate path |
| Line: break s1-s2 | (s1, s2) | DISCONNECTED — no alternate path |

---

## 15. Test Coverage

### 15.1 CI Automated Tests

| Test File | Topology | What It Verifies |
|-----------|----------|-----------------|
| `tests/switching_test/ci/test_switching.py` | 2 switches, 4 hosts | Same-switch connectivity, cross-switch connectivity, full mesh ping, ARP table population |
| `tests/switching_test/ci/test_shortest_path.py` | Linear 4-switch + Diamond 4-switch | Multi-hop shortest path routing, redundant path selection, bidirectional connectivity |
| `tests/switching_test/ci/test_arp_proxy.py` | 3 switches, 3 hosts | Controller ARP proxy replies, ARP table population, multi-hop ARP, rapid repeated ARP queries, timeout for non-existent hosts |
| `tests/switching_test/ci/test_link_failover.py` | 4 switches (mesh with direct+alternate paths) | Initial connectivity, failover after link down, connectivity maintained via alternate path, link restoration, multiple simultaneous link failures |

### 15.2 Interactive Test

| Test File | Topologies | Purpose |
|-----------|-----------|---------|
| `tests/switching_test/test_network.py` | Grid, Mesh, Triangle, Diamond, Line | Manual testing via Mininet CLI. Runs automated scenarios (link up/down) and drops into CLI for `pingall` and `dpctl dump-flows`. |

---

## 16. Useful Debugging Commands

```
# In Mininet CLI:
h1 ping h2                  # Test connectivity between hosts
pingall                     # Ping all host pairs
dpctl dump-flows            # View installed flow entries on each switch

# On Linux host:
sudo ovs-ofctl dump-flows s1 --no-stats   # View flows on s1
sudo mn -c                  # Clean up Mininet state between runs
```
