# Controller（Switching）模块接口文档

## 1. 概述

`controller.py` 是整个 SDN 应用的核心。它继承自 `app_manager.OSKenApp`，基于 OpenFlow 1.0 协议运行。控制器承担三项主要职责：

1. **拓扑发现** — 跟踪交换机、链路和主机的上线/下线。
2. **ARP 代理** — 代表已知主机应答 ARP 请求，消除广播泛洪。
3. **最短路径转发** — 计算交换机间的最优路径，并沿路径在每台交换机上安装流表项。

支撑模块：
- `dhcp.py` — DHCP 服务器，在 PacketIn 管道中先于 ARP/交换逻辑被调用。
- `firewall.py` — 防火墙规则安装器，交换机加入时被调用。
- `ofctl_utilis.py` — OpenFlow 工具库（版本无关的流表/数据包辅助函数）。

---

## 2. 类定义：`ControllerApp`

```
os_ken.base.app_manager.OSKenApp
  └── ControllerApp
```

### 2.1 OpenFlow 版本

| 常量 | 值 |
|----------|-------|
| `OFP_VERSIONS` | `[ofproto_v1_0.OFP_VERSION]`（OpenFlow 1.0） |

---

## 3. 核心数据结构

以下均为 `__init__` 中初始化的实例属性。

| 属性 | 类型 | 描述 |
|-----------|------|-------------|
| `topology_graph` | `defaultdict(dict)` | 邻接映射：`{dpid: {相邻dpid: 端口号}}`。双向——每条链路在两个方向上都添加条目。 |
| `hosts` | `dict` | 主机位置表：`{mac: (dpid, 端口号, ip)}`。通过 `EventHostAdd` 和被动数据包学习来填充。 |
| `datapaths` | `dict` | 活跃交换机 datapath 对象：`{dpid: datapath}`。用于发送 OpenFlow 消息。 |
| `arp_table` | `dict` | IP 到 MAC 的映射：`{ip: mac}`。从 ARP 数据包和主机添加事件中构建。驱动 ARP 代理应答。 |
| `path_algo` | `str` | 选定的路由算法。可选值：`"dijkstra"`（默认）、`"bellman-ford"`、`"floyd-warshall"`。 |
| `ofctls` | `dict` | 每台交换机的 OfCtl 实例：`{dpid: OfCtl}`。交换机加入时创建；根据版本分发（v1.0 vs v1.2+）。 |
| `firewall` | `Firewall` | 防火墙模块实例。每台交换机加入时安装规则。 |

---

## 4. 事件处理器

### 4.1 `handle_switch_add(ev)` — `EventSwitchEnter`

交换机连接到控制器时触发。

**处理逻辑：**
1. 在 `self.datapaths` 中记录该交换机的 datapath。
2. 若为新交换机，初始化 `self.topology_graph[dpid]` 为空字典。
3. 创建对应版本的 `OfCtl` 实例：
   - OpenFlow 1.0 → `OfCtl_v1_0`
   - OpenFlow ≥1.2 → `OfCtl_after_v1_2`
4. 调用 `self.firewall.install_rules(self.ofctls)` — 在新交换机上安装拒绝规则。
5. 调用 `self.install_table_miss(dp)` — 安装优先级为 0 的默认规则，将未匹配的数据包发送至控制器。
6. 日志：`Switch {dpid} has entered the network.`

---

### 4.2 `handle_switch_delete(ev)` — `EventSwitchLeave`

交换机断开连接时触发。

**处理逻辑：**
1. 从 `datapaths`、`ofctls` 和 `topology_graph` 中移除该交换机。
2. 从其他交换机的邻接列表中移除所有引用该交换机的边。
3. 移除连接到该交换机的所有主机（从 `hosts` 和 `arp_table` 中删除）。
4. 调用 `self.update_all_paths()` 重新计算转发规则。
5. 日志：`Switch {dpid} has left the network.`

---

### 4.3 `handle_host_add(ev)` — `EventHostAdd`

os-ken 拓扑模块检测到新主机时触发。

**处理逻辑：**
1. 提取 `mac`、`ip`（取 `host.ipv4` 列表的第一个）、`dpid`、`port_no`。
2. 若主机已在相同位置记录过则跳过（重复事件不处理）。
3. 存储到 `self.hosts[mac] = (dpid, port_no, ip)`。
4. 若 IP 已知，填充 `self.arp_table[ip] = mac`。
5. 调用 `self.update_all_paths()`。
6. 日志：`Host {mac} (IP={ip}) added at s{dpid}:{port_no}`。

---

### 4.4 `handle_link_add(ev)` — `EventLinkAdd`

发现新的交换机间链路时触发。

**处理逻辑：**
1. 添加双向条目：`topology_graph[src.dpid][dst.dpid] = src.port_no`，反之亦然。
2. 调用 `self.update_all_paths()`。
3. 日志：`Link added: s{src}:{port} <-> s{dst}:{port}`。

---

### 4.5 `handle_link_delete(ev)` — `EventLinkDelete`

交换机间链路断开时触发。

**处理逻辑：**
1. 从 `topology_graph` 中移除两个方向的条目。
2. 调用 `self.update_all_paths()`。
3. 日志：`Link deleted: s{src}:{port} <-> s{dst}:{port}`。

---

### 4.6 `handle_port_modify(ev)` — `EventPortModify`

任意交换机端口状态变化（up/down）时触发。

**处理逻辑：**
1. 记录端口状态变更。
2. 若端口为 **down**：
   - `_remove_links_for_port(dpid, port_no)` — 删除所有使用该端口的交换机间链路。
   - `_remove_hosts_for_port(dpid, port_no)` — 删除连接到该端口的主机（同时清理 `arp_table`）。
3. 调用 `self.update_all_paths()`。

---

### 4.7 `packet_in_handler(ev)` — `EventOFPPacketIn`（MAIN_DISPATCHER）

核心的数据包处理管道。交换机硬件无法匹配的每个数据包都会被转发到这里。

**处理流程：**

```
PacketIn
  ├── DHCP? ──────────> DHCPServer.handle_dhcp() ──> return
  ├── LLDP? ──────────> return（忽略）
  ├── ARP? ───────────> _learn_host_from_packet()
  │                     handle_arp()
  │                       ├── ARP_REQUEST + 已知目标 → send_arp_reply()（代理）
  │                       ├── ARP_REQUEST + 未知目标 → flood_packet()
  │                       └── ARP_REPLY → 转发给目标主机
  │                     return
  └── 其他（IP等）─────> _learn_host_from_packet()（从IP头部学习）
                           ├── 目标已知 + 同一交换机 → send_packet_out() 直接转发
                           ├── 目标已知 + 跨交换机 → get_path() + install_path() + send_packet_out()
                           └── 目标未知 → flood_packet()
```

**关键设计说明：** 通过 ARP 数据包进行主机学习（`_learn_host_from_packet`）使控制器在 `EventHostAdd` 延迟触发或未触发时仍能正常工作。两条路径均填充 `self.hosts` 和 `self.arp_table`，并通过重复检测避免不必要的 `update_all_paths()` 调用。

---

## 5. ARP 代理

控制器通过充当代理来消除广播 ARP 泛洪。当主机发送 ARP 请求查询另一台主机的 MAC 时，控制器若已知该映射则直接应答。

### 5.1 `handle_arp(datapath, in_port, pkt, pkt_arp)`

| ARP 操作码 | 条件 | 动作 |
|------------|-----------|--------|
| `ARP_REQUEST` (1) | 目标 IP 在 `arp_table` 中 | `send_arp_reply()` — 用已知 MAC 进行代理应答 |
| `ARP_REPLY` (2) | 目标 MAC 在 `hosts` 中 | 转发到目标主机所在的交换机和端口 |

发送方的 IP-MAC 映射总是会被学习：`self.arp_table[src_ip] = src_mac`。

### 5.2 `send_arp_reply(datapath, out_port, src_mac, src_ip, dst_mac, dst_ip)`

通过 `OFPPacketOut` 构造并发送 ARP 应答包：

| 层 | 字段 | 值 |
|-------|-------|-------|
| Ethernet | `src` | `src_mac`（目标主机的 MAC） |
| Ethernet | `dst` | `dst_mac`（请求方主机的 MAC） |
| Ethernet | `ethertype` | `ETH_TYPE_ARP`（0x0806） |
| ARP | `opcode` | `ARP_REPLY` (2) |
| ARP | `src_mac` | `src_mac` |
| ARP | `src_ip` | `src_ip` |
| ARP | `dst_mac` | `dst_mac` |
| ARP | `dst_ip` | `dst_ip` |

---

## 6. 被动主机学习

### 6.1 `_learn_host_from_packet(dpid, port, mac, ip)`

从任意数据包（ARP 或 IP）中学习主机位置。这是 `EventHostAdd` 未触发时的被动回退机制。

**处理逻辑：**
1. 若端口为交换机间链路端口（通过检查 `topology_graph` 中的值来判断），则跳过。
2. 若该主机在相同位置上已已知且 IP 相同，则返回（无操作）。
3. 否则，更新 `self.hosts[mac]` 和 `self.arp_table[ip]`。
4. 调用 `self.update_all_paths()`。

调用来源：
- ARP 数据包处理（`handle_arp`）
- IP 数据包处理（提取 `src_mac` 和 `pkt_ipv4.src`）

---

## 7. 数据包转发原语

### 7.1 `send_packet_out(datapath, out_port, pkt, buffer_id=None)`

通过 `OFPPacketOut` 将单个数据包从指定端口发出。若提供了 `buffer_id`（数据包已在交换机上缓存），则不包含 `data` 字段。

### 7.2 `install_table_miss(datapath)`

安装 table-miss 流表项（优先级 0，匹配所有数据包），将所有未匹配的数据包发送至控制器。这是被动转发的基础。

---

## 8. 最短路径路由

控制器支持三种路由算法，通过 `self.path_algo` 选择。所有算法假设链路权重统一为 1。

### 8.1 算法选择

| `self.path_algo` | 方法 | 复杂度 | 说明 |
|------------------|--------|------------|-------|
| `"dijkstra"` | `dijkstra(src)` | O((V+E) log V) | 默认。最适合稀疏拓扑。 |
| `"bellman-ford"` | `bellman_ford(src)` | O(VE) | 可处理负权边（此处不需要，均为1）。 |
| `"floyd-warshall"` | `floyd_warshall(src)` | O(V³) | 全源预计算。在 `update_all_paths()` 中触发特殊的清理逻辑。 |

### 8.2 `get_path(src_dpid, dst_dpid) -> list`

分发到选定的算法。返回 DPID 列表 `[src, ..., dst]`，若不可达则返回 `[]`。同一交换机的情况返回 `[src_dpid]`。

### 8.3 `dijkstra(src_dpid) -> dict`

使用 `heapq` 实现的标准 Dijkstra 算法。返回所有可达目标的 `{dst_dpid: [path]}` 字典。通过 `prev` 指针从每个目标回溯到源点来重建路径。

### 8.4 `bellman_ford(src_dpid) -> dict`

对所有边迭代 `|V|-1` 轮，当没有更新发生时提前终止。返回相同格式的路径字典。

### 8.5 `floyd_warshall(src_dpid) -> dict`

使用 Floyd-Warshall 动态规划算法的全源最短路径。构建所有节点对的 `dist` 和 `nxt` 矩阵，然后仅提取 `src_dpid` 的路径。

---

## 9. 路径安装

### 9.1 `update_all_paths()`

在任何拓扑变更后调用（交换机/链路/主机增删、端口 down、新主机学习到）。

**Floyd-Warshall 模式：** 首先删除所有交换机上 priority=1 的流表项（使用 `OFPFC_DELETE_STRICT`），因为所有路径都需要从头重算。

**Dijkstra / Bellman-Ford 模式：** 直接安装新流表，不进行显式清理。过期路径的 priority=1 流表可能残留，但会被新的流表取代。

**每对主机 `(src_mac, dst_mac)` 的处理逻辑：**
- 同一交换机 → `install_single_switch_path()`
- 不同交换机 → `get_path()` 后在找到路径的情况下调用 `install_path()`

调用 `_log_host_path()` 记录计算出的路由及跳数。

### 9.2 `install_single_switch_path(dpid, dst_mac, dst_port)`

在 `dpid` 上安装单条流表项：

| 字段 | 值 |
|-------|-------|
| 优先级 | 1 |
| 匹配 | `dl_dst = dst_mac` |
| 动作 | `OUTPUT:dst_port` |

### 9.3 `install_path(path, dst_mac, dst_port)`

沿 `path` 在每台交换机上安装流表项：

| 交换机位置 | 匹配 | 动作 |
|-----------------|-------|--------|
| 首台 / 中间 | `dl_dst = dst_mac` | `OUTPUT:<到达下一跳的端口>` |
| 最后一台 | `dl_dst = dst_mac` | `OUTPUT:dst_port`（主机端口） |

所有条目使用优先级 1，匹配目标 MAC 地址。这使后续数据包能够在硬件中转发。

### 9.4 `add_flow(datapath, priority, match, actions, idle_timeout=0, hard_timeout=0)`

通过 `OFPFlowMod` + `OFPFC_ADD` 进行底层流表安装。记录安装日志以便调试。

### 9.5 `delete_flows(datapath)`

删除交换机上所有流表项（优先级 ≥1），仅保留 table-miss 规则（优先级 0）。

---

## 10. 链路故障切换

当链路断开时（`EventLinkDelete` 或 `EventPortModify` 端口 down）：

1. 从 `topology_graph` 中移除拓扑边。
2. 清理受影响端口上的主机。
3. `update_all_paths()` 在新拓扑上重新计算最短路径。
4. 沿备用路径安装新的流表项。

当链路恢复时，控制器再次重新计算路径，可能会恢复更短的路由。

**收敛时间：** 事件送达后即刻进行路径计算。Dijkstra 算法通常为 O(V log V)。

---

## 11. 主机路径日志

### 11.1 `_format_host(mac) -> str`

格式化主机标识用于日志输出：若 IP 已知则为 `IP(MAC)`，否则输出原始 `MAC`。

### 11.2 `_log_host_path(src_mac, dst_mac, path)`

以如下格式记录每条计算出的路径：

```
Shortest path 10.0.0.1(00:00:00:00:00:01) -> 10.0.0.2(00:00:00:00:00:02): s1->s2->s4, length=2
```

---

## 12. 模块集成

### 12.1 DHCP 分发

```python
# 在 packet_in_handler 中：
pkt_dhcp = pkt.get_protocols(dhcp.dhcp)
if pkt_dhcp:
    DHCPServer.handle_dhcp(datapath, in_port, pkt)
    return
```

DHCP 数据包最先被拦截，在 ARP 或交换逻辑之前。DHCPServer 直接应答，然后管道返回。

### 12.2 防火墙安装

```python
# 在 handle_switch_add 中：
self.firewall.install_rules(self.ofctls)
```

防火墙规则以优先级 60000 安装（高于 priority=1 的转发规则），因此拒绝规则优先执行。新交换机加入时会重新安装规则。

### 12.3 OfCtl 工厂

```python
# 在 handle_switch_add 中：
version = dp.ofproto.OFP_VERSION
if version == ofproto_v1_0.OFP_VERSION:
    self.ofctls[dp.id] = OfCtl_v1_0(dp, self.logger)
else:
    self.ofctls[dp.id] = OfCtl_after_v1_2(dp, self.logger)
```

---

## 13. 流表布局

每台交换机上的 OpenFlow 管道结构如下：

| 优先级 | 匹配 | 动作 | 安装者 | 用途 |
|----------|-------|---------|-------------|---------|
| 60000 | `dl_type=0x0800, nw_src/dst/proto/ports` | `[]`（丢包） | `Firewall.install_rules()` | 阻断被禁止的流量 |
| 1 | `dl_dst=<host_mac>` | `OUTPUT:<port>` | `install_path()` / `install_single_switch_path()` | 转发到已知目标 |
| 0 | `*`（通配） | `OUTPUT:CONTROLLER` | `install_table_miss()` | 将未知数据包发送至控制器 |

---

## 14. 测试覆盖

### 14.1 CI 自动化测试

| 测试文件 | 拓扑 | 验证内容 |
|-----------|----------|-----------------|
| `tests/switching_test/ci/test_switching.py` | 2 台交换机，4 台主机 | 同交换机连通性、跨交换机连通性、全网状 ping、ARP 表填充 |
| `tests/switching_test/ci/test_shortest_path.py` | 线性 4 交换机 + 菱形 4 交换机 | 多跳最短路径路由、冗余路径选择、双向连通性 |
| `tests/switching_test/ci/test_arp_proxy.py` | 3 台交换机，3 台主机 | 控制器 ARP 代理应答、ARP 表填充、多跳 ARP、快速重复 ARP 查询、不存在主机的超时处理 |
| `tests/switching_test/ci/test_link_failover.py` | 4 台交换机（网格，含直连+备用路径） | 初始连通性、链路断开后故障切换、通过备用路径保持连通性、链路恢复、多条链路同时断开 |

### 14.2 交互式测试

| 测试文件 | 拓扑 | 用途 |
|-----------|-----------|---------|
| `tests/switching_test/test_network.py` | 网格、全网状、三角形、菱形、线性 | 通过 Mininet CLI 进行手动测试。运行自动化场景（链路 up/down）并进入 CLI 执行 `pingall` 和 `dpctl dump-flows`。 |

---

## 15. 常用调试命令

```
# Mininet CLI 中：
h1 ping h2                  # 测试主机间连通性
pingall                     # 对所有主机对执行 ping
dpctl dump-flows            # 查看每台交换机上已安装的流表项

# Linux 主机上：
sudo ovs-ofctl dump-flows s1 --no-stats   # 查看 s1 上的流表
sudo mn -c                  # 清理运行间的 Mininet 状态
```
