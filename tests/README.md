# CI Tests

Each `tests/<feature>_test/ci/` directory must contain at least one `.py` file. The CI workflow runs **all** files matching `tests/*_test/ci/*.py`. These are the **only** tests that gate PRs and pushes.

## What your test must do

- **Exit code 0** if the feature works correctly.
- **Exit code non-zero** if anything fails.
- Print a clear `PASS:` or `FAIL:` message for each check.
- Create and tear down its own Mininet topology (see below).

## Starting template

```python
import sys

def run_test():
    print("PASS: my feature works")
    return True

if __name__ == "__main__":
    sys.exit(0 if run_test() else 1)
```

Replace `run_test()` with your actual test logic.

## Writing a real test

1. Copy the interactive `test_network.py` from your feature's directory as a starting reference for the topology setup.
2. Replace the interactive CLI with automated assertions (exit 0 on pass, exit 1 on fail).
3. Use `Mininet` with `controller=RemoteController` — the CI workflow starts the controller separately.
4. Always call `net.stop()` at the end, even on failure.

### Example skeleton (switching test)

```python
import sys, time, re
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topo import Topo

class MyTopo(Topo):
    def __init__(self, **opts):
        Topo.__init__(self, **opts)
        # add hosts, switches, links

def disable_ipv6(node):
    node.cmd("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.default.disable_ipv6=1")
    node.cmd("sysctl -w net.ipv6.conf.lo.disable_ipv6=1")

def run_test():
    net = Mininet(topo=MyTopo(), autoSetMacs=True, controller=RemoteController)
    for h in net.hosts:
        disable_ipv6(h)
    for s in net.switches:
        disable_ipv6(s)
    net.start()
    time.sleep(3)

    # --- your checks here ---

    net.stop()
    return True  # or False on failure

if __name__ == "__main__":
    setLogLevel("info")
    sys.exit(0 if run_test() else 1)
```

## Common pitfalls

- **`dhclient` hangs forever** if the DHCP server doesn't respond. Always wrap with `timeout`:
  ```python
  node.cmd("timeout 10 dhclient -v %s-eth0 2>/dev/null" % node.name)
  ```
- **Disable IPv6** on every host and switch before `net.start()`, or some tools behave unpredictably.
- **Wait 2-3 seconds** after `net.start()` and after sending ARP for the controller to process events.
- **Send gratuitous ARP** before connectivity checks (`arping -c 1 -A -I h1-eth0 h1_IP`).
- **Use `sudo mn -c`** to clean Mininet state between local test runs.
