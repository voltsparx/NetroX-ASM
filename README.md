# NetroX-ASC

Phase 1 foundation: Sequential SYN probe in pure x86_64 assembly (Linux + Windows).

## Build (Linux)

```sh
make linux
```

## Build (Windows)

```sh
make windows
```

## Run

```sh
sudo ./NetroX-ASC <target_ip> [-p port|start-end|-] [--rate N] [--iface IFACE] [--scan MODE] [--stabilize]
```

```sh
NetroX-ASC.exe <target_ip> [-p port|start-end|-] [--rate N] [--scan MODE] [--stabilize]
```

```sh
sudo ./NetroX-ASC --prompt-mode
```

```sh
NetroX-ASC.exe --prompt-mode
```

```sh
./NetroX-ASC --about
```

```sh
NetroX-ASC.exe --about
```

## Notes

- Raw sockets require root or the `cap_net_raw` capability.
- Windows requires Administrator privileges for raw sockets.
- The current implementation scans sequentially and prints `PORT OPEN TTL=<n> WIN=<n>` or `PORT CLOSED/FILTERED`.
- Default range is ports 1-1000; use `-p -` for 1-65535.
- Source IP is detected by a temporary UDP `connect` to the target.
- Linux uses `epoll` for non-blocking receive checks between sends.
- Output is buffered (128KB) and flushed at ~75% to reduce syscall overhead.
- End-of-scan summary prints open count and a list built from a bitfield map.
- `--rate <N>` throttles packets/sec using an RDTSC-calibrated cycle budget.
- `--stabilize` enables adaptive rate control (auto-baseline is 200k pps if `--rate` is not set).
- `--scan MODE` supports: `syn`, `ack`, `fin`, `null`, `xmas`, `window`, `maimon` (TCP flag scans).
- `--prompt-mode` launches an interactive configuration wizard.
- `--about` prints banner + metadata.
- ASCII banner prints at startup.
- Linux `--iface <name>` enables an `AF_PACKET` send engine (NIC verified, link-layer send). Windows stays on WinSock raw sockets for now.
- The send loop routes through an `intelligence` gate (currently rate control) for future adaptive logic.

