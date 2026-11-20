# Divisor

Divisor is an optional component that provides IP rotation for Quotient runner containers. It creates a network interface with multiple rotating IP addresses and manages NAT rules to distribute outbound traffic across those addresses.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Environment Variables](#environment-variables)
- [Project layout](#project-layout)
- [How It Works](#how-it-works)
- [Deployment](#deployment)
- [Troubleshooting](#troubleshooting)

---

## Overview

Divisor solves a common problem in cybersecurity competitions: preventing blue teams from identifying and blocking the scoring engine based on its source IP address. By rotating the source IP addresses used by runner containers, Divisor makes it significantly harder to distinguish scoring traffic from other network activity.

**Key Features:**
- Creates a dedicated network interface with multiple IP addresses
- Automatically discovers Quotient runner containers
- Configures SNAT (Source NAT) rules to rotate outbound IPs
- Triggers reconfiguration at the end of each scoring round
- Randomizes source ports for additional obfuscation

---

## Prerequisites

Before configuring Divisor, ensure:

1. **Host Network Access**: Divisor requires `network_mode: host` in Docker
2. **Privileged Mode**: Container must run with `privileged: true` to manage iptables
3. **Docker Socket**: Access to `/var/run/docker.sock` to discover runner containers
4. **Available Subnet**: A subnet range that doesn't conflict with existing networks
5. **Git Submodule**: The divisor submodule must be initialized:

```bash
git submodule update --init --recursive
```

---

## Configuration

Divisor is configured entirely through environment variables. These can be set in the `.env` file in your Quotient root directory.

### Minimal Configuration

Add these variables to your `.env` file:

```bash
# Divisor Configuration
REDIS_ADDR=quotient-redis:6379
REDIS_PASSWORD=your_redis_password
NUM_IPS=5
DESIRED_SUBNET=10.192.0.0/10
TARGET_SUBNETS=10.100.0.0/16
INTERFACE_NAME=divisor
CONTAINER_PREFIX=quotient-runner
```

### Configuration with Multiple Subnets

If your competition infrastructure or source IP ranges span multiple subnets:

```bash
REDIS_ADDR=quotient-redis:6379
REDIS_PASSWORD=your_redis_password
NUM_IPS=10
DESIRED_SUBNET=10.192.0.0/16,192.168.200.0/24
TARGET_SUBNETS=10.100.0.0/16,10.200.0.0/16,172.16.0.0/12
INTERFACE_NAME=divisor
CONTAINER_PREFIX=quotient-runner
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `REDIS_ADDR` | Yes | `localhost:6379` | Address of the Quotient Redis server |
| `REDIS_PASSWORD` | Yes | - | Password for Redis authentication |
| `NUM_IPS` | Yes | - | Number of IP addresses to create on the interface |
| `DESIRED_SUBNET` | Yes | - | Comma-separated CIDR subnet(s) from which to allocate IPs (`DESIRED_SUBNETS` is also supported) |
| `TARGET_SUBNETS` | Yes | - | Comma-separated list of destination subnets |
| `INTERFACE_NAME` | No | `divisor` | Name for the network interface |
| `CONTAINER_PREFIX` | No | `quotient-runner` | Prefix to identify runner containers |
| `DIVISOR_MODE` | No | `snat` | Mode of operation, see [direct mode](#direct-mode) |
| `TARGET_SUBNET_GATEWAY` | No | - | Direct mode: gateway for `TARGET_SUBNETS` (unset: on-link) |
| `QUOTIENT_BACKEND` | No | `redis` | Event source: `redis` or `nats` |
| `NATS_URL` | No | `nats://localhost:4222` | Core NATS server URL, used when `QUOTIENT_BACKEND=nats` |
| `NATS_ROUND_CLOSED_SUBJECT` | No | `scoring.rounds.closed` | Subject that carries one closed-round message |
| `SYN_SHAPE` | No | - | `on`: make each runner connection's TTL and SYN match the OS the check claims, see [SYN shaping](#syn-shaping) |
### Variable Details

#### REDIS_ADDR

The address where Divisor can reach the Redis server. Since Divisor uses host networking, use `localhost:6379` if Redis port is exposed to the host, or the actual host IP.

```bash
# If Redis is exposed on localhost
REDIS_ADDR=localhost:6379

# If using host IP
REDIS_ADDR=192.168.1.100:6379
```

#### REDIS_PASSWORD

Must match the `REDIS_PASSWORD` configured for the Quotient Redis container.

#### NUM_IPS

The number of IP addresses to configure on the divisor interface. This should typically match or exceed the number of runner replicas configured in `docker-compose.yml`.

```bash
# For 5 runner replicas
NUM_IPS=5

# For high-availability with extra IPs
NUM_IPS=10
```

#### DESIRED_SUBNET

One or more comma-separated CIDR subnets from which Divisor will randomly select IP addresses (`DESIRED_SUBNETS` is also accepted as an alias). Choose subnet(s) that:
- Do not conflict with your existing network infrastructure
- Do not overlap with team networks
- Have enough total addresses for `NUM_IPS`

```bash
# Large private subnet
DESIRED_SUBNET=10.192.0.0/10

# Smaller dedicated subnet
DESIRED_SUBNET=192.168.200.0/24

# Multiple non-contiguous CIDR blocks
DESIRED_SUBNET=10.192.0.0/16,172.16.50.0/24,192.168.200.0/24
```

#### TARGET_SUBNETS

Comma-separated list of destination subnets that should use the divisor interface. This typically includes all team network ranges.

```bash
# Single team subnet
TARGET_SUBNETS=10.100.0.0/16

# Multiple team subnets
TARGET_SUBNETS=10.100.0.0/16,10.200.0.0/16

# Broad range covering all teams
TARGET_SUBNETS=10.0.0.0/8
```

#### INTERFACE_NAME

The name assigned to the network interface created by Divisor. The default `divisor` works for most deployments.

#### QUOTIENT_BACKEND

Selects where Divisor hears that a scoring round closed.

- `redis` (the default) subscribes to the Redis `events` channel and reconfigures on a payload of exactly `round_finish`. Other payloads are ignored. `REDIS_ADDR` defaults to `localhost:6379`. `REDIS_PASSWORD` is sent as the Redis password when set.
- `nats` connects to core NATS (not JetStream) and reconfigures on each valid message. Anything else is rejected at startup.

```bash
QUOTIENT_BACKEND=nats
NATS_URL=nats://localhost:4222
NATS_ROUND_CLOSED_SUBJECT=scoring.rounds.closed
```

#### NATS_URL

Used only in NATS mode. The URL is passed to the NATS client as-is, so user info and tokens belong in the URL (`nats://user:password@host:4222` or `nats://token@host:4222`). There is no separate username, token, or credentials-file variable.

#### NATS_ROUND_CLOSED_SUBJECT

Each message on this subject is one closed round. The payload is JSON:

```json
{"round_id": "6f1c0c3e-9b1a-4e0a-9c2a-1b7e5d4a8c11", "closed_at": "2026-10-24T22:00:00Z"}
```

`round_id` is a UUID string and `closed_at` is RFC3339. Quotient publishes one message when a round reaches completed, and at most once. Divisor does not inspect the round. The message arriving runs the same reconfiguration as Redis `round_finish`. The body is decoded leniently: `round_id` is added to the log when it is present, and a body that is missing fields or is not JSON is logged and still reconfigures. It does not stop the listener.

---

## Project layout

`cmd/divisor` is the process entry point. It loads `.env`, checks `DIVISOR_MODE`, wires an event source to network reconfiguration, and runs. The rest of the program lives under `internal/`:

- `config` reads environment variables
- `ippool` chooses addresses from `DESIRED_SUBNET`
- `network` rotates the interface and installs SNAT rules or direct-mode routes
- `events` subscribes to Redis `round_finish` or a NATS round-closed subject. Both call the same reconfiguration function.
- `shape` installs the SYN-shaping table and NFQUEUE listeners (`SYN_SHAPE=on`) and holds the watchdog (`divisor watchdog`)

Build with `go build -o divisor ./cmd/divisor`.

## How It Works

### Initialization

1. Divisor subscribes to round-closed notifications. The default is the Redis `events` channel. With `QUOTIENT_BACKEND=nats` it is the NATS subject `scoring.rounds.closed`.
2. Creates (or recreates) the network interface specified by `INTERFACE_NAME`
3. Assigns `NUM_IPS` random addresses from `DESIRED_SUBNET` to the interface
4. Each IP is validated via ICMP ping to ensure it's not already in use

### Round-Based Rotation

1. Quotient signals the end of a scoring round. Redis mode uses the payload `round_finish`. NATS mode uses one JSON message, `{"round_id": "<uuid>", "closed_at": "<RFC3339>"}`, published once when the round reaches completed.
2. Divisor receives the event and triggers reconfiguration
3. New random IPs are selected and added to the interface, next to the current ones
4. NAT rules for the new IPs are inserted for all runner containers, then the old rules are deleted
5. In SNAT mode, the previous IPs are removed 2 seconds later

A connection opened during a rotation therefore always matches a SNAT rule whose address is on the interface, and connections whose SYN left from an old address just before the switch still get their answers. Keeping the new addresses when the old primary address is removed needs `promote_secondaries` on the interface, which SNAT mode sets on `INTERFACE_NAME`; if it can't, Divisor removes the old addresses first, as before, and logs a warning.

### NAT Rule Configuration

For each Quotient runner container:
1. Divisor discovers the container's IP address via Docker API
2. Creates SNAT rules mapping the container IP to a divisor interface IP
3. Rules target traffic destined for `TARGET_SUBNETS`
4. Source ports are randomized for additional obfuscation

### Container Discovery

Divisor automatically finds runner containers by matching the naming pattern `quotient-runner-*`. This aligns with how Docker Compose names replicated service containers.

---

## Deployment

### Docker Compose Configuration

The Quotient `docker-compose.yml` includes Divisor configuration:

```yaml
divisor:
  build:
    context: divisor/
    dockerfile: Dockerfile
  restart: always
  env_file:
    - .env
  network_mode: host
  depends_on:
    redis:
      condition: service_healthy
  privileged: true
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock:ro
```
### Enabling Divisor
1. Initialize the submodule:
   ```bash
   git submodule update --init --recursive
   ```

2. Add configuration to `.env`:
   ```bash
   # Add to existing .env file
   NUM_IPS=5
   DESIRED_SUBNET=10.192.0.0/10
   TARGET_SUBNETS=10.100.0.0/16
   INTERFACE_NAME=divisor
   ```

3. Start the stack:
   ```bash
   docker-compose up --build -d
   ```

### Disabling Divisor

To run Quotient without IP rotation, comment out or remove the divisor service from `docker-compose.yml`:

```yaml
# divisor:
#   build:
#     context: divisor/
#     dockerfile: Dockerfile
#   ...
```

### Direct Mode

With `DIVISOR_MODE=direct`, Divisor expects to run in a runner's network namespace and sets the address directly on `INTERFACE_NAME`. Each runner must have its own divisor attached. Use this mode if you want to run on Kubernetes, or otherwise don't want to use the SNAT mode.

Requires `net.ipv4.conf.<INTERFACE_NAME>.promote_secondaries=1`. Divisor needs an IP to ping from when ensuring an address is unused, and in direct mode there's no existing IP to rely on other than the previously used scoring IP, so we add the new IP before removing the old one.

### SYN Shaping

With `SYN_SHAPE=on`, the packets a check sends leave with the TCP/IP fingerprint of the operating system the check claims (its User-Agent, workstation name or client banner), not the runner's Linux one. The runner marks each socket with a DSCP value per OS when `QUOTIENT_PROFILE_MARK=dscp` is set on it: 7 Windows, 11 Linux, 15 macOS. **Set that only on runners behind a Divisor with `SYN_SHAPE=on`**, or the marks reach the teams.

Divisor's `divisor_shape` nftables table (postrouting, before SNAT), for traffic to `TARGET_SUBNETS`:
- clears the DSCP and sets the OS's TTL (128 Windows, 64 Linux and macOS, plus `SHAPE_EXTRA_HOPS`) on every packet of the flow, also on packets the runner kernel sends without the socket (via the conntrack mark). The profile DSCP values are cleared toward every other destination too;
- sends SYNs of the Windows and macOS profiles to an NFQUEUE listener that rewrites the SYN's options into the OS's layout (Windows: `mss,nop,ws,nop,nop,sackOK`, no timestamps). Without timestamps in the SYN the server answers without them, and the client runs the whole flow without timestamps. The window scale is only ever lowered. Nothing after the SYN is rewritten, so there is no per-flow state in Divisor.

Divisor sets the TTL of marked flows, overriding Quotient's `QUOTIENT_RUNNER_EXTRA_HOPS` for them (ping checks carry no mark and keep it). In SNAT mode Divisor's egress is where a real host would sit, so leave `SHAPE_EXTRA_HOPS` at 0. In direct mode the table is in the runner pod, before the node; set it to the number of routers between the pod and the scoring network.

**Runner window scale:** the runner's own window scale must be at least the OS's (8 for Windows), because Divisor never raises one. Give runner containers `net.ipv4.tcp_rmem = 4096 131072 8388608` (a per-network-namespace sysctl: compose `sysctls:`, or a Kubernetes pod `securityContext.sysctls` entry, which needs the kubelet to allow it). With Linux's default 6 MiB maximum, Windows SYNs keep scale 7. With the 8 MiB maximum, sockets without a profile clamp (custom checks) announce scale 8.

**Failure behaviour:** if no listener is bound, or its queue or socket buffer is full, the kernel passes SYNs unmodified (`queue ... bypass`, fail-open). Connections still work, and the runner's own fingerprint shows. The TTL and DSCP rules stay in place either way. Address rotation does not touch the table: it matches the DSCP mark and `TARGET_SUBNETS`, not the rotated SNAT addresses.

A listener that is bound but **not answering** (Divisor frozen or hung) is not covered by the kernel's fail-open: its SYNs wait in the queue, and the checks that sent them time out. Run the watchdog, `divisor watchdog`, as its own container (SNAT mode: `network_mode: host`, `cap_add: [NET_ADMIN]`) or as a pod sidecar (direct mode), so that it keeps running when Divisor is frozen.
- It reads `/proc/net/netfilter/nfnetlink_queue` every 50 ms.
- When the Windows/macOS queues have been non-empty at every sample for `SHAPE_WATCHDOG_THRESHOLD` (default `500ms`), it empties the table's `synopts` chain, so new SYNs leave unshaped.
- It puts the queue rules back once the queues have been empty that long.
- The chain is the bypass state, so a watchdog that restarts mid-bypass still restores.
- The chain is also re-read during a stall, so a Divisor restart that reinstalls the queue rules is bypassed again.
- It touches only that chain. It writes its trips and state to `/run/divisor/watchdog.json`; mount the same directory in Divisor. It reads `.env` like Divisor.

**Counters:** at every rotation Divisor logs `SYN shaping counters`:
- `shaped` and `passed_through`: SYNs rewritten or left unmodified since Divisor started;
- `verdict_errors`;
- `kernel_queued`: SYNs the kernel queued;
- `failed_open`: queued SYNs that never reached the listener because its socket buffer was full, so they left unshaped. A full queue (65536 SYNs) fails open before queueing and is not counted;
- `watchdog_trips` and `watchdog_bypassed`.

It warns when the watchdog's state is missing or stale.

| Variable | Default | Description |
|---|---|---|
| `SHAPE_EXTRA_HOPS` | `0` | Added to each profile's TTL (0–64) |
| `SHAPE_WATCHDOG_THRESHOLD` | `500ms` | How long the shaping queues may stay non-empty before the watchdog bypasses shaping (watchdog) |

Needs `nft` in the image and the `nfnetlink_queue` kernel module.

---

## Troubleshooting

### Divisor Container Won't Start

**Check submodule initialization:**
```bash
ls -la divisor/
# Should contain Dockerfile, cmd/divisor/main.go, etc.

# If empty, initialize:
git submodule update --init --recursive
```

**Check environment variables:**
```bash
docker-compose config | grep -A 20 divisor
```

### IP Addresses Not Rotating

**Verify Redis connectivity:**
```bash
docker logs quotient-divisor-1 2>&1 | grep -i redis
```

**Check for round_finish events:**
```bash
docker exec quotient-redis redis-cli -a $REDIS_PASSWORD SUBSCRIBE events
# Start a scoring round and verify events are published
```

### NAT Rules Not Applied

**Check iptables on host:**
```bash
sudo iptables -t nat -L -n -v | grep -i snat
```

**Verify container discovery:**
```bash
docker ps --filter "name=quotient-runner" --format "{{.Names}}"
```

### Network Conflicts

**Symptoms:** Connectivity issues, duplicate IP errors

**Resolution:**
1. Choose a different `DESIRED_SUBNET` that doesn't overlap with:
   - Host network interfaces
   - Docker bridge networks
   - Team infrastructure subnets

2. Verify no conflicts:
   ```bash
   ip addr show
   ip route show
   ```

### Checking Divisor Logs

```bash
# View recent logs
docker logs quotient-divisor-1

# Follow logs in real-time
docker logs -f quotient-divisor-1

# Check for errors
docker logs quotient-divisor-1 2>&1 | grep -i error
```
