# docker-fw

UFW firewall rules for Docker and Podman integration, to be placed at `/etc/ufw/after.rules`.

**DISCLAIMER**: The firewall rules are supplied in the hope that they will be useful,
but **WITHOUT ANY WARANTY**. Use at your own risk.

## Problem

By default, the Docker daemon manipulates `iptables` directly and bypasses UFW entirely. This means ports exposed by containers are reachable from the network even if UFW would otherwise block them.

Also, containers can reach services on the host and local network without restriction, which is bad when running untrusted code in a container.

## Assumptions
The design of the rules in `ufw/after.rules` is based on the following assumptions:
- **Code running in containers is not trusted**, it should be prevented from accessing otherwise protected resources, such as services running on the host.
- **Computers on the local network are not trusted**, the local network may include everyone staying at the same hotel, riding the same train, or attending the same conference.

## What these rules do
The rules in `ufw/after.rules` will ensure that incoming traffic can only reach containers if UFW allows it, and containers can only connect to services on the host or local network if permitted by UFW rules. It will:

- **Prevent Docker from bypassing UFW** for exposed ports — inbound connections to containers are subject to UFW route rules (e.g. `ufw route allow proto tcp from any to any port 8000`).
- **Block containers from reaching the LAN** (RFC 1918 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Block containers from reaching the host** (host ports can be allowed with `ufw allow in on docker+ to any port <PORT>`).

Note that traffic from containers is identified based on the device name prefix such as `docker+` or `podman+`. So the rules will not interfere with traffic in a local LAN that uses addresses in the ranges `10.0.0.0/8` and `172.16.0.0/12`, which are also typically used by Docker and Podman.

Containers are still allowed to:
- **Use local DNS** — containers may query DNS servers on the LAN and on the host.
- **Talk to other containers** — forwarding between interfaces matching prefixes such as `docker+` is permitted.
- **Access the internet** — containers can reach public IP addresses (but not addresses on the LAN).

NOTE: The containment rules DO NOT WORK for Docker or Podman running in "rootless" mode, since they would be using a user-space network stack and their traffic is indistinguishable from the user's. For details and other exceptions see the [Caveats](#caveats) section below.

## Installation

```bash
sudo cp --backup=numbered /etc/ufw/after.rules /etc/ufw/after.backup
sudo cp ufw/after.rules /etc/ufw/after.rules
sudo cp --backup=numbered /etc/ufw/after6.rules /etc/ufw/after6.backup
sudo cp ufw/after6.rules /etc/ufw/after6.rules
sudo ufw reload
```

`after6.rules` is the IPv6 counterpart; UFW loads it automatically via
`ip6tables` (see [IPv6](#ipv6) below). Then [run tests](#testing) to confirm.

## Usage examples

Allow external connections to a port published by a container. A published
port is reached by *forwarded* traffic (DNAT'd to the container), so it is
governed by UFW's route rules, not `ufw allow` (which only affects traffic
to the host itself):
```bash
ufw route allow proto tcp from any to any port 8000
```

Allow containers to connect to a port on the host (e.g. Xdebug):
```bash
ufw allow in on docker+ to any port 9003
```

Allow podman to connect to (almost) any unprivileged port on the host:
```bash
ufw allow in on podman+ proto tcp to any port 1024:65499
```

Note that ports 65500 and above are used by the self-test, allowing them will produce
misleading results from `tests/host_tests.py`. So they are now allowed by the example above.

## IPv6

`ufw/after6.rules` is the IPv6 counterpart, installed alongside `after.rules`
(UFW applies it automatically through `ip6tables`). The boundary it enforces is
the container's own host:

- **Container to host** is treated exactly as in IPv4: blocked by default, with
  the same DNS carve-out and the same `ufw allow in on docker+ ...` escape
  hatch. These rules match by interface, which works the same for both address
  families.
- **Everything beyond the host is blocked** — LAN and public internet alike.
  IPv4 can allow the internet while blocking the LAN because the LAN uses
  private (RFC 1918) ranges; IPv6 LANs use global addresses indistinguishable
  from the internet by range, so there is no safe way to make that split. Rather
  than leak, `after6.rules` denies all container IPv6 egress past the host.

Container-to-container IPv6 still works. Dual-stack containers simply use IPv4
for outbound connectivity. If a container genuinely needs a specific IPv6
destination beyond the host, open it deliberately with a route rule, e.g.:

```bash
ufw route allow proto tcp from any to any port 443
```

## Caveats

The rules identify container traffic by the network interface it passes through,
based on prefixes like `docker+`, `podman+`, or `br+`. Container setups whose
traffic does not go through such a bridge interface are not covered!

This can be dangerous, but it can also be useful: It can be used to
allow trusted containers to bypass the firewall rules, or it could be used by
malicious code to do the same.

The sections below describe cases where the firewall would be bypassed.

### Host networking (`--network=host`)

With the `--network=host` option, the container shares the host's network namespace.
There is no bridge interface, and traffic from the container is indistinguishable from
traffic of any other process on the host. It would still be subject to the general
firewall rules for the host, but not to any rules specific to containers. Since UFW
typically does not restrict outbound or loopback traffic, such a container can reach any
service on the host or LAN.

### Rootless
Both Podman and Docker have a "rootless" mode where the container engine runs
without root privileges. For Podman, this is the usual mode of operation.

Rootless container engines bypass the firewall rules because they do not
create a bridge interface on the host (they can't, because they do not have root
privileges). Instead, a user-mode network stack is used (`pasta` in Podman, `slirp4netns` in Docker).
Traffic leaves the host as ordinary outbound traffic from the user's processes.
Normal UFW rules still apply, so incoming traffic is filtered, but outgoing traffic
is typically unrestricted.

A possible workaround for rootless Docker is RootlessKit's experimental `lxc-user-nic`
network driver, which replaces the user-mode stack with a real veth pair attached to a host
bridge. Traffic then traverses the host firewall like rootful traffic.

In how far rootless containers can reach services on the host itself depends on configuration:

- With pasta's `--map-gw` behavior (the default), connections from the container
  to its gateway IP are redirected to the host's loopback interface. The traffic
  arrives on `lo` rather than on a `podman+` interface. Disable with `--no-map-gw`
  (via `network_cmd_options` in `containers.conf`).
- With slirp4netns, the equivalent is the `allow_host_loopback` option, which is
  disabled by default (rootless Docker also disables it by default).

Even with those mappings disabled, a rootless container can reach host services
bound to a wildcard or the LAN address by connecting to the host's LAN IP, and
UFW cannot block it because the relayed connection travels over `lo`. Only
services bound exclusively to `127.0.0.1` stay out of reach.

## Testing

The `tests/` directory contains an experimental test suite that probes a running system for
the outcomes described above and reports secure/insecure verdicts, including
optional cross-host tests from a second machine on the LAN. A one-time
`ufw_setup.sh` / `ufw_teardown.sh` pair prepares and restores the firewall so
the test runs themselves never change it. See [tests/README.md](tests/README.md).

The test suite is supplied in the hope it will be useful, but **WITHOUT ANY WARANTY**!

## Credits

Inspired by [chaifeng/ufw-docker](https://github.com/chaifeng/ufw-docker).
