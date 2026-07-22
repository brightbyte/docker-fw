# docker-fw

UFW firewall rules for Docker integration, to be placed at `/etc/ufw/after.rules`.

## Problem

By default, the Docker daemon manipulates `iptables` directly and bypasses UFW entirely. This means ports exposed by containers are reachable from the network even if UFW would otherwise block them.

Also, containers can reach services on the host and local network without restriction, which is bad when running untrusted code in a container.

## Assumptions
The design of the rules in `ufw/after.rules` are based on the following assumptions:
- **Code running in docker is not trusted**, it should be prevented from accessing resources otherwise protected resources, such as services running on the host.
- **Computers on the local network are not trusted**, the local network may include everyone staying at the same hotel, riding the same train, or attending the same conference.

## What these rules do
The rules in `ufw/after.rules` will ensure that incoming traffic can only reach docker containers if UFW allows it, and containers can only connect to services on the host or local network if permitted by UFW rules. It will:

- **Prevent Docker from bypassing UFW** for exposed ports — inbound connections to containers are subject to normal UFW rules (e.g. `ufw allow 8000`).
- **Block containers from reaching the LAN** (RFC 1918 ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
- **Block containers from reaching the host**  (host ports can be allowed with `ufw allow in on docker+ to any port <PORT>`).

Note that docker traffic is identified based on the device name, `docker*` and `br-*`. So the rules will not interfere with traffic in the local LAN that uses addresses in the ranges `10.0.0.0/8` and `172.16.0.0/12`, wh8ich are also typically used by docker.

Docker containers are still allowed to:
- **Use local DNS** — containers may query DNS servers on the LAN and on the host.
- **Talk to other containers** — forwarding between `docker+` and `br+` interfaces is permitted.
- **Allow outbound internet access** — containers can reach public IP addresses (but not addresses on the LAN).

## Installation

```bash
sudo cp ufw/after.rules /etc/ufw/after.rules
sudo ufw reload
```

## Usage examples

Allow external connections to a port exposed by a container (same as any local service):
```bash
ufw allow 8000
```

Allow containers to connect to a port on the host (e.g. Xdebug):
```bash
ufw allow in on docker+ to any port 9003
```

Allow the docker bridge to connect to any unprivileged port on the host:
```bash
ufw allow in on br+ proto tcp to any port 1024:65535
```

## Credits

Inspired by [chaifeng/ufw-docker](https://github.com/chaifeng/ufw-docker).
