## wireguard-install (hardened fork)

WireGuard [road warrior](http://en.wikipedia.org/wiki/Road_warrior_%28computing%29)
installer for Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora.

This script sets up your own VPN server in well under a minute, even if you
have never touched WireGuard before. It is designed to be unobtrusive,
universal, and safe to run unattended.

This repository is a hardened fork of the upstream [`Nyr/wireguard-install`](https://github.com/Nyr/wireguard-install).
See [What's different from upstream](#whats-different-from-upstream) below.

### Installation

Run the script as root and follow the assistant:

```sh
wget https://raw.githubusercontent.com/<your-org>/wireguard-install/master/wireguard-install.sh \
    -O wireguard-install.sh && sudo bash wireguard-install.sh
```

Once it finishes, run the same script again to add more clients, remove
clients, or completely uninstall WireGuard.

### Supported distributions

| Distribution         | Minimum version | Kernel module | BoringTun userspace |
| -------------------- | --------------- | ------------- | ------------------- |
| Ubuntu               | 22.04           | Yes           | Yes (x86_64 only)   |
| Debian               | 11              | Yes           | Yes (x86_64 only)   |
| AlmaLinux / Rocky / CentOS Stream | 9   | Yes           | Yes (x86_64 only)   |
| Fedora               | current         | Yes           | Yes (x86_64 only)   |

In containerized environments (OpenVZ, LXC, some Docker setups) without the
`wireguard` kernel module, the installer transparently falls back to
[BoringTun](https://github.com/cloudflare/boringtun) — Cloudflare's userspace
WireGuard implementation — and configures `wg-quick` to use it.

### What's different from upstream

This fork applies five rounds of hardening and refactoring without changing
the interactive user flow. Existing installations remain backward-compatible:
re-running the script on a host that already has `/etc/wireguard/wg0.conf`
keeps every prior configuration value (subnet, ULA prefix, port) intact.

#### Safety baseline
- `set -uo pipefail` so undefined variables fail loudly.
- `die()` helper writes to **stderr** and exits with status **1**;
  every bare `exit` on an error path is now an explicit `exit 1`.
- `EXIT` trap releases the lockfile cleanly; `INT`/`TERM` traps abort
  with a clear message instead of leaving the system half-configured.
- `flock`-based lockfile (`/var/lock/wireguard-install.lock`) so two
  concurrent installer runs cannot race on `wg0.conf`.
- Every privileged package operation (`apt-get`, `dnf`, `systemctl
  enable`) is followed by `|| die "..."` so the script bails on the
  first failure rather than continuing into an inconsistent state.

#### Input validation
- Strict IPv4 octet validation: each octet must be 0-255. The previous
  regex `^[0-9]{1,3}(\.[0-9]{1,3}){3}$` accepted `999.999.999.999`,
  which would silently break DNS for every client.
- Validation applies to **both** custom DNS input and the resolvers
  parsed from `/etc/resolv.conf` / `/run/systemd/resolve/resolv.conf`.

#### Randomized IPv6 ULA prefix
- A fresh install generates a random RFC 4193 /64 prefix
  (`fdXX:XXXX:XXXX:XXXX::/64`) from `/dev/urandom`. Previously every
  installation used the same hardcoded `fddd:2c4:2c4:2c4::/64`, which
  (a) fingerprinted the host as running this specific installer and
  (b) made it impossible to mesh two installer-managed VPNs together.
- Existing installs keep their current prefix — the helper reads it
  back from `wg0.conf` to preserve peer compatibility.

#### Hardened downloads (BoringTun + public-IP lookup)
- `secure_download()` enforces HTTPS (`--proto '=https'`), pins
  TLS 1.2 minimum, retries 3 times with 2-second backoff, and bounds
  both connect and overall timeouts. Falls back from `curl` to `wget`
  with equivalent flags.
- BoringTun binary fetch and the embedded `boringtun-upgrade` daily
  script both use this hardened helper.
- Public-IP detection now probes **four** services with fallback:
  `api.ipify.org`, `ifconfig.me`, `ipv4.icanhazip.com`, and finally
  the upstream `ip1.dynupdate.no-ip.com`. The single-point-of-failure
  in the original is gone.

> **Note** — Upstream does not publish detached SHA256SUMS or signed
> releases for BoringTun, so cryptographic verification is not yet
> possible. TLS 1.2+ with curl's default HSTS handling is the best
> mitigation available without a maintainer-side change.

#### Refactor and performance
- The four per-OS `if/elif` install ladders are consolidated into a
  single `case "$os" in ubuntu|debian) ...` block. The same applies
  to the uninstall path. ~70 lines of duplicated code removed.
- `ip -o addr show ... | awk` replaces the legacy
  `ip addr | grep | grep | cut | grep | sed` chain.
- IPv4 and IPv6 addresses are enumerated **once** with `mapfile` into
  bash arrays. Previously the same pipeline ran up to 5 times during
  a fresh install.

#### Backup before mutation
- `backup_wg_conf()` snapshots `/etc/wireguard/wg0.conf` to
  `wg0.conf.bak.<epoch>` before every change (client add, client
  remove). Recover from a botched run with `cp wg0.conf.bak.* wg0.conf`.

#### Hygiene
- `umask 077` around `wg0.conf` and `client.conf` writes so secret
  material is never world-readable, even transiently.
- `command -v` replaces the bash-specific `hash` builtin for
  portability.
- All shellcheck warnings addressed (only info-level style hints
  remain).

### Operational notes

- **Lockfile**: `/var/lock/wireguard-install.lock`. If the installer
  reports "already running" but no other process exists, remove the
  file manually.
- **Backups**: `/etc/wireguard/wg0.conf.bak.<epoch>` (one per mutation).
  These are gitignored at the repo root but may need rotation if you
  run the script frequently.
- **Subnet and interface name** remain hardcoded to `10.7.0.0/24` and
  `wg0` for backward compatibility with prior installs. Making them
  configurable is on the roadmap.

### Usage — common workflows

| Action                  | How                                              |
| ----------------------- | ------------------------------------------------ |
| Fresh install           | `sudo bash wireguard-install.sh`                 |
| Add a client            | Re-run the script, choose option **1**           |
| Remove a client         | Re-run the script, choose option **2**           |
| Uninstall WireGuard     | Re-run the script, choose option **3**           |
| QR code for a client    | `qrencode -t ANSI256UTF8 < <client>.conf`        |
| Inspect live peers      | `sudo wg show wg0`                               |
| Restart the VPN service | `sudo systemctl restart wg-quick@wg0.service`    |

### Roadmap (not yet implemented)

- `--unattended` mode driven entirely by environment variables for
  Ansible / Terraform / cloud-init use.
- `--help` / `--version` flags.
- Configurable subnet (`WG_SUBNET_V4=`) and interface name (`WG_IF=`).
- SHA256 verification for the BoringTun binary, contingent on
  upstream publishing checksums.

### License

MIT — same as the upstream project. See `LICENSE.txt`.

### Credit

Original installer by [Nyr](https://github.com/Nyr/wireguard-install)
(MIT-licensed). This fork preserves the upstream's road-warrior
philosophy and CLI flow.
