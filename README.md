## wireguard-install (hardened fork, v2.0)

WireGuard [road warrior](http://en.wikipedia.org/wiki/Road_warrior_%28computing%29)
installer for Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora, and
Arch Linux.

Sets up your own VPN server in well under a minute, even if you have never
touched WireGuard before. Designed to be unobtrusive, universal, and safe
to run unattended in CI / cloud-init / Ansible.

This repository is a hardened fork of [`Nyr/wireguard-install`](https://github.com/Nyr/wireguard-install).
See [What's different from upstream](#whats-different-from-upstream) and
[CLI / environment reference](#cli--environment-reference) below.

---

### Quick start

```sh
wget https://raw.githubusercontent.com/<your-org>/wireguard-install/master/wireguard-install.sh \
    -O wireguard-install.sh && sudo bash wireguard-install.sh
```

Run the same script again to add or remove clients, or to uninstall.

### Unattended install (CI / cloud-init / Ansible)

```sh
sudo WG_PORT=51820 \
     WG_DNS=cloudflare \
     WG_CLIENT_NAME=laptop \
     bash wireguard-install.sh --unattended
```

Every interactive prompt has an `WG_*` environment-variable equivalent —
see the [CLI / environment reference](#cli--environment-reference).

### Supported distributions

| Distribution                        | Minimum | Kernel module | BoringTun (x86_64) |
| ----------------------------------- | ------- | ------------- | ------------------ |
| Ubuntu                              | 22.04   | Yes           | Yes                |
| Debian                              | 11      | Yes           | Yes                |
| AlmaLinux / Rocky / CentOS Stream   | 9       | Yes           | Yes                |
| Fedora                              | current | Yes           | Yes                |
| Arch Linux                          | rolling | Yes           | Yes                |

In containers without the `wireguard` kernel module, the installer
transparently falls back to [BoringTun](https://github.com/cloudflare/boringtun)
(Cloudflare's userspace WireGuard) and configures `wg-quick` to use it.

---

### CLI / environment reference

#### Flags

| Flag                       | What it does                                                       |
| -------------------------- | ------------------------------------------------------------------ |
| `--help`, `-h`             | Show full usage and exit                                           |
| `--version`, `-V`          | Print version and exit                                             |
| `--unattended`             | Run without prompts (use with `WG_*` env vars)                     |
| `--add-client NAME`        | Append a new peer, write `NAME.conf`, print QR                     |
| `--remove-client NAME`     | Remove a peer from `wg0.conf` and the live interface               |
| `--uninstall`              | Remove WireGuard entirely (no confirmation prompt)                 |
| `--self-update`            | Replace this script in place with the latest upstream version      |

#### Environment variables

Used by the install path and honored by `--unattended`. Anything left
unset falls back to interactive prompt (if a TTY is available) or to
the documented default.

| Variable                    | Default                          | Meaning                                              |
| --------------------------- | -------------------------------- | ---------------------------------------------------- |
| `WG_NON_INTERACTIVE`        | `0`                              | Force non-interactive (same as `--unattended`)       |
| `WG_PORT`                   | `51820`                          | Listen port                                          |
| `WG_CLIENT_NAME`            | `client`                         | Name of the first client                             |
| `WG_DNS`                    | system                           | Preset name (`cloudflare`, `google`, `opendns`, `quad9`, `gcore`, `adguard`, `system`) or custom comma-separated IPv4 list |
| `WG_PUBLIC_IP`              | auto-detect                      | Override the public IP / hostname                    |
| `WG_IPV4`                   | first non-loopback               | Server-side IPv4 to bind                             |
| `WG_IPV6`                   | `auto`                           | `auto`, `disable`, or an explicit IPv6 address       |
| `WG_SUBNET_V4`              | `10.7.0.0/24`                    | Internal VPN subnet                                  |
| `WG_GATEWAY_V4`             | `10.7.0.1`                       | Server-side gateway address                          |
| `WG_IF`                     | `wg0`                            | WireGuard interface name                             |
| `WG_ULA_PREFIX`             | random per install               | RFC 4193 ULA `/64` prefix override                   |
| `WG_BORINGTUN_AUTOUPDATE`   | `y` (unattended)                 | Enable the daily BoringTun upgrade job               |
| `WG_UPGRADE_VIA`            | `auto`                           | `systemd`, `cron`, or `auto` (prefer systemd)        |
| `WG_LOG_FILE`               | `/var/log/wireguard-install.log` | Where to append timestamped events                   |
| `WG_SCRIPT_URL`             | upstream raw URL                 | Used by `--self-update` to fetch the new version     |

---

### What's different from upstream

Six rounds of hardening + a v2.0 feature expansion. Every prior
installation stays backward-compatible — re-running the script keeps
the existing subnet, ULA prefix, port, and interface name intact.

#### Safety baseline (commit `c734a48`)
- `set -uo pipefail` so undefined variables fail loudly.
- `die()` helper writes to stderr and exits with status 1.
- `EXIT` trap releases the lockfile; `INT`/`TERM` traps abort cleanly.
- `flock`-based lockfile (`/var/lock/wireguard-install.lock`) so two
  concurrent installer runs cannot race on `wg0.conf`.
- Every privileged package operation now has `|| die "..."` so the
  script bails on the first failure.

#### Input validation (commit `ad5f853`)
- Strict IPv4 octet validation (each octet 0-255) applied to **both**
  user-supplied custom DNS and the resolvers parsed from `resolv.conf`.
- `is_valid_port()` enforces 1-65535.
- `is_valid_client_name()` enforces A-Z/0-9/_-, max 15 chars.

#### Randomized IPv6 ULA prefix (commit `7a74632`)
- Fresh installs generate 40 random bits from `/dev/urandom`. The
  upstream `fddd:2c4:2c4:2c4::/64` is no longer reused everywhere
  (fingerprinting + meshing collision risk).
- Existing installs keep their current prefix — the helper reads it
  back from `wg0.conf`.

#### Hardened downloads (commit `650ae0a`)
- `secure_download()` requires HTTPS (`--proto '=https'`), pins TLS 1.2
  minimum, retries 3× with backoff, bounds connect + overall timeouts.
- BoringTun fetch and the embedded `boringtun-upgrade` daily script
  both use this hardened helper.
- Public-IP detection probes 4 services in order: `api.ipify.org`,
  `ifconfig.me`, `ipv4.icanhazip.com`, then the original
  `ip1.dynupdate.no-ip.com`.

#### Refactor + caching + backups (commit `ec8233c`)
- Per-OS `if/elif` install ladders collapsed into a single `case`.
- IP address discovery uses `mapfile` once instead of `ip addr | grep |
  cut | grep | sed` 5× per install.
- `backup_wg_conf()` snapshots `/etc/wireguard/wg0.conf` to
  `wg0.conf.bak.<epoch>` before every client add/remove.
- `umask 077` around config writes so secret material is never
  world-readable, even transiently.

#### v2.0 feature expansion (commit `9399a8f`)
- **CLI flags**: `--help`, `--version`, `--add-client`, `--remove-client`,
  `--uninstall`, `--unattended`, `--self-update`.
- **Non-interactive mode**: every prompt has an `WG_*` env-var
  equivalent. Suitable for Ansible / cloud-init / CI.
- **Configurable layout**: subnet, gateway, interface name, and ULA
  prefix are all env-var driven.
- **Structured logging**: `/var/log/wireguard-install.log` gets
  timestamped events, mode 0600.
- **Arch Linux support**: pacman-based install/uninstall branches.
- **BoringTun binary integrity**: ELF magic + size bounds check
  before the binary is moved into `/usr/local/sbin`. Same check in
  the daily upgrade script.
- **systemd timer for updates**: replaces the cron job on systems
  where systemd is the init. Falls back to cron transparently.
- **Self-update**: `--self-update` flag fetches and replaces the
  script via the same hardened download helper, validates with
  `bash -n` and size sanity before swap, keeps a `pre-update.<epoch>`
  backup.
- **ERR-trap rollback**: registered paths/services are torn down if
  the install fails mid-way. The completion path sets a sentinel so
  rollback skips after success.

---

### Common workflows

| Action                         | How                                                              |
| ------------------------------ | ---------------------------------------------------------------- |
| Fresh install (interactive)    | `sudo bash wireguard-install.sh`                                 |
| Fresh install (unattended)     | `sudo WG_PORT=51820 WG_DNS=cloudflare bash wireguard-install.sh --unattended` |
| Add a client                   | `sudo bash wireguard-install.sh --add-client phone`              |
| Remove a client                | `sudo bash wireguard-install.sh --remove-client laptop`          |
| Uninstall                      | `sudo bash wireguard-install.sh --uninstall`                     |
| Update the installer itself    | `sudo bash wireguard-install.sh --self-update`                   |
| QR code for a client           | `qrencode -t ANSI256UTF8 < <client>.conf`                        |
| Inspect live peers             | `sudo wg show $WG_IF`                                            |
| Restart the VPN                | `sudo systemctl restart wg-quick@$WG_IF.service`                 |
| Tail the install log           | `sudo tail -f /var/log/wireguard-install.log`                    |

---

### Operational notes

- **Lockfile**: `/var/lock/wireguard-install.lock`. Stale lockfile?
  Verify no process holds it (`lsof` or `fuser`) then remove.
- **Backups**: `/etc/wireguard/<if>.conf.bak.<epoch>` (one per
  mutation). Gitignored at the repo root; rotate manually if needed.
- **Pre-update backups**: when `--self-update` runs, the previous
  script is preserved at `<script>.pre-update.<epoch>`.
- **Log file**: `/var/log/wireguard-install.log`, mode 0600. Never
  contains private keys.

---

### Caveats & non-goals

- **BoringTun cryptographic verification**: upstream `wg.nyr.be` does
  not publish detached SHA256SUMS or signed releases. The script uses
  TLS 1.2+ pinning + ELF magic + size bounds as best-effort. Real
  signature verification is contingent on a maintainer-side change.
- **Alpine Linux**: intentionally not supported. Alpine uses OpenRC,
  not systemd; the wg-quick service model would require a parallel
  implementation. PRs welcome.
- **Multiple interfaces**: setting `WG_IF=wg1` works for a fresh
  install but the script does not yet manage interface lifecycles
  side-by-side. Treat one host = one WireGuard interface.

---

### License

MIT — same as the upstream project. See `LICENSE.txt`.

### Credit

Original installer by [Nyr](https://github.com/Nyr/wireguard-install)
(MIT-licensed). This fork preserves the upstream's road-warrior
philosophy and interactive CLI flow.
