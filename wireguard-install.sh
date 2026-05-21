#!/bin/bash
#
# Hardened fork of https://github.com/Nyr/wireguard-install
#
# Original Copyright (c) 2020 Nyr. Released under the MIT License.
#
# v2.0 adds: CLI argument parser, fully non-interactive mode driven by
# WG_* environment variables, configurable subnet/interface/ULA prefix,
# structured logging to /var/log/wireguard-install.log, Arch Linux
# support, BoringTun binary integrity checks, systemd timer for
# updates (with cron fallback), self-update mechanism, and an ERR-trap
# rollback that cleans up partial installs.
#

set -uo pipefail

readonly SCRIPT_VERSION="2.0.0"
readonly SCRIPT_URL_DEFAULT="https://raw.githubusercontent.com/Nyr/wireguard-install/master/wireguard-install.sh"

# ---------------------------------------------------------------------------
# Defaults (can be overridden via environment for unattended runs)
# ---------------------------------------------------------------------------

: "${WG_NON_INTERACTIVE:=0}"
: "${WG_LOG_FILE:=/var/log/wireguard-install.log}"
: "${WG_SUBNET_V4:=10.7.0.0/24}"
: "${WG_GATEWAY_V4:=10.7.0.1}"
: "${WG_IF:=wg0}"
: "${WG_ULA_PREFIX:=}"
: "${WG_PORT:=}"
: "${WG_DNS:=}"
: "${WG_CLIENT_NAME:=}"
: "${WG_PUBLIC_IP:=}"
: "${WG_IPV4:=}"
: "${WG_IPV6:=}"
: "${WG_BORINGTUN_AUTOUPDATE:=}"
: "${WG_UPGRADE_VIA:=auto}"
: "${WG_SCRIPT_URL:=$SCRIPT_URL_DEFAULT}"

# Internal globals populated by the parser and used by trap handlers
_lock_fd=""
_action="install"
_cli_client=""

# ---------------------------------------------------------------------------
# Error handling, locking, and validation helpers
# ---------------------------------------------------------------------------

die() {
	echo "ERROR: $*" >&2
	exit 1
}

log() {
	# Write to stdout and (if writable) append to the log file with timestamp.
	local msg="$*"
	echo "$msg"
	if [[ -n "$WG_LOG_FILE" ]] && [[ -w "$(dirname "$WG_LOG_FILE")" || -w "$WG_LOG_FILE" ]] 2>/dev/null; then
		printf '%s [%s] %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$$" "$msg" >> "$WG_LOG_FILE" 2>/dev/null || true
	fi
}

# Track resources created during install so an ERR trap can clean them up
_rollback_paths=()
_rollback_services=()
_rollback_step="boot"

register_rollback_path() {
	_rollback_paths+=("$1")
}

register_rollback_service() {
	_rollback_services+=("$1")
}

rollback_partial_install() {
	local rc=$?
	[[ "$_rollback_step" == "complete" ]] && return 0
	[[ "$_rollback_step" == "boot" ]] && return 0

	echo "" >&2
	echo "Installation failed (exit=$rc) at step: $_rollback_step" >&2
	echo "Rolling back partial state..." >&2

	local svc path
	for svc in "${_rollback_services[@]:-}"; do
		[[ -z "$svc" ]] && continue
		systemctl disable --now "$svc" 2>/dev/null || true
	done
	for path in "${_rollback_paths[@]:-}"; do
		[[ -z "$path" ]] && continue
		rm -rf "$path" 2>/dev/null || true
	done
	echo "Rollback complete. The system has been restored to its pre-install state." >&2
	echo "Re-run the installer once the underlying issue is fixed." >&2
}

cleanup_on_exit() {
	local rc=$?
	if [[ -n "$_lock_fd" ]]; then
		eval "exec ${_lock_fd}>&-" 2>/dev/null || true
	fi
	exit "$rc"
}
trap cleanup_on_exit EXIT
trap 'die "Interrupted."' INT TERM
trap 'rollback_partial_install' ERR

acquire_lock() {
	local lockfile="/var/lock/wireguard-install.lock"
	exec {_lock_fd}>"$lockfile" || die "Cannot create lockfile at $lockfile"
	if ! flock -n "$_lock_fd"; then
		die "Another wireguard-install process is already running."
	fi
}

is_valid_ipv4() {
	local ip="$1" oct
	[[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	for oct in "${BASH_REMATCH[@]:1:4}"; do
		(( oct <= 255 )) || return 1
	done
	return 0
}

is_valid_port() {
	local p="$1"
	[[ "$p" =~ ^[0-9]+$ ]] && (( p >= 1 && p <= 65535 ))
}

is_valid_client_name() {
	[[ "$1" =~ ^[A-Za-z0-9_-]{1,15}$ ]]
}

gen_random_ula_prefix() {
	local r
	r=$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n')
	printf 'fd%s:%s%s:%s%s' \
		"${r:0:2}" "${r:2:2}" "${r:4:2}" "${r:6:2}" "${r:8:2}"
}

detect_or_generate_ula_prefix() {
	local existing
	if [[ -f /etc/wireguard/${WG_IF}.conf ]]; then
		existing=$(grep -oE 'fd[0-9a-f]{2}(:[0-9a-f]{1,4}){3}' "/etc/wireguard/${WG_IF}.conf" | head -1)
		if [[ -n "$existing" ]]; then
			echo "$existing"
			return 0
		fi
	fi
	if [[ -n "$WG_ULA_PREFIX" ]]; then
		echo "$WG_ULA_PREFIX"
	else
		gen_random_ula_prefix
	fi
}

backup_wg_conf() {
	local f="/etc/wireguard/${WG_IF}.conf"
	[[ -f "$f" ]] || return 0
	cp -a "$f" "${f}.bak.$(date +%s)" || die "Failed to back up $f"
}

# HTTPS-only download with TLS 1.2+, retries, and bounded timeouts
secure_download() {
	local url="$1"
	if command -v curl >/dev/null 2>&1; then
		curl --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 \
			--connect-timeout 10 --max-time 60 -fsSL "$url"
	elif command -v wget >/dev/null 2>&1; then
		wget --secure-protocol=TLSv1_2 --tries=3 --waitretry=2 \
			--timeout=60 -qO- "$url"
	else
		return 1
	fi
}

detect_public_ipv4() {
	local services=(
		"https://api.ipify.org"
		"https://ifconfig.me/ip"
		"https://ipv4.icanhazip.com"
		"http://ip1.dynupdate.no-ip.com/"
	)
	local svc resp
	for svc in "${services[@]}"; do
		resp=$(secure_download "$svc" 2>/dev/null | head -1 | tr -d '[:space:]') || true
		if is_valid_ipv4 "$resp"; then
			echo "$resp"
			return 0
		fi
	done
	return 1
}

list_ipv4_addresses() {
	ip -4 -o addr show 2>/dev/null | awk '
		$3 == "inet" {
			split($4, a, "/")
			if (a[1] !~ /^127\./) print a[1]
		}'
}

list_ipv6_global_addresses() {
	ip -6 -o addr show scope global 2>/dev/null | awk '
		$3 == "inet6" {
			split($4, a, "/"); print a[1]
		}'
}

# Verify a downloaded file looks like a sane Linux x86_64 ELF binary.
# This is the best we can do without upstream-published checksums.
verify_elf_binary() {
	local path="$1"
	local min_bytes=131072    # 128 KiB lower bound (boringtun is ~1-4 MiB)
	local max_bytes=52428800  # 50 MiB upper bound

	[[ -f "$path" ]] || { echo "Binary missing: $path" >&2; return 1; }

	local size
	size=$(stat -c %s "$path" 2>/dev/null || stat -f %z "$path" 2>/dev/null || echo 0)
	if (( size < min_bytes || size > max_bytes )); then
		echo "Binary size out of plausible range: $size bytes" >&2
		return 1
	fi

	# ELF magic bytes: 0x7F 'E' 'L' 'F'
	local magic
	magic=$(head -c 4 "$path" | od -An -tx1 | tr -d ' \n')
	if [[ "$magic" != "7f454c46" ]]; then
		echo "Binary does not have ELF magic header (got: $magic)" >&2
		return 1
	fi
	return 0
}

# Translate a DNS preset name (cloudflare, google, ...) into a "ip1, ip2" pair
resolve_dns_preset() {
	case "${1,,}" in
		system|default|"") echo "" ;;
		google)            echo "8.8.8.8, 8.8.4.4" ;;
		cloudflare|1.1.1.1) echo "1.1.1.1, 1.0.0.1" ;;
		opendns)           echo "208.67.222.222, 208.67.220.220" ;;
		quad9)             echo "9.9.9.9, 149.112.112.112" ;;
		gcore)             echo "95.85.95.85, 2.56.220.2" ;;
		adguard)           echo "94.140.14.14, 94.140.15.15" ;;
		*)                 echo "$1" ;;
	esac
}

# Whether the platform we are running on offers systemd timers
have_systemd_timers() {
	command -v systemctl >/dev/null 2>&1
}

# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

usage() {
	cat <<USAGE
wireguard-install ${SCRIPT_VERSION} — hardened WireGuard road-warrior installer

USAGE:
  wireguard-install.sh [FLAGS]

FLAGS:
  --help                 Show this help and exit
  --version              Print version and exit
  --unattended           Run without prompts (requires WG_* env vars)
  --add-client NAME      Add a new client (non-interactive)
  --remove-client NAME   Remove an existing client (non-interactive)
  --uninstall            Remove WireGuard entirely (non-interactive)
  --self-update          Replace this script with the latest upstream version

ENVIRONMENT VARIABLES (read when --unattended or with no TTY):
  WG_PORT             WireGuard listen port (default: 51820)
  WG_CLIENT_NAME      Name of the first client (default: client)
  WG_DNS              cloudflare|google|opendns|quad9|gcore|adguard|system|
                        custom comma-separated IPv4 list
  WG_PUBLIC_IP        Public IPv4 or hostname (overrides auto-detection)
  WG_IPV4             Pin server IPv4 (default: first non-loopback)
  WG_IPV6             auto|disable|<address> (default: auto)
  WG_SUBNET_V4        VPN subnet (default: 10.7.0.0/24)
  WG_GATEWAY_V4       VPN gateway (default: 10.7.0.1)
  WG_IF               WireGuard interface name (default: wg0)
  WG_ULA_PREFIX       IPv6 ULA /64 prefix (default: random per install)
  WG_BORINGTUN_AUTOUPDATE  y|n
  WG_UPGRADE_VIA      systemd|cron|auto (default: auto)
  WG_LOG_FILE         Log destination (default: /var/log/wireguard-install.log)

EXAMPLES:
  sudo bash wireguard-install.sh                    # interactive
  sudo WG_PORT=51820 WG_DNS=cloudflare WG_CLIENT_NAME=laptop \\
       bash wireguard-install.sh --unattended       # fully scripted
  sudo bash wireguard-install.sh --add-client phone
  sudo bash wireguard-install.sh --remove-client laptop
  sudo bash wireguard-install.sh --uninstall
  sudo bash wireguard-install.sh --self-update

See README.md for the full hardening and operational notes.
USAGE
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--help|-h)        usage; exit 0 ;;
			--version|-V)     echo "wireguard-install ${SCRIPT_VERSION}"; exit 0 ;;
			--unattended)     WG_NON_INTERACTIVE=1; shift ;;
			--add-client)
				[[ $# -lt 2 ]] && die "--add-client requires a NAME"
				_action="add-client"
				_cli_client="$2"; WG_CLIENT_NAME="$2"
				WG_NON_INTERACTIVE=1
				shift 2
				;;
			--remove-client)
				[[ $# -lt 2 ]] && die "--remove-client requires a NAME"
				_action="remove-client"
				_cli_client="$2"
				WG_NON_INTERACTIVE=1
				shift 2
				;;
			--uninstall)      _action="uninstall"; WG_NON_INTERACTIVE=1; shift ;;
			--self-update)    _action="self-update"; shift ;;
			*) die "Unknown argument: $1 (try --help)" ;;
		esac
	done
}

# Read a value: $1 = env var name, $2 = prompt, $3 = default (optional)
ask() {
	local env_var="$1" prompt="$2" default="${3:-}" current
	current="${!env_var:-}"
	if [[ -n "$current" ]]; then
		printf '%s\n' "$current"
		return 0
	fi
	if [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
		if [[ -n "$default" ]]; then
			printf '%s\n' "$default"
			return 0
		fi
		die "Missing value for $env_var in non-interactive mode (and no default)."
	fi
	# Interactive: prompt with default in brackets
	local label="$prompt"
	[[ -n "$default" ]] && label="$prompt [$default]: " || label="$prompt: "
	local val=""
	read -rp "$label" val
	if [[ -z "$val" ]]; then
		val="$default"
	fi
	printf '%s\n' "$val"
}

# ---------------------------------------------------------------------------
# Self-update
# ---------------------------------------------------------------------------

do_self_update() {
	local target="${BASH_SOURCE[0]}"
	[[ "$target" == /* ]] || target="$(pwd)/$target"
	[[ -w "$target" ]] || die "Cannot write to $target (run with sudo or chown)."

	local tmp
	tmp=$(mktemp)
	trap 'rm -f "$tmp"' RETURN

	echo "Fetching latest installer from $WG_SCRIPT_URL ..."
	if ! secure_download "$WG_SCRIPT_URL" > "$tmp"; then
		rm -f "$tmp"
		die "Self-update failed: could not download from $WG_SCRIPT_URL"
	fi
	if ! bash -n "$tmp"; then
		rm -f "$tmp"
		die "Self-update aborted: downloaded script failed syntax check."
	fi
	if [[ $(stat -c %s "$tmp" 2>/dev/null || stat -f %z "$tmp" 2>/dev/null || echo 0) -lt 5000 ]]; then
		rm -f "$tmp"
		die "Self-update aborted: downloaded script suspiciously small."
	fi

	local backup
	backup="${target}.pre-update.$(date +%s)"
	cp -a "$target" "$backup" || die "Could not back up current script to $backup"
	mv "$tmp" "$target" || die "Could not replace $target"
	chmod +x "$target"
	echo "Updated to latest. Previous version saved to $backup"
}

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe 2>/dev/null | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".' >&2
	exit 1
fi

# Discard stdin from one-liner newlines (must happen before parse_args)
read -N 999999 -t 0.001 || true

parse_args "$@"

if [[ "$_action" == "self-update" ]]; then
	do_self_update
	exit 0
fi

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
elif [[ -e /etc/arch-release ]] || grep -qs '^ID=arch' /etc/os-release 2>/dev/null; then
	os="arch"
	os_version="rolling"
else
	die "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS, Fedora, and Arch Linux."
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	die "Ubuntu 22.04 or higher is required."
fi
if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		die "Debian Testing and Debian Unstable are unsupported by this installer."
	fi
	if [[ "$os_version" -lt 11 ]]; then
		die "Debian 11 or higher is required."
	fi
fi
if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
	os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
	die "$os_name 9 or higher is required."
fi

if ! grep -q sbin <<< "$PATH"; then
	die '$PATH does not include sbin. Try using "su -" instead of "su".'
fi

if ! systemd-detect-virt -cq; then
	use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
	use_boringtun="0"
else
	use_boringtun="1"
fi

if [[ "$EUID" -ne 0 ]]; then
	die "This installer needs to be run with superuser privileges."
fi

if [[ "$use_boringtun" -eq 1 ]]; then
	if [ "$(uname -m)" != "x86_64" ]; then
		die "In containerized systems without the wireguard kernel module, this installer supports only x86_64."
	fi
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		die "The system does not have the TUN device available."
	fi
fi

# Initialize log file before any state mutation
if [[ -n "$WG_LOG_FILE" ]]; then
	mkdir -p "$(dirname "$WG_LOG_FILE")" 2>/dev/null || true
	touch "$WG_LOG_FILE" 2>/dev/null || true
	chmod 600 "$WG_LOG_FILE" 2>/dev/null || true
fi

acquire_lock
log "wireguard-install ${SCRIPT_VERSION} starting action=${_action} os=${os}/${os_version}"

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ula_prefix=$(detect_or_generate_ula_prefix)

# ---------------------------------------------------------------------------
# Helpers used inside install/menu flows
# ---------------------------------------------------------------------------

new_client_dns () {
	# In non-interactive mode, WG_DNS picks the resolver directly
	if [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
		if [[ -z "$WG_DNS" ]]; then
			dns=""
		else
			dns=$(resolve_dns_preset "$WG_DNS")
		fi
		# When dns is still empty, fall back to system resolvers
		if [[ -z "$dns" ]]; then
			local resolv_conf="/etc/resolv.conf"
			if ! grep '^nameserver' /etc/resolv.conf 2>/dev/null | grep -qv '127.0.0.53'; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			local resolved="" ns
			while read -r ns; do
				if is_valid_ipv4 "$ns"; then
					if [[ -z "$resolved" ]]; then
						resolved="$ns"
					else
						resolved="$resolved, $ns"
					fi
				fi
			done < <(grep -v '^#\|^;' "$resolv_conf" 2>/dev/null | awk '$1=="nameserver" && $2 != "127.0.0.53" {print $2}')
			dns="$resolved"
		fi
		return 0
	fi

	echo "Select a DNS server for the client:"
	echo "   1) Default system resolvers"
	echo "   2) Google"
	echo "   3) 1.1.1.1"
	echo "   4) OpenDNS"
	echo "   5) Quad9"
	echo "   6) Gcore"
	echo "   7) AdGuard"
	echo "   8) Specify custom resolvers"
	read -rp "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-8]$ ]]; do
		echo "$dns: invalid selection."
		read -rp "DNS server [1]: " dns
	done
	case "$dns" in
		1|"")
			local resolv_conf
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			local resolved="" ns
			while read -r ns; do
				if is_valid_ipv4 "$ns"; then
					if [[ -z "$resolved" ]]; then
						resolved="$ns"
					else
						resolved="$resolved, $ns"
					fi
				fi
			done < <(grep -v '^#\|^;' "$resolv_conf" | awk '$1=="nameserver" && $2 != "127.0.0.53" {print $2}')
			dns="$resolved"
		;;
		2)  dns="8.8.8.8, 8.8.4.4" ;;
		3)  dns="1.1.1.1, 1.0.0.1" ;;
		4)  dns="208.67.222.222, 208.67.220.220" ;;
		5)  dns="9.9.9.9, 149.112.112.112" ;;
		6)  dns="95.85.95.85, 2.56.220.2" ;;
		7)  dns="94.140.14.14, 94.140.15.15" ;;
		8)
			echo
			local custom_dns=""
			until [[ -n "$custom_dns" ]]; do
				echo "Enter DNS servers (one or more IPv4 addresses, separated by commas or spaces):"
				read -rp "DNS servers: " dns_input
				dns_input=$(echo "$dns_input" | tr ',' ' ')
				for dns_ip in $dns_input; do
					if is_valid_ipv4 "$dns_ip"; then
						if [[ -z "$custom_dns" ]]; then
							custom_dns="$dns_ip"
						else
							custom_dns="$custom_dns, $dns_ip"
						fi
					fi
				done
				if [[ -z "$custom_dns" ]]; then
					echo "Invalid input."
				else
					dns="$custom_dns"
				fi
			done
		;;
	esac
}

new_client_setup () {
	local octet=2
	while grep AllowedIPs "/etc/wireguard/${WG_IF}.conf" | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
		(( octet++ ))
	done
	if [[ "$octet" -eq 255 ]]; then
		die "253 clients are already configured. The WireGuard internal subnet is full!"
	fi

	local has_ipv6=0
	if grep -q "${ula_prefix}::1" "/etc/wireguard/${WG_IF}.conf"; then
		has_ipv6=1
	fi

	# Derive the IPv4 subnet's first 3 octets so we honor WG_SUBNET_V4.
	# For 10.7.0.0/24 this produces "10.7.0".
	local v4_prefix
	v4_prefix=$(echo "$WG_SUBNET_V4" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3}')

	local key psk pubkey server_pubkey endpoint listen_port
	key=$(wg genkey)
	psk=$(wg genpsk)
	pubkey=$(wg pubkey <<< "$key")
	server_pubkey=$(grep PrivateKey "/etc/wireguard/${WG_IF}.conf" | cut -d " " -f 3 | wg pubkey)
	endpoint=$(grep '^# ENDPOINT' "/etc/wireguard/${WG_IF}.conf" | cut -d " " -f 3)
	listen_port=$(grep ListenPort "/etc/wireguard/${WG_IF}.conf" | cut -d " " -f 3)

	backup_wg_conf

	{
		echo "# BEGIN_PEER $client"
		echo "[Peer]"
		echo "PublicKey = $pubkey"
		echo "PresharedKey = $psk"
		if [[ "$has_ipv6" -eq 1 ]]; then
			echo "AllowedIPs = ${v4_prefix}.${octet}/32, ${ula_prefix}::${octet}/128"
		else
			echo "AllowedIPs = ${v4_prefix}.${octet}/32"
		fi
		echo "# END_PEER $client"
	} >> "/etc/wireguard/${WG_IF}.conf"

	local client_addr="${v4_prefix}.${octet}/24"
	if [[ "$has_ipv6" -eq 1 ]]; then
		client_addr="${client_addr}, ${ula_prefix}::${octet}/64"
	fi

	umask 077
	cat << EOF > "$script_dir"/"$client".conf
[Interface]
Address = $client_addr
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $server_pubkey
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${endpoint}:${listen_port}
PersistentKeepalive = 25
EOF
	umask 022
}

# Install a BoringTun systemd timer (preferred) or cron job (fallback) that
# runs the daily upgrade at a random time between 3:00 and 5:59.
install_boringtun_updater() {
	local mode="$WG_UPGRADE_VIA"
	if [[ "$mode" == "auto" ]]; then
		if have_systemd_timers; then
			mode="systemd"
		else
			mode="cron"
		fi
	fi

	if [[ "$mode" == "systemd" ]]; then
		cat << 'EOF' > /etc/systemd/system/boringtun-upgrade.service
[Unit]
Description=Update BoringTun userspace WireGuard binary
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/sbin/boringtun-upgrade
EOF
		# Randomize within 3:00-5:59 to spread load
		local minute=$(( RANDOM % 60 ))
		local hour=$(( RANDOM % 3 + 3 ))
		cat << EOF > /etc/systemd/system/boringtun-upgrade.timer
[Unit]
Description=Run boringtun-upgrade daily

[Timer]
OnCalendar=*-*-* ${hour}:${minute}:00
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
EOF
		systemctl daemon-reload
		systemctl enable --now boringtun-upgrade.timer || die "Failed to enable boringtun-upgrade.timer"
	else
		{ crontab -l 2>/dev/null; echo "$(( RANDOM % 60 )) $(( RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
	fi
}

remove_boringtun_updater() {
	systemctl disable --now boringtun-upgrade.timer 2>/dev/null || true
	rm -f /etc/systemd/system/boringtun-upgrade.timer /etc/systemd/system/boringtun-upgrade.service
	systemctl daemon-reload 2>/dev/null || true
	{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab - 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Action dispatcher
# ---------------------------------------------------------------------------

handle_add_client() {
	if [[ ! -e "/etc/wireguard/${WG_IF}.conf" ]]; then
		die "WireGuard is not installed (no ${WG_IF}.conf). Run the installer first."
	fi
	if [[ -n "$_cli_client" ]]; then
		client="$_cli_client"
	else
		client="$WG_CLIENT_NAME"
	fi
	is_valid_client_name "$client" || die "Invalid client name: '$client' (allow A-Z a-z 0-9 _ -, max 15 chars)"
	if grep -q "^# BEGIN_PEER ${client}$" "/etc/wireguard/${WG_IF}.conf"; then
		die "A client named '$client' already exists."
	fi
	new_client_dns
	new_client_setup
	wg addconf "$WG_IF" <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "/etc/wireguard/${WG_IF}.conf")
	echo "$client added. Configuration: $script_dir/$client.conf"
	command -v qrencode >/dev/null 2>&1 && qrencode -t ANSI256UTF8 < "$script_dir/$client.conf" || true
}

handle_remove_client() {
	if [[ ! -e "/etc/wireguard/${WG_IF}.conf" ]]; then
		die "WireGuard is not installed."
	fi
	local target="$_cli_client"
	[[ -z "$target" ]] && die "--remove-client requires a NAME"
	if ! grep -q "^# BEGIN_PEER ${target}$" "/etc/wireguard/${WG_IF}.conf"; then
		die "No client named '$target' found."
	fi
	backup_wg_conf
	local pub
	pub=$(sed -n "/^# BEGIN_PEER ${target}$/,\$p" "/etc/wireguard/${WG_IF}.conf" | grep -m 1 PublicKey | cut -d " " -f 3)
	wg set "$WG_IF" peer "$pub" remove || true
	sed -i "/^# BEGIN_PEER ${target}$/,/^# END_PEER ${target}$/d" "/etc/wireguard/${WG_IF}.conf"
	echo "$target removed."
}

# Dispatch standalone subcommands before falling into the interactive flow
case "$_action" in
	add-client)    handle_add_client; exit 0 ;;
	remove-client) handle_remove_client; exit 0 ;;
	uninstall)
		# Fall through to the existing-installation branch with option 3 selected
		option=3
		;;
esac

# ---------------------------------------------------------------------------
# First-run installer / management menu
# ---------------------------------------------------------------------------

if [[ ! -e "/etc/wireguard/${WG_IF}.conf" ]]; then
	_rollback_step="bootstrap"

	if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
		echo "Wget is required to use this installer."
		[[ "$WG_NON_INTERACTIVE" -eq 0 ]] && read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update || die "apt-get update failed"
		apt-get install -y wget || die "Failed to install wget"
	fi
	[[ "$WG_NON_INTERACTIVE" -eq 0 ]] && clear
	echo 'Welcome to this WireGuard road warrior installer!'

	# --- IPv4 selection ---
	mapfile -t ipv4_addrs < <(list_ipv4_addresses)
	if [[ "${#ipv4_addrs[@]}" -eq 0 ]]; then
		die "No non-loopback IPv4 address detected."
	fi

	if [[ -n "$WG_IPV4" ]]; then
		ip="$WG_IPV4"
	elif [[ "${#ipv4_addrs[@]}" -eq 1 ]]; then
		ip="${ipv4_addrs[0]}"
	elif [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
		ip="${ipv4_addrs[0]}"
		log "Multiple IPv4 addresses found; picked ${ip} for unattended run"
	else
		echo
		echo "Which IPv4 address should be used?"
		printf '%s\n' "${ipv4_addrs[@]}" | nl -s ') '
		read -rp "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || ( "$ip_number" =~ ^[0-9]+$ && "$ip_number" -ge 1 && "$ip_number" -le "${#ipv4_addrs[@]}" ) ]]; do
			echo "$ip_number: invalid selection."
			read -rp "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip="${ipv4_addrs[$((ip_number - 1))]}"
	fi

	# --- Public IP detection (NAT) ---
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		if [[ -n "$WG_PUBLIC_IP" ]]; then
			public_ip="$WG_PUBLIC_IP"
		else
			echo
			echo "This server is behind NAT. What is the public IPv4 address or hostname?"
			get_public_ip=$(detect_public_ipv4 || true)
			if [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
				public_ip="$get_public_ip"
				[[ -z "$public_ip" ]] && die "Could not auto-detect public IP and WG_PUBLIC_IP not set."
			else
				read -rp "Public IPv4 address / hostname [$get_public_ip]: " public_ip
				until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
					echo "Invalid input."
					read -rp "Public IPv4 address / hostname: " public_ip
				done
				[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
			fi
		fi
	fi

	# --- IPv6 selection ---
	mapfile -t ipv6_addrs < <(list_ipv6_global_addresses)
	ip6=""
	if [[ "${WG_IPV6,,}" == "disable" || "${WG_IPV6,,}" == "no" ]]; then
		ip6=""
	elif [[ -n "$WG_IPV6" && "${WG_IPV6,,}" != "auto" ]]; then
		ip6="$WG_IPV6"
	elif [[ "${#ipv6_addrs[@]}" -eq 1 ]]; then
		ip6="${ipv6_addrs[0]}"
	elif [[ "${#ipv6_addrs[@]}" -gt 1 ]]; then
		if [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
			ip6="${ipv6_addrs[0]}"
			log "Multiple IPv6 addresses found; picked ${ip6} for unattended run"
		else
			echo
			echo "Which IPv6 address should be used?"
			printf '%s\n' "${ipv6_addrs[@]}" | nl -s ') '
			read -rp "IPv6 address [1]: " ip6_number
			until [[ -z "$ip6_number" || ( "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -ge 1 && "$ip6_number" -le "${#ipv6_addrs[@]}" ) ]]; do
				echo "$ip6_number: invalid selection."
				read -rp "IPv6 address [1]: " ip6_number
			done
			[[ -z "$ip6_number" ]] && ip6_number="1"
			ip6="${ipv6_addrs[$((ip6_number - 1))]}"
		fi
	fi

	# --- Port ---
	if [[ -n "$WG_PORT" ]]; then
		port="$WG_PORT"
		is_valid_port "$port" || die "Invalid WG_PORT: $port"
	elif [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
		port="51820"
	else
		echo
		echo "What port should WireGuard listen on?"
		read -rp "Port [51820]: " port
		until [[ -z "$port" || ( "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ) ]]; do
			echo "$port: invalid port."
			read -rp "Port [51820]: " port
		done
		[[ -z "$port" ]] && port="51820"
	fi

	# --- Client name ---
	if [[ -n "$WG_CLIENT_NAME" ]]; then
		client="$WG_CLIENT_NAME"
		is_valid_client_name "$client" || die "Invalid WG_CLIENT_NAME: $client"
	elif [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
		client="client"
	else
		echo
		echo "Enter a name for the first client:"
		read -rp "Name [client]: " unsanitized_client
		client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
		[[ -z "$client" ]] && client="client"
	fi
	echo
	new_client_dns

	# --- BoringTun auto-update preference ---
	cron=""
	boringtun_updates=""
	if [[ "$use_boringtun" -eq 1 ]]; then
		if [[ -n "$WG_BORINGTUN_AUTOUPDATE" ]]; then
			boringtun_updates="$WG_BORINGTUN_AUTOUPDATE"
		elif [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
			boringtun_updates="y"
		else
			echo
			echo "BoringTun will be installed to set up WireGuard on the system."
			read -rp "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
			until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
				echo "$boringtun_updates: invalid selection."
				read -rp "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
			done
			[[ -z "$boringtun_updates" ]] && boringtun_updates="y"
		fi
		if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
			case "$os" in
				centos|fedora) cron="cronie" ;;
				debian|ubuntu) cron="cron" ;;
				arch)          cron="cronie" ;;
			esac
		fi
	fi
	echo
	echo "WireGuard installation is ready to begin."
	firewall=""
	if ! systemctl is-active --quiet firewalld.service && ! command -v iptables >/dev/null 2>&1; then
		case "$os" in
			centos|fedora|arch)
				firewall="firewalld"
				echo "firewalld, which is required to manage routing tables, will also be installed."
				;;
			debian|ubuntu)
				firewall="iptables"
				;;
		esac
	fi
	[[ "$WG_NON_INTERACTIVE" -eq 0 ]] && read -n1 -r -p "Press any key to continue..."

	_rollback_step="package-install"

	# --- Install packages ---
	case "$os" in
		ubuntu|debian)
			apt-get update || die "apt-get update failed"
			if [[ "$use_boringtun" -eq 0 ]]; then
				apt-get install -y wireguard qrencode $firewall || die "Failed to install WireGuard"
			else
				apt-get install -y qrencode ca-certificates $cron $firewall || die "Failed to install dependencies"
				apt-get install -y wireguard-tools --no-install-recommends || die "Failed to install wireguard-tools"
			fi
			;;
		centos)
			dnf install -y epel-release || die "Failed to install epel-release"
			if [[ "$use_boringtun" -eq 0 ]]; then
				dnf install -y wireguard-tools qrencode $firewall || die "Failed to install WireGuard"
			else
				dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall || die "Failed to install dependencies"
			fi
			;;
		fedora)
			if [[ "$use_boringtun" -eq 0 ]]; then
				dnf install -y wireguard-tools qrencode $firewall || die "Failed to install WireGuard"
			else
				dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall || die "Failed to install dependencies"
			fi
			mkdir -p /etc/wireguard/
			;;
		arch)
			pacman -Sy --noconfirm --needed wireguard-tools qrencode ca-certificates ${cron:+$cron} ${firewall:+$firewall} \
				|| die "pacman install failed"
			mkdir -p /etc/wireguard/
			;;
	esac

	_rollback_step="boringtun-install"

	if [[ "$use_boringtun" -eq 1 ]]; then
		local_tmp=$(mktemp -d)
		register_rollback_path "$local_tmp"
		if ! secure_download "https://wg.nyr.be/1/latest/download" \
			| tar xz -C "$local_tmp" --wildcards 'boringtun-*/boringtun' --strip-components 1; then
			rm -rf "$local_tmp"
			die "Failed to download BoringTun binary."
		fi
		if ! verify_elf_binary "$local_tmp/boringtun"; then
			rm -rf "$local_tmp"
			die "BoringTun binary failed integrity checks (ELF magic / size)."
		fi
		install -m 0755 "$local_tmp/boringtun" /usr/local/sbin/boringtun || die "Failed to install BoringTun"
		rm -rf "$local_tmp"
		register_rollback_path /usr/local/sbin/boringtun

		mkdir -p /etc/systemd/system/wg-quick@"${WG_IF}".service.d/ || die "Failed to create wg-quick override dir"
		register_rollback_path "/etc/systemd/system/wg-quick@${WG_IF}.service.d/boringtun.conf"
		cat << 'EOF' > /etc/systemd/system/wg-quick@"${WG_IF}".service.d/boringtun.conf
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1
EOF
		if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" || "$os" == "arch" ]]; then
			systemctl enable --now crond.service 2>/dev/null \
				|| systemctl enable --now cronie.service 2>/dev/null \
				|| die "Failed to enable cron service"
		fi
	fi
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service || die "Failed to enable firewalld.service"
		register_rollback_service "firewalld.service"
	fi

	_rollback_step="wg-config"

	register_rollback_path "/etc/wireguard/${WG_IF}.conf"
	register_rollback_path "/etc/sysctl.d/99-wireguard-forward.conf"

	# Derive subnet first 3 octets for generating wg0.conf
	v4_prefix=$(echo "$WG_SUBNET_V4" | cut -d/ -f1 | awk -F. '{print $1"."$2"."$3}')

	umask 077
	cat << EOF > "/etc/wireguard/${WG_IF}.conf"
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "${public_ip:-}" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = ${WG_GATEWAY_V4}/24$([[ -n "$ip6" ]] && echo ", ${ula_prefix}::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 "/etc/wireguard/${WG_IF}.conf"
	umask 022

	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi

	_rollback_step="firewall-rules"

	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd --add-port="$port"/udp
		firewall-cmd --zone=trusted --add-source="$WG_SUBNET_V4"
		firewall-cmd --permanent --add-port="$port"/udp
		firewall-cmd --permanent --zone=trusted --add-source="$WG_SUBNET_V4"
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s "$WG_SUBNET_V4" ! -d "$WG_SUBNET_V4" -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "$WG_SUBNET_V4" ! -d "$WG_SUBNET_V4" -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source="${ula_prefix}::/64"
			firewall-cmd --permanent --zone=trusted --add-source="${ula_prefix}::/64"
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
		fi
	else
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && command -v iptables-legacy >/dev/null 2>&1; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		register_rollback_path "/etc/systemd/system/wg-iptables.service"
		register_rollback_service "wg-iptables.service"
		{
			echo "[Unit]"
			echo "After=network-online.target"
			echo "Wants=network-online.target"
			echo "[Service]"
			echo "Type=oneshot"
			echo "ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s $WG_SUBNET_V4 ! -d $WG_SUBNET_V4 -j SNAT --to $ip"
			echo "ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT"
			echo "ExecStart=$iptables_path -w 5 -I FORWARD -s $WG_SUBNET_V4 -j ACCEPT"
			echo "ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
			echo "ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s $WG_SUBNET_V4 ! -d $WG_SUBNET_V4 -j SNAT --to $ip"
			echo "ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT"
			echo "ExecStop=$iptables_path -w 5 -D FORWARD -s $WG_SUBNET_V4 -j ACCEPT"
			echo "ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
			if [[ -n "$ip6" ]]; then
				echo "ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s ${ula_prefix}::/64 ! -d ${ula_prefix}::/64 -j SNAT --to $ip6"
				echo "ExecStart=$ip6tables_path -w 5 -I FORWARD -s ${ula_prefix}::/64 -j ACCEPT"
				echo "ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
				echo "ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s ${ula_prefix}::/64 ! -d ${ula_prefix}::/64 -j SNAT --to $ip6"
				echo "ExecStop=$ip6tables_path -w 5 -D FORWARD -s ${ula_prefix}::/64 -j ACCEPT"
				echo "ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
			fi
			echo "RemainAfterExit=yes"
			echo "[Install]"
			echo "WantedBy=multi-user.target"
		} > /etc/systemd/system/wg-iptables.service
		systemctl enable --now wg-iptables.service || die "Failed to enable wg-iptables.service"
	fi

	_rollback_step="client-config"

	new_client_setup
	register_rollback_service "wg-quick@${WG_IF}.service"
	systemctl enable --now wg-quick@"${WG_IF}".service || die "Failed to enable wg-quick@${WG_IF}.service"

	if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
		register_rollback_path /usr/local/sbin/boringtun-upgrade
		cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
set -uo pipefail

fetch() {
	local url="$1"
	if command -v curl >/dev/null 2>&1; then
		curl --proto '=https' --tlsv1.2 --retry 3 --retry-delay 2 \
			--connect-timeout 10 --max-time 60 -fsSL "$url"
	else
		wget --secure-protocol=TLSv1_2 --tries=3 --waitretry=2 \
			--timeout=60 -qO- "$url"
	fi
}

verify_elf() {
	local path="$1"
	local size magic
	size=$(stat -c %s "$path" 2>/dev/null || stat -f %z "$path" 2>/dev/null || echo 0)
	(( size >= 131072 && size <= 52428800 )) || { echo "size out of range: $size" >&2; return 1; }
	magic=$(head -c 4 "$path" | od -An -tx1 | tr -d ' \n')
	[[ "$magic" == "7f454c46" ]] || { echo "bad ELF magic: $magic" >&2; return 1; }
}

latest=$(fetch "https://wg.nyr.be/1/latest" 2>/dev/null || true)
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable" >&2
	exit 1
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	xdir=$(mktemp -d)
	trap 'rm -rf "$xdir"' EXIT
	if fetch "https://wg.nyr.be/1/latest/download" \
		| tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1 \
		&& verify_elf "$xdir/boringtun"; then
		WG_IF_NAME="$(ls -1 /etc/wireguard/ 2>/dev/null | head -1 | sed 's/\.conf$//')"
		WG_IF_NAME="${WG_IF_NAME:-wg0}"
		systemctl stop wg-quick@"${WG_IF_NAME}".service
		rm -f /usr/local/sbin/boringtun
		mv "$xdir"/boringtun /usr/local/sbin/boringtun
		systemctl start wg-quick@"${WG_IF_NAME}".service
		echo "Successfully updated to $(/usr/local/sbin/boringtun -V)"
	else
		echo "boringtun update failed" >&2
		exit 1
	fi
else
	echo "$current is up to date"
fi
EOF
		chmod +x /usr/local/sbin/boringtun-upgrade
		install_boringtun_updater
	fi

	_rollback_step="complete"
	log "Install complete for client=$client on if=$WG_IF subnet=$WG_SUBNET_V4"

	echo
	command -v qrencode >/dev/null 2>&1 && qrencode -t ANSI256UTF8 < "$script_dir/$client.conf" || true
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in: $script_dir/$client.conf"
	echo "New clients can be added by running this script again."
else
	# -----------------------------------------------------------------------
	# Existing-installation management menu
	# -----------------------------------------------------------------------

	[[ "$WG_NON_INTERACTIVE" -eq 0 ]] && clear
	echo "WireGuard is already installed."

	if [[ "$WG_NON_INTERACTIVE" -eq 0 && -z "${option:-}" ]]; then
		echo
		echo "Select an option:"
		echo "   1) Add a new client"
		echo "   2) Remove an existing client"
		echo "   3) Remove WireGuard"
		echo "   4) Exit"
		read -rp "Option: " option
		until [[ "$option" =~ ^[1-4]$ ]]; do
			echo "$option: invalid selection."
			read -rp "Option: " option
		done
	fi

	case "${option:-4}" in
		1)
			echo
			echo "Provide a name for the client:"
			read -rp "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" "/etc/wireguard/${WG_IF}.conf"; do
				echo "$client: invalid name."
				read -rp "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			done
			echo
			new_client_dns
			new_client_setup
			wg addconf "$WG_IF" <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" "/etc/wireguard/${WG_IF}.conf")
			echo
			command -v qrencode >/dev/null 2>&1 && qrencode -t ANSI256UTF8 < "$script_dir/$client.conf" || true
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "$client added. Configuration available in: $script_dir/$client.conf"
			exit 0
		;;
		2)
			number_of_clients=$(grep -c '^# BEGIN_PEER' "/etc/wireguard/${WG_IF}.conf")
			if [[ "$number_of_clients" -eq 0 ]]; then
				echo
				die "There are no existing clients!"
			fi
			echo
			echo "Select the client to remove:"
			grep '^# BEGIN_PEER' "/etc/wireguard/${WG_IF}.conf" | cut -d ' ' -f 3 | nl -s ') '
			read -rp "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -ge 1 && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -rp "Client: " client_number
			done
			client=$(grep '^# BEGIN_PEER' "/etc/wireguard/${WG_IF}.conf" | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -rp "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -rp "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				backup_wg_conf
				wg set "$WG_IF" peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" "/etc/wireguard/${WG_IF}.conf" | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" "/etc/wireguard/${WG_IF}.conf"
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit 0
		;;
		3)
			remove=""
			if [[ "$WG_NON_INTERACTIVE" -eq 1 ]]; then
				remove="y"
			else
				echo
				read -rp "Confirm WireGuard removal? [y/N]: " remove
				until [[ "$remove" =~ ^[yYnN]*$ ]]; do
					echo "$remove: invalid selection."
					read -rp "Confirm WireGuard removal? [y/N]: " remove
				done
			fi
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^ListenPort' "/etc/wireguard/${WG_IF}.conf" | cut -d " " -f 3)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep -- "-s $WG_SUBNET_V4" | grep -oE '[^ ]+$')
					firewall-cmd --remove-port="$port"/udp
					firewall-cmd --zone=trusted --remove-source="$WG_SUBNET_V4"
					firewall-cmd --permanent --remove-port="$port"/udp
					firewall-cmd --permanent --zone=trusted --remove-source="$WG_SUBNET_V4"
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$WG_SUBNET_V4" ! -d "$WG_SUBNET_V4" -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s "$WG_SUBNET_V4" ! -d "$WG_SUBNET_V4" -j SNAT --to "$ip"
					if grep -qs "${ula_prefix}::1/64" "/etc/wireguard/${WG_IF}.conf"; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep -- "-s ${ula_prefix}::/64" | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source="${ula_prefix}::/64"
						firewall-cmd --permanent --zone=trusted --remove-source="${ula_prefix}::/64"
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now wg-iptables.service 2>/dev/null || true
					rm -f /etc/systemd/system/wg-iptables.service
				fi
				systemctl disable --now wg-quick@"${WG_IF}".service 2>/dev/null || true
				rm -f /etc/systemd/system/wg-quick@"${WG_IF}".service.d/boringtun.conf
				rm -f /etc/sysctl.d/99-wireguard-forward.conf

				if [[ "$use_boringtun" -eq 0 ]]; then
					case "$os" in
						ubuntu|debian)
							rm -rf /etc/wireguard/
							apt-get remove --purge -y wireguard wireguard-tools
							;;
						centos|fedora)
							dnf remove -y wireguard-tools
							rm -rf /etc/wireguard/
							;;
						arch)
							pacman -Rns --noconfirm wireguard-tools
							rm -rf /etc/wireguard/
							;;
					esac
				else
					remove_boringtun_updater
					case "$os" in
						ubuntu|debian)
							rm -rf /etc/wireguard/
							apt-get remove --purge -y wireguard-tools
							;;
						centos|fedora)
							dnf remove -y wireguard-tools
							rm -rf /etc/wireguard/
							;;
						arch)
							pacman -Rns --noconfirm wireguard-tools
							rm -rf /etc/wireguard/
							;;
					esac
					rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
				fi
				echo
				echo "WireGuard removed!"
			else
				echo
				echo "WireGuard removal aborted!"
			fi
			exit 0
		;;
		4)
			exit 0
		;;
	esac
fi
