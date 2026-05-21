#!/bin/bash
#
# Hardened fork of https://github.com/Nyr/wireguard-install
#
# Original Copyright (c) 2020 Nyr. Released under the MIT License.
#
# This version adds: strict-mode error handling, input validation,
# randomized IPv6 ULA prefix, TLS-hardened downloads with retries,
# public-IP service fallbacks, concurrent-run lockfile, automatic
# backups of /etc/wireguard/wg0.conf, and consolidated distro branches.
#

set -uo pipefail

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".' >&2
	exit 1
fi

# ---------------------------------------------------------------------------
# Error handling, locking, and validation helpers
# ---------------------------------------------------------------------------

die() {
	echo "ERROR: $*" >&2
	exit 1
}

_lock_fd=""

cleanup_on_exit() {
	local rc=$?
	if [[ -n "$_lock_fd" ]]; then
		eval "exec ${_lock_fd}>&-" 2>/dev/null || true
	fi
	exit "$rc"
}
trap cleanup_on_exit EXIT
trap 'die "Interrupted."' INT TERM

# Prevent concurrent installer runs from racing on /etc/wireguard/wg0.conf
acquire_lock() {
	local lockfile="/var/lock/wireguard-install.lock"
	exec {_lock_fd}>"$lockfile" || die "Cannot create lockfile at $lockfile"
	if ! flock -n "$_lock_fd"; then
		die "Another wireguard-install process is already running."
	fi
}

# Strict IPv4 octet validation (each octet must be 0-255)
is_valid_ipv4() {
	local ip="$1" oct
	[[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
	for oct in "${BASH_REMATCH[@]:1:4}"; do
		(( oct <= 255 )) || return 1
	done
	return 0
}

# RFC 4193 ULA /64 prefix: fd + 40 random bits, formatted as fdXX:XXXX:XXXX:XXXX
gen_random_ula_prefix() {
	local r
	r=$(od -An -N5 -tx1 /dev/urandom | tr -d ' \n')
	printf 'fd%s:%s%s:%s%s' \
		"${r:0:2}" "${r:2:2}" "${r:4:2}" "${r:6:2}" "${r:8:2}"
}

# Read the existing ULA prefix from wg0.conf, or generate a new random one.
# Keeps backward compatibility with previous installs that used the fixed
# fddd:2c4:2c4:2c4:: prefix.
detect_or_generate_ula_prefix() {
	local existing
	if [[ -f /etc/wireguard/wg0.conf ]]; then
		existing=$(grep -oE 'fd[0-9a-f]{2}(:[0-9a-f]{1,4}){3}' /etc/wireguard/wg0.conf | head -1)
		if [[ -n "$existing" ]]; then
			echo "$existing"
			return 0
		fi
	fi
	gen_random_ula_prefix
}

# Snapshot wg0.conf before mutation so a partial failure is recoverable
backup_wg_conf() {
	local f="/etc/wireguard/wg0.conf"
	[[ -f "$f" ]] || return 0
	cp -a "$f" "${f}.bak.$(date +%s)" || die "Failed to back up $f"
}

# HTTPS-only download with TLS 1.2 minimum, retries, and bounded timeout
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

# Try several public-IP services in order; return the first valid IPv4
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

# Enumerate non-loopback IPv4 addresses (cached: callers use mapfile once)
list_ipv4_addresses() {
	ip -4 -o addr show 2>/dev/null | awk '
		$3 == "inet" {
			split($4, a, "/")
			if (a[1] !~ /^127\./) print a[1]
		}'
}

# Enumerate global-scope IPv6 addresses
list_ipv6_global_addresses() {
	ip -6 -o addr show scope global 2>/dev/null | awk '
		$3 == "inet6" {
			split($4, a, "/"); print a[1]
		}'
}

# Discard stdin. Needed when running from a one-liner which includes a newline
read -N 999999 -t 0.001 || true

# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

# $os_version variables aren't always in use, but are kept here for convenience
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
else
	die "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	die "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
fi

if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		die "Debian Testing and Debian Unstable are unsupported by this installer."
	fi
	if [[ "$os_version" -lt 11 ]]; then
		die "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
	fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
	os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
	die "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	die '$PATH does not include sbin. Try using "su -" instead of "su".'
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
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
		die "In containerized systems without the wireguard kernel module, this installer
supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
	fi
	# TUN device is required to use BoringTun
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		die "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
	fi
fi

# Acquire installer lock after privilege check so unauthorized users don't
# create stray lockfiles
acquire_lock

# Store the absolute path of the directory where the script is located
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Resolve the IPv6 ULA prefix used for the VPN's internal network. For an
# existing installation we read it back from wg0.conf so we don't break peers;
# for a fresh install we generate a random RFC 4193 prefix.
ula_prefix=$(detect_or_generate_ula_prefix)

# ---------------------------------------------------------------------------
# Client DNS picker
# ---------------------------------------------------------------------------

new_client_dns () {
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
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			# Extract nameservers and validate each octet (0-255)
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
				# Validate each candidate with strict octet range checking
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

# ---------------------------------------------------------------------------
# Per-client config generation
# ---------------------------------------------------------------------------

new_client_setup () {
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	local octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "^$octet$"; do
		(( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
		die "253 clients are already configured. The WireGuard internal subnet is full!"
	fi

	# Cache the IPv6-enabled flag so we don't re-grep for every line
	local has_ipv6=0
	if grep -q "${ula_prefix}::1" /etc/wireguard/wg0.conf; then
		has_ipv6=1
	fi

	local key psk pubkey server_pubkey endpoint listen_port
	key=$(wg genkey)
	psk=$(wg genpsk)
	pubkey=$(wg pubkey <<< "$key")
	server_pubkey=$(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
	endpoint=$(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3)
	listen_port=$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)

	backup_wg_conf

	# Configure client in the server
	{
		echo "# BEGIN_PEER $client"
		echo "[Peer]"
		echo "PublicKey = $pubkey"
		echo "PresharedKey = $psk"
		if [[ "$has_ipv6" -eq 1 ]]; then
			echo "AllowedIPs = 10.7.0.$octet/32, ${ula_prefix}::$octet/128"
		else
			echo "AllowedIPs = 10.7.0.$octet/32"
		fi
		echo "# END_PEER $client"
	} >> /etc/wireguard/wg0.conf

	# Create client configuration with restrictive perms before writing secrets
	local client_addr="10.7.0.$octet/24"
	if [[ "$has_ipv6" -eq 1 ]]; then
		client_addr="${client_addr}, ${ula_prefix}::$octet/64"
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

# ---------------------------------------------------------------------------
# First-run installer
# ---------------------------------------------------------------------------

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	# Detect some Debian minimal setups where neither wget nor curl are installed
	if ! command -v wget >/dev/null 2>&1 && ! command -v curl >/dev/null 2>&1; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update || die "apt-get update failed"
		apt-get install -y wget || die "Failed to install wget"
	fi
	clear
	echo 'Welcome to this WireGuard road warrior installer!'

	# Cache the IPv4 list once and reuse it
	mapfile -t ipv4_addrs < <(list_ipv4_addresses)
	if [[ "${#ipv4_addrs[@]}" -eq 0 ]]; then
		die "No non-loopback IPv4 address detected."
	elif [[ "${#ipv4_addrs[@]}" -eq 1 ]]; then
		ip="${ipv4_addrs[0]}"
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

	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Probe several IP-detection services for resilience
		get_public_ip=$(detect_public_ipv4 || true)
		read -rp "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -rp "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi

	# Cache the global IPv6 list
	mapfile -t ipv6_addrs < <(list_ipv6_global_addresses)
	ip6=""
	if [[ "${#ipv6_addrs[@]}" -eq 1 ]]; then
		ip6="${ipv6_addrs[0]}"
	elif [[ "${#ipv6_addrs[@]}" -gt 1 ]]; then
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

	echo
	echo "What port should WireGuard listen on?"
	read -rp "Port [51820]: " port
	until [[ -z "$port" || ( "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ) ]]; do
		echo "$port: invalid port."
		read -rp "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	echo "Enter a name for the first client:"
	read -rp "Name [client]: " unsanitized_client
	# Allow a limited length and set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
	[[ -z "$client" ]] && client="client"
	echo
	new_client_dns
	# Set up automatic updates for BoringTun if the user is fine with that
	cron=""
	boringtun_updates=""
	if [[ "$use_boringtun" -eq 1 ]]; then
		echo
		echo "BoringTun will be installed to set up WireGuard on the system."
		read -rp "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
			echo "$boringtun_updates: invalid selection."
			read -rp "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		done
		[[ -z "$boringtun_updates" ]] && boringtun_updates="y"
		if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
			case "$os" in
				centos|fedora) cron="cronie" ;;
				debian|ubuntu) cron="cron" ;;
			esac
		fi
	fi
	echo
	echo "WireGuard installation is ready to begin."
	# Install a firewall if firewalld or iptables are not already available
	firewall=""
	if ! systemctl is-active --quiet firewalld.service && ! command -v iptables >/dev/null 2>&1; then
		case "$os" in
			centos|fedora)
				firewall="firewalld"
				# We don't want to silently enable firewalld, so we give a subtle warning
				echo "firewalld, which is required to manage routing tables, will also be installed."
				;;
			debian|ubuntu)
				firewall="iptables"
				;;
		esac
	fi
	read -n1 -r -p "Press any key to continue..."
	# Install WireGuard (consolidated distro branches)
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
	esac

	# BoringTun setup (userspace WireGuard for containers without kernel module)
	if [[ "$use_boringtun" -eq 1 ]]; then
		# Grab the BoringTun binary over hardened HTTPS and extract into the right place.
		# Don't use this service elsewhere without permission! Contact upstream maintainer first.
		# NOTE: upstream does not currently publish signed releases or detached checksums,
		# so we mitigate MITM risk by pinning TLS 1.2+ and using retries with bounded timeouts.
		if ! secure_download "https://wg.nyr.be/1/latest/download" \
			| tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1; then
			die "Failed to download BoringTun binary."
		fi
		# Configure wg-quick to use BoringTun
		mkdir -p /etc/systemd/system/wg-quick@wg0.service.d/ || die "Failed to create wg-quick override dir"
		cat << 'EOF' > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1
EOF
		if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			systemctl enable --now crond.service || die "Failed to enable crond.service"
		fi
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service || die "Failed to enable firewalld.service"
	fi

	# Generate wg0.conf with hardened permissions before writing secret material
	umask 077
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "${public_ip:-}" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", ${ula_prefix}::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	umask 022

	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi

	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld reload
		firewall-cmd --add-port="$port"/udp
		firewall-cmd --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd --permanent --add-port="$port"/udp
		firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source="${ula_prefix}::/64"
			firewall-cmd --permanent --zone=trusted --add-source="${ula_prefix}::/64"
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		# nf_tables is not available as standard in OVZ kernels. Fall back to
		# iptables-legacy if we are in OVZ with a nf_tables backend.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && command -v iptables-legacy >/dev/null 2>&1; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		{
			echo "[Unit]"
			echo "After=network-online.target"
			echo "Wants=network-online.target"
			echo "[Service]"
			echo "Type=oneshot"
			echo "ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip"
			echo "ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT"
			echo "ExecStart=$iptables_path -w 5 -I FORWARD -s 10.7.0.0/24 -j ACCEPT"
			echo "ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT"
			echo "ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip"
			echo "ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT"
			echo "ExecStop=$iptables_path -w 5 -D FORWARD -s 10.7.0.0/24 -j ACCEPT"
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
	# Generates the custom client.conf
	new_client_setup
	# Enable and start the wg-quick service
	systemctl enable --now wg-quick@wg0.service || die "Failed to enable wg-quick@wg0.service"

	# Set up automatic updates for BoringTun if the user wanted to
	if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
		# Deploy upgrade script with the same hardened-download behavior
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

latest=$(fetch "https://wg.nyr.be/1/latest" 2>/dev/null || true)
# If server did not provide an appropriate response, exit
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable" >&2
	exit 1
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	xdir=$(mktemp -d)
	trap 'rm -rf "$xdir"' EXIT
	if fetch "https://wg.nyr.be/1/latest/download" \
		| tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
		systemctl stop wg-quick@wg0.service
		rm -f /usr/local/sbin/boringtun
		mv "$xdir"/boringtun /usr/local/sbin/boringtun
		systemctl start wg-quick@wg0.service
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
		# Add cron job to run the updater daily at a random time between 3:00 and 5:59
		{ crontab -l 2>/dev/null; echo "$(( RANDOM % 60 )) $(( RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
	fi
	echo
	qrencode -t ANSI256UTF8 < "$script_dir"/"$client.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" "$script_dir"/"$client.conf"
	echo "New clients can be added by running this script again."
else
	# -----------------------------------------------------------------------
	# Existing-installation management menu
	# -----------------------------------------------------------------------

	clear
	echo "WireGuard is already installed."
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
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -rp "Name: " unsanitized_client
			# Allow a limited length and set of characters to avoid conflicts
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -rp "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			done
			echo
			new_client_dns
			new_client_setup
			# Append new client configuration to the WireGuard interface
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo
			qrencode -t ANSI256UTF8 < "$script_dir"/"$client.conf"
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "$client added. Configuration available in:" "$script_dir"/"$client.conf"
			exit 0
		;;
		2)
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" -eq 0 ]]; then
				echo
				die "There are no existing clients!"
			fi
			echo
			echo "Select the client to remove:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -rp "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -ge 1 && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -rp "Client: " client_number
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -rp "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -rp "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				backup_wg_conf
				# Remove from the live interface so existing connections aren't disrupted
				wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				# Remove from the configuration file
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit 0
		;;
		3)
			echo
			read -rp "Confirm WireGuard removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -rp "Confirm WireGuard removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload
					firewall-cmd --remove-port="$port"/udp
					firewall-cmd --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --permanent --remove-port="$port"/udp
					firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
					if grep -qs "${ula_prefix}::1/64" /etc/wireguard/wg0.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep -- "-s ${ula_prefix}::/64" | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source="${ula_prefix}::/64"
						firewall-cmd --permanent --zone=trusted --remove-source="${ula_prefix}::/64"
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s "${ula_prefix}::/64" ! -d "${ula_prefix}::/64" -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now wg-iptables.service
					rm -f /etc/systemd/system/wg-iptables.service
				fi
				systemctl disable --now wg-quick@wg0.service
				rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
				rm -f /etc/sysctl.d/99-wireguard-forward.conf
				# Different stuff was installed depending on whether BoringTun was used or not
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
					esac
				else
					{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
					case "$os" in
						ubuntu|debian)
							rm -rf /etc/wireguard/
							apt-get remove --purge -y wireguard-tools
							;;
						centos|fedora)
							dnf remove -y wireguard-tools
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
