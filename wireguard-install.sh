#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2020 Nyr. Released under the MIT License.
#
# Extended features:
#   Client management  : status/list, show QR code, rename, disable/enable
#   Network/routing    : change subnet, change endpoint, split-tunnel toggle, change DNS, change keepalive
#   Security           : rotate client keys, rotate server key


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from a one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
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
	echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
	echo "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
	exit
fi

if [[ "$os" == "debian" ]]; then
	if grep -q '/sid' /etc/debian_version; then
		echo "Debian Testing and Debian Unstable are unsupported by this installer."
		exit
	fi
	if [[ "$os_version" -lt 11 ]]; then
		echo "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
		exit
	fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
	os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
	echo "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
	exit
fi

if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
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
	echo "This installer needs to be run with superuser privileges."
	exit
fi

if [[ "$use_boringtun" -eq 1 ]]; then
	if [ "$(uname -m)" != "x86_64" ]; then
		echo "In containerized systems without the wireguard kernel module, this installer
supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
		exit
	fi
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
		exit
	fi
fi

# Store the absolute path of the directory where the script is located
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# ==============================================================================
# CORE FUNCTIONS
# ==============================================================================

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
	read -p "DNS server [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-8]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS server [1]: " dns
	done
	case "$dns" in
		1|"")
			if grep '^nameserver' "/etc/resolv.conf" | grep -qv '127.0.0.53' ; then
				resolv_conf="/etc/resolv.conf"
			else
				resolv_conf="/run/systemd/resolve/resolv.conf"
			fi
			dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
		;;
		2) dns="8.8.8.8, 8.8.4.4" ;;
		3) dns="1.1.1.1, 1.0.0.1" ;;
		4) dns="208.67.222.222, 208.67.220.220" ;;
		5) dns="9.9.9.9, 149.112.112.112" ;;
		6) dns="95.85.95.85, 2.56.220.2" ;;
		7) dns="94.140.14.14, 94.140.15.15" ;;
		8)
			echo
			until [[ -n "$custom_dns" ]]; do
				echo "Enter DNS servers (one or more IPv4 addresses, separated by commas or spaces):"
				read -p "DNS servers: " dns_input
				dns_input=$(echo "$dns_input" | tr ',' ' ')
				for dns_ip in $dns_input; do
					if [[ "$dns_ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
						if [[ -z "$custom_dns" ]]; then
							custom_dns="$dns_ip"
						else
							custom_dns="$custom_dns, $dns_ip"
						fi
					fi
				done
				if [ -z "$custom_dns" ]; then
					echo "Invalid input."
				else
					dns="$custom_dns"
				fi
			done
		;;
	esac
}

new_client_setup () {
	# Read server address info from wg0.conf
	local vpn_server_ip
	vpn_server_ip=$(grep '^Address' /etc/wireguard/wg0.conf | head -1 | cut -d '=' -f 2 | tr -d ' ' | cut -d ',' -f 1 | cut -d '/' -f 1)
	local vpn_cidr
	vpn_cidr=$(grep '^Address' /etc/wireguard/wg0.conf | head -1 | cut -d '=' -f 2 | tr -d ' ' | cut -d ',' -f 1 | grep -oE '/[0-9]+$')
	# Base for auto-increment (first 3 octets of server IP)
	local vpn_base
	vpn_base=$(echo "$vpn_server_ip" | sed 's/\.[0-9]*$//')

	# Find next available IP (simple auto-increment on last octet of base)
	local next_octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -q "^${vpn_base}\.${next_octet}$"; do
		(( next_octet++ ))
	done
	local next_ip="${vpn_base}.${next_octet}"

	echo
	echo "Client IP address (must be within the VPN network${vpn_cidr})"
	echo "Example: ${vpn_base}.10 or 10.0.1.5 for a /8"
	echo "Next available (auto): ${next_ip}"
	read -p "IP [${next_ip}]: " chosen_ip
	[[ -z "$chosen_ip" ]] && chosen_ip="$next_ip"

	# Validate IP format
	until [[ "$chosen_ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
		echo "Invalid IP format. Enter a full IPv4 address (e.g. 10.0.1.5)"
		read -p "IP [${next_ip}]: " chosen_ip
		[[ -z "$chosen_ip" ]] && chosen_ip="$next_ip"
	done

	# Check not the server IP
	if [[ "$chosen_ip" == "$vpn_server_ip" ]]; then
		echo "Error: ${chosen_ip} is the server address."
		exit 1
	fi

	# Check not already taken
	if grep AllowedIPs /etc/wireguard/wg0.conf | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -q "^${chosen_ip}$"; then
		echo "Error: IP ${chosen_ip} is already in use."
		exit 1
	fi

	local client_ip="$chosen_ip"

	key=$(wg genkey)
	psk=$(wg genpsk)
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = ${client_ip}/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$(echo $client_ip | cut -d. -f4)/128")
# END_PEER $client
EOF
	cat << EOF > "$script_dir"/"$client".conf
[Interface]
Address = ${client_ip}${vpn_cidr}$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$(echo $client_ip | cut -d. -f4)/64")
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = $(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d " " -f 3):$(grep ListenPort /etc/wireguard/wg0.conf | cut -d " " -f 3)
PersistentKeepalive = 25
EOF
}

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

validate_cidr () {
	local input="$1"
	[[ "$input" == "0.0.0.0/0" || "$input" == "::/0" ]] && return 0
	[[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/([0-9]|[1-2][0-9]|3[0-2]))?$ ]] && return 0
	[[ "$input" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ && "$input" == *:* ]] && return 0
	return 1
}

restart_wg () {
	echo
	echo "Restarting WireGuard..."
	if systemctl restart wg-quick@wg0.service; then
		echo "WireGuard restarted successfully."
	else
		echo "ERROR: WireGuard failed to restart. Check: systemctl status wg-quick@wg0"
		exit 1
	fi
}

# Pick a client interactively — sets $client variable
pick_client () {
	local prompt="${1:-Client}"
	number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
	if [[ "$number_of_clients" -eq 0 ]]; then
		echo "No clients configured."
		exit 1
	fi
	grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
	read -p "${prompt}: " client_number
	until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -ge 1 && "$client_number" -le "$number_of_clients" ]]; do
		echo "$client_number: invalid selection."
		read -p "${prompt}: " client_number
	done
	client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "${client_number}p")
}

# Get the public key of a peer from wg0.conf
get_peer_pubkey () {
	local peer="$1"
	sed -n "/^# BEGIN_PEER ${peer}$/,/^# END_PEER ${peer}$/p" /etc/wireguard/wg0.conf \
		| grep '^PublicKey' | cut -d ' ' -f 3
}

# ==============================================================================
# INSTALLATION
# ==============================================================================

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		apt-get update
		apt-get install -y wget
	fi
	clear
	echo 'Welcome to this WireGuard road warrior installer!'
	if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')
		echo
		echo "Which IPv4 address should be used?"
		ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
	fi
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		until [[ -n "$get_public_ip" || -n "$public_ip" ]]; do
			echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "Which IPv6 address should be used?"
		ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '
		read -p "IPv6 address [1]: " ip6_number
		until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$number_of_ip6" ]]; do
			echo "$ip6_number: invalid selection."
			read -p "IPv6 address [1]: " ip6_number
		done
		[[ -z "$ip6_number" ]] && ip6_number="1"
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
	fi
	echo
	echo "What port should WireGuard listen on?"
	read -p "Port [51820]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	# ── VPN internal subnet ──────────────────────────────────────────────────
	echo "What VPN internal subnet should be used?"
	echo "The server will take the .1 address (e.g. 10.7.0.1/24)."
	read -p "VPN subnet [10.7.0.0/24]: " vpn_subnet_input
	[[ -z "$vpn_subnet_input" ]] && vpn_subnet_input="10.7.0.0/24"
	until [[ "$vpn_subnet_input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[1-2][0-9]|3[0-2])$ ]]; do
		echo "$vpn_subnet_input: invalid subnet. Use CIDR notation, e.g. 10.8.0.0/24"
		read -p "VPN subnet [10.7.0.0/24]: " vpn_subnet_input
		[[ -z "$vpn_subnet_input" ]] && vpn_subnet_input="10.7.0.0/24"
	done
	vpn_base=$(echo "$vpn_subnet_input" | sed 's/\.[0-9]*\/.*$//')
	vpn_cidr=$(echo "$vpn_subnet_input" | grep -oE '/[0-9]+$')
	vpn_server_addr="${vpn_base}.1${vpn_cidr}"
	vpn_network="${vpn_base}.0${vpn_cidr}"
	# ────────────────────────────────────────────────────────────────────────
	echo
	echo "Enter a name for the first client:"
	read -p "Name [client]: " unsanitized_client
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
	[[ -z "$client" ]] && client="client"
	echo
	new_client_dns
	if [[ "$use_boringtun" -eq 1 ]]; then
		echo
		echo "BoringTun will be installed to set up WireGuard on the system."
		read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		until [[ "$boringtun_updates" =~ ^[yYnN]*$ ]]; do
			echo "$remove: invalid selection."
			read -p "Should automatic updates be enabled for it? [Y/n]: " boringtun_updates
		done
		[[ -z "$boringtun_updates" ]] && boringtun_updates="y"
		if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
			if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
				cron="cronie"
			elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
				cron="cron"
			fi
		fi
	fi
	echo
	echo "WireGuard installation is ready to begin."
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	if [[ "$use_boringtun" -eq 0 ]]; then
		if [[ "$os" == "ubuntu" ]]; then
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "debian" ]]; then
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "centos" ]]; then
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode $firewall
		elif [[ "$os" == "fedora" ]]; then
			dnf install -y wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		fi
	else
		if [[ "$os" == "ubuntu" ]]; then
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "debian" ]]; then
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "centos" ]]; then
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
		elif [[ "$os" == "fedora" ]]; then
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		fi
		{ wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
		mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
		echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
		if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			systemctl enable --now crond.service
		fi
	fi
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = ${vpn_server_addr}$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		firewall-cmd --add-port="$port"/udp
		firewall-cmd --zone=trusted --add-source="${vpn_network}"
		firewall-cmd --permanent --add-port="$port"/udp
		firewall-cmd --permanent --zone=trusted --add-source="${vpn_network}"
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s "${vpn_network}" ! -d "${vpn_network}" -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "${vpn_network}" ! -d "${vpn_network}" -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
		fi
	else
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
		echo "[Unit]
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=$iptables_path -w 5 -t nat -A POSTROUTING -s ${vpn_network} ! -d ${vpn_network} -j SNAT --to $ip
ExecStart=$iptables_path -w 5 -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -s ${vpn_network} -j ACCEPT
ExecStart=$iptables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -w 5 -t nat -D POSTROUTING -s ${vpn_network} ! -d ${vpn_network} -j SNAT --to $ip
ExecStop=$iptables_path -w 5 -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -s ${vpn_network} -j ACCEPT
ExecStop=$iptables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -w 5 -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -w 5 -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -w 5 -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -w 5 -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -w 5 -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -w 5 -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		systemctl enable --now wg-iptables.service
	fi
	new_client_setup
	systemctl enable --now wg-quick@wg0.service
	if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
		cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.nyr.be/1/latest 2>/dev/null || curl -sL https://wg.nyr.be/1/latest 2>/dev/null)
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable"
	exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	download="https://wg.nyr.be/1/latest/download"
	xdir=$(mktemp -d)
	if { wget -qO- "$download" 2>/dev/null || curl -sL "$download" ; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
		systemctl stop wg-quick@wg0.service
		rm -f /usr/local/sbin/boringtun
		mv "$xdir"/boringtun /usr/local/sbin/boringtun
		systemctl start wg-quick@wg0.service
		echo "Successfully updated to $(/usr/local/sbin/boringtun -V)"
	else
		echo "boringtun update failed"
	fi
	rm -rf "$xdir"
else
	echo "$current is up to date"
fi
EOF
		chmod +x /usr/local/sbin/boringtun-upgrade
		{ crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
	fi
	echo
	qrencode -t ANSI256UTF8 < "$script_dir"/"$client.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" "$script_dir"/"$client.conf"
	echo "New clients can be added by running this script again."

# ==============================================================================
# MANAGEMENT MENU
# ==============================================================================
else
	clear
	echo "WireGuard is already installed."
	echo
	echo "Select an option:"
	echo "   ── Client management ──────────────────"
	echo "   1)  Add a new client"
	echo "   2)  Remove an existing client"
	echo "   3)  Show client status (connected peers)"
	echo "   4)  Show QR code of a client"
	echo "   5)  Rename a client"
	echo "   6)  Disable a client (temporary block)"
	echo "   7)  Enable a disabled client"
	echo "   ── Network / routing ──────────────────"
	echo "   8)  Add an allowed IP to a client"
	echo "   9)  Remove an allowed IP from a client"
	echo "   10) Toggle full-tunnel / split-tunnel for a client"
	echo "   11) Change client DNS"
	echo "   12) Change client PersistentKeepalive"
	echo "   13) Change VPN internal network (subnet)"
	echo "   14) Change endpoint (IP/hostname and/or port)"
	echo "   ── Security ───────────────────────────"
	echo "   15) Rotate keys of a client"
	echo "   16) Rotate server private key"
	echo "   ── Other ──────────────────────────────"
	echo "   17) Remove WireGuard"
	echo "   18) Exit"
	echo
	read -p "Option: " option
	until [[ "$option" =~ ^[0-9]+$ && "$option" -ge 1 && "$option" -le 18 ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in

		# ======================================================================
		# 1 — Add a new client
		# ======================================================================
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			done
			echo
			new_client_dns
			new_client_setup
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo
			qrencode -t ANSI256UTF8 < "$script_dir"/"$client.conf"
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "$client added. Configuration available in:" "$script_dir"/"$client.conf"
			exit
		;;

		# ======================================================================
		# 2 — Remove a client
		# ======================================================================
		2)
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to remove:"
			pick_client "Client"
			echo
			read -p "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				pubkey=$(get_peer_pubkey "$client")
				[[ -n "$pubkey" ]] && wg set wg0 peer "$pubkey" remove 2>/dev/null
				sed -i "/^# DISABLED_PEER $client$/d" /etc/wireguard/wg0.conf
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
				if [[ -f "$script_dir/${client}.conf" ]]; then
					rm -f "$script_dir/${client}.conf"
					echo "Config file deleted: $script_dir/${client}.conf"
				fi
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit
		;;

		# ======================================================================
		# 3 — Show client status
		# ======================================================================
		3)
			echo
			echo "=== Client status ==="
			echo
			printf "%-18s %-20s %-22s %-10s %-10s %s\n" \
				"CLIENT" "ENDPOINT" "LAST HANDSHAKE" "RX" "TX" "STATUS"
			printf "%-18s %-20s %-22s %-10s %-10s %s\n" \
				"──────────────────" "────────────────────" "──────────────────────" "──────────" "──────────" "──────────"
			declare -A seen_clients
			while IFS=$'\t' read -r pubkey _psk endpoint _allowed handshake rx tx _ka; do
				name=$(grep -B2 "PublicKey = $pubkey" /etc/wireguard/wg0.conf | grep '# BEGIN_PEER' | awk '{print $3}')
				[[ -z "$name" ]] && name="unknown"
				seen_clients["$name"]=1
				if grep -q "^# DISABLED_PEER $name$" /etc/wireguard/wg0.conf; then
					status="DISABLED"
					handshake_fmt="-"
				elif [[ "$handshake" -eq 0 ]]; then
					status="never connected"
					handshake_fmt="never"
				else
					now=$(date +%s)
					diff=$(( now - handshake ))
					if [[ "$diff" -lt 180 ]]; then
						status="ONLINE"
					else
						status="offline"
					fi
					handshake_fmt=$(date -d "@$handshake" "+%Y-%m-%d %H:%M" 2>/dev/null \
						|| date -r "$handshake" "+%Y-%m-%d %H:%M" 2>/dev/null || echo "$handshake")
				fi
				rx_h=$(numfmt --to=iec "$rx" 2>/dev/null || echo "${rx}B")
				tx_h=$(numfmt --to=iec "$tx" 2>/dev/null || echo "${tx}B")
				[[ "$endpoint" == "(none)" || -z "$endpoint" ]] && endpoint="-"
				printf "%-18s %-20s %-22s %-10s %-10s %s\n" \
					"$name" "$endpoint" "$handshake_fmt" "$rx_h" "$tx_h" "$status"
			done < <(wg show wg0 dump 2>/dev/null | tail -n +2)
			while read -r cfg_client; do
				[[ -n "${seen_clients[$cfg_client]}" ]] && continue
				if grep -q "^# DISABLED_PEER $cfg_client$" /etc/wireguard/wg0.conf; then
					st="DISABLED"
				else
					st="never connected"
				fi
				printf "%-18s %-20s %-22s %-10s %-10s %s\n" \
					"$cfg_client" "-" "never" "-" "-" "$st"
			done < <(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | awk '{print $3}')
			exit
		;;

		# ======================================================================
		# 4 — Show QR code of a client
		# ======================================================================
		4)
			echo
			echo "=== Show QR code ==="
			echo
			echo "Select a client:"
			pick_client "Client"
			client_conf="$script_dir/${client}.conf"
			if [[ ! -f "$client_conf" ]]; then
				echo "Configuration file not found: $client_conf"
				echo "The file may have been deleted or the client was created on another machine."
				exit 1
			fi
			echo
			qrencode -t ANSI256UTF8 < "$client_conf"
			echo -e '\xE2\x86\x91 QR code for '"$client"
			echo
			echo "Configuration file: $client_conf"
			exit
		;;

		# ======================================================================
		# 5 — Rename a client
		# ======================================================================
		5)
			echo
			echo "=== Rename a client ==="
			echo
			echo "Select the client to rename:"
			pick_client "Client"
			old_name="$client"
			echo
			echo "Current name: $old_name"
			read -p "New name: " unsanitized_new
			new_name=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_new" | cut -c-15)
			if [[ -z "$new_name" ]]; then
				echo "Invalid name."
				exit 1
			fi
			if grep -q "^# BEGIN_PEER $new_name$" /etc/wireguard/wg0.conf; then
				echo "A client named '$new_name' already exists."
				exit 1
			fi
			echo
			read -p "Rename '$old_name' → '$new_name'? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			sed -i "s|^# BEGIN_PEER ${old_name}$|# BEGIN_PEER ${new_name}|" /etc/wireguard/wg0.conf
			sed -i "s|^# END_PEER ${old_name}$|# END_PEER ${new_name}|" /etc/wireguard/wg0.conf
			sed -i "s|^# DISABLED_PEER ${old_name}$|# DISABLED_PEER ${new_name}|" /etc/wireguard/wg0.conf
			if [[ -f "$script_dir/${old_name}.conf" ]]; then
				mv "$script_dir/${old_name}.conf" "$script_dir/${new_name}.conf"
				echo "Config file renamed: ${old_name}.conf → ${new_name}.conf"
			fi
			echo "Client renamed: $old_name → $new_name"
			exit
		;;

		# ======================================================================
		# 6 — Disable a client
		# ======================================================================
		6)
			echo
			echo "=== Disable a client ==="
			echo
			echo "Select the client to disable:"
			pick_client "Client"
			if grep -q "^# DISABLED_PEER $client$" /etc/wireguard/wg0.conf; then
				echo "$client is already disabled."
				exit 1
			fi
			echo
			read -p "Disable '$client'? It will be disconnected immediately. [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			wg set wg0 peer "$(get_peer_pubkey "$client")" remove
			awk -v client="$client" '
				/^# BEGIN_PEER / && $3 == client {
					in_block = 1
					print "# DISABLED_PEER " client
					print "# BEGIN_PEER " client
					next
				}
				/^# END_PEER / && $3 == client {
					in_block = 0
					print "# END_PEER " client
					next
				}
				in_block { print "## " $0; next }
				{ print }
			' /etc/wireguard/wg0.conf > /etc/wireguard/wg0.conf.tmp \
				&& mv /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf
			chmod 600 /etc/wireguard/wg0.conf
			echo "$client disabled and disconnected. Use option 7 to re-enable."
			exit
		;;

		# ======================================================================
		# 7 — Enable a disabled client
		# ======================================================================
		7)
			echo
			echo "=== Enable a disabled client ==="
			echo
			disabled_list=$(grep '^# DISABLED_PEER' /etc/wireguard/wg0.conf | awk '{print $3}')
			if [[ -z "$disabled_list" ]]; then
				echo "No disabled clients found."
				exit 1
			fi
			echo "Disabled clients:"
			echo "$disabled_list" | nl -s ') '
			disabled_count=$(echo "$disabled_list" | wc -l)
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -ge 1 && "$client_number" -le "$disabled_count" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(echo "$disabled_list" | sed -n "${client_number}p")
			echo
			read -p "Enable '$client'? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			awk -v client="$client" '
				/^# DISABLED_PEER / && $3 == client { next }
				/^# BEGIN_PEER / && $3 == client { in_block = 1 }
				/^# END_PEER / && $3 == client { in_block = 0 }
				in_block && /^## / { sub(/^## /, ""); print; next }
				{ print }
			' /etc/wireguard/wg0.conf > /etc/wireguard/wg0.conf.tmp \
				&& mv /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf
			chmod 600 /etc/wireguard/wg0.conf
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo "$client enabled and restored live."
			exit
		;;

		# ======================================================================
		# 8 — Add an allowed IP to a client
		# ======================================================================
		8)
			echo
			echo "=== Add an allowed IP to a client ==="
			echo
			echo "Select a client:"
			pick_client "Client"
			current_allowed=$(sed -n "/^# BEGIN_PEER ${client}$/,/^# END_PEER ${client}$/p" /etc/wireguard/wg0.conf \
				| grep '^AllowedIPs' | cut -d '=' -f 2 | tr -d ' ')
			echo
			echo "Client            : $client"
			echo "Current AllowedIPs: $current_allowed"
			echo
			read -p "New IP/CIDR to add (e.g. 192.168.1.0/24): " new_ip
			if ! validate_cidr "$new_ip"; then
				echo "Invalid IP/CIDR."
				exit 1
			fi
			if echo "$current_allowed" | tr ',' '\n' | tr -d ' ' | grep -qxF "$new_ip"; then
				echo "$new_ip is already present."
				exit 1
			fi
			new_allowed="${current_allowed}, ${new_ip}"
			awk -v client="$client" -v new_allowed="$new_allowed" '
				/^# BEGIN_PEER / { in_block = ($3 == client) }
				in_block && /^AllowedIPs / { $0 = "AllowedIPs = " new_allowed }
				{ print }
			' /etc/wireguard/wg0.conf > /etc/wireguard/wg0.conf.tmp \
				&& mv /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf
			chmod 600 /etc/wireguard/wg0.conf
			wg set wg0 peer "$(get_peer_pubkey "$client")" allowed-ips "$new_allowed"
			echo
			echo "AllowedIPs updated: $new_allowed"
			echo "Applied live."
			client_conf="$script_dir/${client}.conf"
			if [[ -f "$client_conf" ]]; then
				sed -i "s|^AllowedIPs = .*|AllowedIPs = ${new_allowed}|" "$client_conf"
				echo "Client config updated: $client_conf"
			fi
			exit
		;;

		# ======================================================================
		# 9 — Remove an allowed IP from a client
		# ======================================================================
		9)
			echo
			echo "=== Remove an allowed IP from a client ==="
			echo
			echo "Select a client:"
			pick_client "Client"
			current_allowed=$(sed -n "/^# BEGIN_PEER ${client}$/,/^# END_PEER ${client}$/p" /etc/wireguard/wg0.conf \
				| grep '^AllowedIPs' | cut -d '=' -f 2 | tr -d ' ')
			echo
			echo "Client            : $client"
			echo "Current AllowedIPs:"
			IFS=',' read -ra ip_array <<< "$current_allowed"
			for i in "${!ip_array[@]}"; do
				ip_array[$i]=$(echo "${ip_array[$i]}" | tr -d ' ')
				echo "   $((i+1))) ${ip_array[$i]}"
			done
			total_ips=${#ip_array[@]}
			echo
			if [[ "$total_ips" -le 1 ]]; then
				echo "Only one entry remains. Cannot remove — client would lose all routing."
				exit 1
			fi
			read -p "Select entry to remove: " ip_number
			until [[ "$ip_number" =~ ^[0-9]+$ && "$ip_number" -ge 1 && "$ip_number" -le "$total_ips" ]]; do
				echo "$ip_number: invalid selection."
				read -p "Select entry to remove: " ip_number
			done
			ip_to_remove="${ip_array[$((ip_number-1))]}"
			echo
			read -p "Remove '$ip_to_remove' from $client? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			new_allowed_arr=()
			for ip in "${ip_array[@]}"; do
				[[ "$ip" != "$ip_to_remove" ]] && new_allowed_arr+=("$ip")
			done
			new_allowed=$(IFS=', '; echo "${new_allowed_arr[*]}")
			awk -v client="$client" -v new_allowed="$new_allowed" '
				/^# BEGIN_PEER / { in_block = ($3 == client) }
				in_block && /^AllowedIPs / { $0 = "AllowedIPs = " new_allowed }
				{ print }
			' /etc/wireguard/wg0.conf > /etc/wireguard/wg0.conf.tmp \
				&& mv /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf
			chmod 600 /etc/wireguard/wg0.conf
			wg set wg0 peer "$(get_peer_pubkey "$client")" allowed-ips "$new_allowed"
			echo
			echo "AllowedIPs updated: $new_allowed"
			echo "Applied live."
			client_conf="$script_dir/${client}.conf"
			if [[ -f "$client_conf" ]]; then
				sed -i "s|^AllowedIPs = .*|AllowedIPs = ${new_allowed}|" "$client_conf"
				echo "Client config updated: $client_conf"
			fi
			exit
		;;

		# ======================================================================
		# 10 — Toggle full-tunnel / split-tunnel
		# ======================================================================
		10)
			echo
			echo "=== Toggle full-tunnel / split-tunnel ==="
			echo
			echo "Select a client:"
			pick_client "Client"
			client_conf="$script_dir/${client}.conf"
			current_client_allowed=""
			if [[ -f "$client_conf" ]]; then
				current_client_allowed=$(grep '^AllowedIPs' "$client_conf" | cut -d '=' -f 2 | tr -d ' ')
			fi
			echo
			echo "Client: $client"
			echo "Current client-side AllowedIPs: $current_client_allowed"
			echo
			if echo "$current_client_allowed" | grep -q "0\.0\.0\.0/0"; then
				echo "Current mode : FULL-TUNNEL (all traffic via VPN)"
				echo "Switching to : SPLIT-TUNNEL (VPN subnet only)"
				vpn_subnet=$(grep '^Address' /etc/wireguard/wg0.conf | head -1 \
					| cut -d '=' -f 2 | tr -d ' ' | cut -d ',' -f 1 | sed 's|\.[0-9]*/|.0/|')
				new_client_allowed="$vpn_subnet"
				grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf \
					&& new_client_allowed="${new_client_allowed}, fddd:2c4:2c4:2c4::/64"
				mode_label="SPLIT-TUNNEL"
			else
				echo "Current mode : SPLIT-TUNNEL"
				echo "Switching to : FULL-TUNNEL (all traffic via VPN)"
				new_client_allowed="0.0.0.0/0, ::/0"
				mode_label="FULL-TUNNEL"
			fi
			echo
			echo "New client AllowedIPs: $new_client_allowed"
			read -p "Confirm switch to $mode_label? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			if [[ -f "$client_conf" ]]; then
				sed -i "s|^AllowedIPs = .*|AllowedIPs = ${new_client_allowed}|" "$client_conf"
				echo "Client config updated: $client_conf"
			else
				echo "Warning: client config file not found."
			fi
			echo "Done. The client must re-import its configuration."
			exit
		;;

		# ======================================================================
		# 11 — Change client DNS
		# ======================================================================
		11)
			echo
			echo "=== Change client DNS ==="
			echo
			echo "Select a client:"
			pick_client "Client"
			client_conf="$script_dir/${client}.conf"
			if [[ ! -f "$client_conf" ]]; then
				echo "Configuration file not found: $client_conf"
				exit 1
			fi
			current_dns=$(grep '^DNS' "$client_conf" | cut -d '=' -f 2 | tr -d ' ')
			echo
			echo "Client     : $client"
			echo "Current DNS: $current_dns"
			echo
			new_client_dns
			sed -i "s|^DNS = .*|DNS = ${dns}|" "$client_conf"
			echo
			echo "DNS updated to: $dns"
			echo "Client config updated: $client_conf"
			echo "The client must re-import its configuration."
			exit
		;;

		# ======================================================================
		# 12 — Change client PersistentKeepalive
		# ======================================================================
		12)
			echo
			echo "=== Change PersistentKeepalive ==="
			echo
			echo "Select a client:"
			pick_client "Client"
			client_conf="$script_dir/${client}.conf"
			if [[ ! -f "$client_conf" ]]; then
				echo "Configuration file not found: $client_conf"
				exit 1
			fi
			current_ka=$(grep '^PersistentKeepalive' "$client_conf" | cut -d '=' -f 2 | tr -d ' ')
			echo
			echo "Client                     : $client"
			echo "Current PersistentKeepalive: ${current_ka:-not set}"
			echo
			echo "Recommended: 25 (seconds). Set to 0 to disable."
			read -p "New value [${current_ka:-25}]: " new_ka
			[[ -z "$new_ka" ]] && new_ka="${current_ka:-25}"
			if ! [[ "$new_ka" =~ ^[0-9]+$ ]]; then
				echo "Invalid value."
				exit 1
			fi
			if grep -q '^PersistentKeepalive' "$client_conf"; then
				sed -i "s|^PersistentKeepalive = .*|PersistentKeepalive = ${new_ka}|" "$client_conf"
			else
				echo "PersistentKeepalive = ${new_ka}" >> "$client_conf"
			fi
			echo "PersistentKeepalive set to: $new_ka"
			echo "Client config updated: $client_conf"
			echo "The client must re-import its configuration."
			exit
		;;

		# ======================================================================
		# 13 — Change VPN internal network (subnet)
		# ======================================================================
		13)
			echo
			echo "=== Change VPN internal network ==="
			echo
			current_addr=$(grep '^Address' /etc/wireguard/wg0.conf | head -1 | cut -d '=' -f 2 | tr -d ' ')
			current_ipv4=$(echo "$current_addr" | tr ',' '\n' | grep -v ':' | tr -d ' ')
			current_ipv6=$(echo "$current_addr" | tr ',' '\n' | grep ':' | tr -d ' ')
			current_base=$(echo "$current_ipv4" | sed 's/\.[0-9]*\/.*$//')
			current_cidr=$(echo "$current_ipv4" | grep -oE '/[0-9]+$')
			echo "Current server address: $current_ipv4"
			[[ -n "$current_ipv6" ]] && echo "Current IPv6          : $current_ipv6"
			echo
			echo "Enter new server IPv4 address with mask (e.g. 10.8.0.1/24)."
			read -p "New server address [$current_ipv4]: " new_server_addr
			if [[ -z "$new_server_addr" ]]; then
				echo "No change made."
				exit
			fi
			if ! validate_cidr "$new_server_addr"; then
				echo "Invalid IP/CIDR format."
				exit 1
			fi
			new_base=$(echo "$new_server_addr" | sed 's/\.[0-9]*\/.*$//')
			new_cidr=$(echo "$new_server_addr" | grep -oE '/[0-9]+$')
			new_server_ip="${new_base}.1${new_cidr}"
			old_subnet="${current_base}.0${current_cidr}"
			new_subnet="${new_base}.0${new_cidr}"
			echo
			echo "Migration: ${current_base}.x${current_cidr}  →  ${new_base}.x${new_cidr}"
			read -p "Confirm? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak
			echo "Backup saved: /etc/wireguard/wg0.conf.bak"
			if [[ -n "$current_ipv6" ]]; then
				sed -i "s|^Address = .*|Address = ${new_server_ip}, ${current_ipv6}|" /etc/wireguard/wg0.conf
			else
				sed -i "s|^Address = .*|Address = ${new_server_ip}|" /etc/wireguard/wg0.conf
			fi
			sed -i "s|AllowedIPs = ${current_base}\.|AllowedIPs = ${new_base}.|g" /etc/wireguard/wg0.conf
			sed -i "s|${old_subnet}|${new_subnet}|g" /etc/wireguard/wg0.conf
			echo
			echo "Updated wg0.conf:"
			grep '^Address' /etc/wireguard/wg0.conf
			grep 'AllowedIPs' /etc/wireguard/wg0.conf
			echo
			updated_clients=0
			orphan_clients=0
			for conf in "$script_dir"/*.conf; do
				[[ -f "$conf" ]] || continue
				[[ "$(basename "$conf")" == "wg0.conf" ]] && continue
				conf_client="$(basename "$conf" .conf)"
				if ! grep -q "^# BEGIN_PEER ${conf_client}$" /etc/wireguard/wg0.conf; then
					echo "  Skipped (client removed): $conf"
					(( orphan_clients++ ))
					continue
				fi
				client_octet=$(grep '^Address' "$conf" | grep -oE "${current_base//./\\.}\.[0-9]+" | grep -oE '[0-9]+$')
				if [[ -n "$client_octet" ]]; then
					sed -i "s|${current_base}\.\([0-9]\+\)/|${new_base}.\1/|g" "$conf"
					if [[ "$current_cidr" != "$new_cidr" ]]; then
						sed -i "/^Address/s|${new_base}\.${client_octet}${current_cidr}|${new_base}.${client_octet}${new_cidr}|g" "$conf"
					fi
				fi
				sed -i "s|${old_subnet}|${new_subnet}|g" "$conf"
				echo "  Updated: $conf"
				(( updated_clients++ ))
			done
			[[ "$updated_clients" -gt 0 ]] && echo "  ${updated_clients} client file(s) updated."
			[[ "$updated_clients" -eq 0 ]] && echo "  No active client .conf files to update in ${script_dir}."
			[[ "$orphan_clients" -gt 0 ]] && echo "  ${orphan_clients} orphan .conf file(s) skipped (client no longer in wg0.conf)."
			restart_wg
			exit
		;;

		# ======================================================================
		# 14 — Change endpoint (IP/hostname and/or port)
		# ======================================================================
		14)
			echo
			echo "=== Change endpoint ==="
			echo
			current_port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d ' ' -f 3)
			current_endpoint=$(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | cut -d ' ' -f 3)
			echo "Current endpoint: ${current_endpoint}:${current_port}"
			echo
			read -p "New hostname/IP [leave blank to keep ${current_endpoint}]: " new_host
			read -p "New port        [leave blank to keep ${current_port}]: " new_port
			if [[ -z "$new_host" && -z "$new_port" ]]; then
				echo "No change made."
				exit
			fi
			[[ -z "$new_host" ]] && new_host="$current_endpoint"
			[[ -z "$new_port" ]] && new_port="$current_port"
			if ! [[ "$new_port" =~ ^[0-9]+$ ]] || [[ "$new_port" -lt 1 || "$new_port" -gt 65535 ]]; then
				echo "Invalid port (must be 1–65535)."
				exit 1
			fi
			echo
			echo "New endpoint: ${new_host}:${new_port}"
			read -p "Confirm? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak
			sed -i "s|^# ENDPOINT .*|# ENDPOINT ${new_host}|" /etc/wireguard/wg0.conf
			sed -i "s|^ListenPort = .*|ListenPort = ${new_port}|" /etc/wireguard/wg0.conf
			if [[ "$new_port" != "$current_port" ]]; then
				if systemctl is-active --quiet firewalld.service; then
					firewall-cmd --remove-port="${current_port}/udp" --permanent 2>/dev/null
					firewall-cmd --add-port="${new_port}/udp" --permanent
					firewall-cmd --reload
					echo "firewalld updated: ${current_port}/udp → ${new_port}/udp"
				elif command -v iptables &>/dev/null; then
					iptables -D INPUT -p udp --dport "$current_port" -j ACCEPT 2>/dev/null
					iptables -I INPUT -p udp --dport "$new_port" -j ACCEPT
					echo "iptables updated: ${current_port}/udp → ${new_port}/udp"
				fi
			fi
			restart_wg
			echo
			updated=0
			for conf in "$script_dir"/*.conf; do
				[[ -f "$conf" ]] || continue
				[[ "$(basename "$conf")" == "wg0.conf" ]] && continue
				if grep -q '^Endpoint' "$conf"; then
					sed -i "s|^Endpoint = .*|Endpoint = ${new_host}:${new_port}|" "$conf"
					echo "Updated: $conf"
					(( updated++ ))
				fi
			done
			[[ "$updated" -eq 0 ]] && echo "No client .conf files found in ${script_dir}."
			echo
			echo "Endpoint updated to: ${new_host}:${new_port}"
			echo "Clients must re-import their configuration."
			exit
		;;

		# ======================================================================
		# 15 — Rotate keys of a client
		# ======================================================================
		15)
			echo
			echo "=== Rotate client keys ==="
			echo
			echo "Select a client:"
			pick_client "Client"
			client_conf="$script_dir/${client}.conf"
			echo
			echo "Client: $client"
			echo "A new PrivateKey and PresharedKey will be generated."
			echo "The client IP and AllowedIPs are preserved."
			read -p "Confirm key rotation? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			new_key=$(wg genkey)
			new_pubkey=$(wg pubkey <<< "$new_key")
			new_psk=$(wg genpsk)
			old_pubkey=$(get_peer_pubkey "$client")
			awk -v client="$client" -v new_pubkey="$new_pubkey" -v new_psk="$new_psk" '
				/^# BEGIN_PEER / { in_block = ($3 == client) }
				in_block && /^PublicKey /    { $0 = "PublicKey = " new_pubkey }
				in_block && /^PresharedKey / { $0 = "PresharedKey = " new_psk }
				{ print }
			' /etc/wireguard/wg0.conf > /etc/wireguard/wg0.conf.tmp \
				&& mv /etc/wireguard/wg0.conf.tmp /etc/wireguard/wg0.conf
			chmod 600 /etc/wireguard/wg0.conf
			allowed=$(sed -n "/^# BEGIN_PEER ${client}$/,/^# END_PEER ${client}$/p" /etc/wireguard/wg0.conf \
				| grep '^AllowedIPs' | cut -d '=' -f 2 | tr -d ' ')
			wg set wg0 peer "$old_pubkey" remove
			wg set wg0 peer "$new_pubkey" preshared-key <(echo "$new_psk") allowed-ips "$allowed"
			if [[ -f "$client_conf" ]]; then
				NEW_KEY="$new_key" NEW_PSK="$new_psk" awk '
					BEGIN { section="" }
					/^\[Interface\]/ { section="interface" }
					/^\[Peer\]/      { section="peer" }
					section=="interface" && /^PrivateKey /    { print "PrivateKey = " ENVIRON["NEW_KEY"]; next }
					section=="peer"      && /^PresharedKey / { print "PresharedKey = " ENVIRON["NEW_PSK"]; next }
					{ print }
				' "$client_conf" > "$client_conf.tmp" && mv "$client_conf.tmp" "$client_conf"
				echo "Client config updated: $client_conf"
			fi
			echo
			echo "Keys rotated for $client — applied live."
			echo "New public key: $new_pubkey"
			echo "The client must re-import its configuration."
			echo
			if [[ -f "$client_conf" ]]; then
				qrencode -t ANSI256UTF8 < "$client_conf"
				echo -e '\xE2\x86\x91 New QR code for '"$client"
			fi
			exit
		;;

		# ======================================================================
		# 16 — Rotate server private key
		# ======================================================================
		16)
			echo
			echo "=== Rotate server private key ==="
			echo
			echo "WARNING: All clients will lose connectivity until they re-import their config."
			echo "Client IPs and names are preserved. Only the server key pair changes."
			echo
			read -p "Confirm server key rotation? [y/N]: " confirm
			[[ "$confirm" =~ ^[yY]$ ]] || { echo "Aborted."; exit; }
			new_server_key=$(wg genkey)
			new_server_pubkey=$(wg pubkey <<< "$new_server_key")
			cp /etc/wireguard/wg0.conf /etc/wireguard/wg0.conf.bak
			echo "Backup saved: /etc/wireguard/wg0.conf.bak"
			sed -i "s|^PrivateKey = .*|PrivateKey = ${new_server_key}|" /etc/wireguard/wg0.conf
			updated=0
			for conf in "$script_dir"/*.conf; do
				[[ -f "$conf" ]] || continue
				[[ "$(basename "$conf")" == "wg0.conf" ]] && continue
				sed -i "s|^PublicKey = .*|PublicKey = ${new_server_pubkey}|" "$conf"
				echo "Updated: $conf"
				(( updated++ ))
			done
			[[ "$updated" -eq 0 ]] && echo "No client .conf files found in ${script_dir}."
			restart_wg
			echo
			echo "Server key rotated."
			echo "New server public key: $new_server_pubkey"
			echo "All clients must re-import their configuration."
			exit
		;;

		# ======================================================================
		# 17 — Remove WireGuard
		# ======================================================================
		17)
			echo
			read -p "Confirm WireGuard removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm WireGuard removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
				wg_addr=$(grep '^Address' /etc/wireguard/wg0.conf | head -1 | cut -d '=' -f 2 | tr -d ' ' | cut -d ',' -f 1)
				wg_base=$(echo "$wg_addr" | sed 's/\.[0-9]*\/.*$//')
				wg_cidr=$(echo "$wg_addr" | grep -oE '/[0-9]+$')
				wg_network="${wg_base}.0${wg_cidr}"
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep "\\-s ${wg_network}" | grep -oE '[^ ]+$')
					firewall-cmd --remove-port="$port"/udp
					firewall-cmd --zone=trusted --remove-source="${wg_network}"
					firewall-cmd --permanent --remove-port="$port"/udp
					firewall-cmd --permanent --zone=trusted --remove-source="${wg_network}"
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s "${wg_network}" ! -d "${wg_network}" -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s "${wg_network}" ! -d "${wg_network}" -j SNAT --to "$ip"
					if grep -qs 'fddd:2c4:2c4:2c4::1/64' /etc/wireguard/wg0.conf; then
						ip6=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s fddd:2c4:2c4:2c4::/64 '"'"'!'"'"' -d fddd:2c4:2c4:2c4::/64' | grep -oE '[^ ]+$')
						firewall-cmd --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd --permanent --zone=trusted --remove-source=fddd:2c4:2c4:2c4::/64
						firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
						firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
					fi
				else
					systemctl disable --now wg-iptables.service
					rm -f /etc/systemd/system/wg-iptables.service
				fi
				systemctl disable --now wg-quick@wg0.service
				rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
				rm -f /etc/sysctl.d/99-wireguard-forward.conf
				if [[ "$use_boringtun" -eq 0 ]]; then
					if [[ "$os" == "ubuntu" ]]; then
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "debian" ]]; then
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "centos" ]]; then
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					fi
				else
					{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
					if [[ "$os" == "ubuntu" ]]; then
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "debian" ]]; then
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "centos" ]]; then
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					fi
					rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
				fi
				echo
				echo "WireGuard removed!"
			else
				echo
				echo "WireGuard removal aborted!"
			fi
			exit
		;;

		18)
			exit
		;;
	esac
fi
