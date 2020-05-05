#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2020 Nyr. Released under the MIT License.


# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo "This script needs to be run with bash, not sh"
	exit
fi

if [[ "$EUID" -ne 0 ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi

# If running inside a container, do nothing
if systemd-detect-virt -cq 2>/dev/null; then
	echo "You are running this script inside a $(systemd-detect-virt) container
We are unable to load the WireGuard kernel module and setup can't continue"
	exit
fi

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
	os="ubuntu"
	os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
	group_name="nogroup"
elif [[ -e /etc/debian_version ]]; then
	os="debian"
	os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
	group_name="nogroup"
elif [[ -e /etc/centos-release ]]; then
	os="centos"
	os_version=$(grep -oE '[0-9]+' /etc/centos-release | head -1)
	group_name="nobody"
elif [[ -e /etc/fedora-release ]]; then
	os="fedora"
	os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
	group_name="nobody"
else
	echo "Looks like you aren't running this installer on Ubuntu, Debian, CentOS or Fedora"
	exit
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
	echo "Ubuntu 18.04 or higher is required to use this installer
This version of Ubuntu is too old and unsupported"
	exit
fi

if [[ "$os" == "debian" && "$os_version" -lt 10 ]]; then
	echo "Debian 10 or higher is required to use this installer
This version of Debian is too old and unsupported"
	exit
fi

if [[ "$os" == "centos" && "$os_version" -lt 7 ]]; then
	echo "CentOS 7 or higher is required to use this installer
This version of CentOS is too old and unsupported"
	exit
fi

if [[ "$os" == "fedora" && "$os_version" -eq 31 && $(uname -r | cut -d "." -f 2) -lt 6 ]]; then
	echo 'Fedora 31 is supported, but your kernel is outdated
Upgrade the kernel using "dnf upgrade kernel" and restart'
	exit
fi

new_client_dns () {
	echo "Which DNS do you want to use for this client?"
	echo "   1) Current system resolvers"
	echo "   2) 1.1.1.1"
	echo "   3) Google"
	echo "   4) OpenDNS"
	echo "   5) NTT"
	echo "   6) AdGuard"
	read -p "DNS [1]: " dns
	until [[ -z "$dns" || "$dns" =~ ^[1-6]$ ]]; do
		echo "$dns: invalid selection."
		read -p "DNS [1]: " dns
	done
		# DNS
	case "$dns" in
		1|"")
			# Locate the proper resolv.conf
			# Needed for systems running systemd-resolved
			if grep -q "127.0.0.53" "/etc/resolv.conf"; then
				resolv_conf="/run/systemd/resolve/resolv.conf"
			else
				resolv_conf="/etc/resolv.conf"
			fi
			# Extract nameservers and provide them in the required format
			dns=$(grep -v '#' "$resolv_conf" | grep nameserver | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | xargs | sed -e 's/ /, /g')
		;;
		2)
			dns="1.1.1.1, 1.0.0.1"
		;;
		3)
			dns="8.8.8.8, 8.8.4.4"
		;;
		4)
			dns="208.67.222.222, 208.67.220.220"
		;;
		5)
			dns="129.250.35.250, 129.250.35.251"
		;;
		6)
			dns="176.103.130.130, 176.103.130.131"
		;;
	esac
}

new_client_setup () {
	# Given a list of the assigned internal IPv4 addresses, obtain the lowest still
	# available octet. Important to start looking at 2, because 1 is our gateway.
	octet=2
	while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f 4 | cut -d "/" -f 1 | grep -q "$octet"; do
	    (( octet++ ))
	done
	# Don't break the WireGuard configuration in case the address space is full
	if [[ "$octet" -eq 255 ]]; then
    	echo "253 clients are already configured. The WireGuard internal subnet is full!"
    	exit
	fi
	key=$(wg genkey)
	psk=$(wg genpsk)
	# Configure client in the server
	cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client
[Peer]
PublicKey = $(wg pubkey <<< $key)
PresharedKey = $psk
AllowedIPs = 10.7.0.$octet/32$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/128")
# END_PEER $client
EOF
	# Create client configuration
	cat << EOF > ~/"$client".conf
[Interface]
Address = 10.7.0.$octet/24$(grep -q 'fddd:2c4:2c4:2c4::1' /etc/wireguard/wg0.conf && echo ", fddd:2c4:2c4:2c4::$octet/64")
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

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
	clear
	echo 'Welcome to this WireGuard road warrior installer!'
	echo
	echo "I need to ask you a few questions before starting setup."
	echo "You can use the default options and just press enter if you are ok with them."
	# If system has a single IPv4, it is selected automatically. Else, ask the user
	if [[ $(ip -4 addr | grep inet | grep -vEc '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}') -eq 1 ]]; then
		ip=$(ip -4 addr | grep inet | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
	else
		number_of_ip=$(ip -4 addr | grep inet | grep -vEc '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
		echo
		echo "What IPv4 address should the WireGuard server use?"
		ip -4 addr | grep inet | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | nl -s ') '
		read -p "IPv4 address [1]: " ip_number
		until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$number_of_ip" ]]; do
			echo "$ip_number: invalid selection."
			read -p "IPv4 address [1]: " ip_number
		done
		[[ -z "$ip_number" ]] && ip_number="1"
		ip=$(ip -4 addr | grep inet | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | sed -n "$ip_number"p)
	fi
	# If $ip is a private IP address, the server must be behind NAT
	if echo "$ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		echo
		echo "This server is behind NAT. What is the public IPv4 address or hostname?"
		# Get public IP and sanitize with grep
		get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
		read -p "Public IPv4 address / hostname [$get_public_ip]: " public_ip
		# If the checkip service is unavailable and user didn't provide input, ask again
		until [[ -n "$get_public_ip" || -n $public_ip ]]; do
    		echo "Invalid input."
			read -p "Public IPv4 address / hostname: " public_ip
		done
		[[ -z "$public_ip" ]] && public_ip="$get_public_ip"
	fi
	# If system has a single IPv6, it is selected automatically
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
		ip6=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
	fi
	# If system has multiple IPv6, ask the user to select one
	if [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
		number_of_ip6=$(ip -6 addr | grep -c 'inet6 [23]')
		echo
		echo "What IPv6 address should the WireGuard server use?"
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
	echo "What port do you want WireGuard listening to?"
	read -p "Port [51820]: " port
	until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
		echo "$port: invalid port."
		read -p "Port [51820]: " port
	done
	[[ -z "$port" ]] && port="51820"
	echo
	echo "Tell me a name for the first client."
	read -p "Client name [client]: " unsanitized_client
	# Allow a limited set of characters to avoid conflicts
	client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
	[[ -z "$client" ]] && client="client"
	echo
	new_client_dns
	echo
	echo "We are ready to set up your WireGuard server now."
	# Install a firewall in the rare case where one is not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	echo
	read -n1 -r -p "Press any key to continue..."
	# Install WireGuard
	if [[ "$os" == "ubuntu" && "$os_version" -ge 2004 ]]; then
		# Ubuntu 20.04 or higer
		apt-get update
		apt-get install -y wireguard qrencode $firewall
	elif [[ "$os" == "ubuntu" && "$os_version" -eq 1804 ]]; then
		# Ubuntu 18.04
		# Repo is added manually so we don't depend on add-apt-repository.
		# gnupg is required to add the repo, we install it if not already present.
		if ! dpkg -s gnupg &>/dev/null; then
			apt-get update
			apt-get install -y gnupg
		fi
		apt-key add - << EOF
-----BEGIN PGP PUBLIC KEY BLOCK-----

xsFNBFgsdJkBEADF7kp11himOaaVQ5rYN05SjdkrNWG2OI+aA8GnBqHk8V9Cjabo
5i+Dof7y6Efcr9kzkHZeRq3sFuyRd4hNBrsTvJbsBkeOZ/O9tUG/hTCBR0E4XHxb
xyXFgdLNvLFKrhcfHo6lPlf5rCGPEp6obuNILh8lzpGKCi1AvC89nCtqZZqeyRKw
MVv1Hf217nDAu3Swgv3iC5a1vncxCni4g5eV2tD8hyCmeIl2Cr/VBDzuFt7YUWCa
TrBkgvE941YQo2xnia203aRiDFi/JhEVAiaNh+ycHQeNIW8bYsp6uoteR/DDoZpt
YKMMQAhdD9QRHKTTDFfOs4a3G2nOsnTdgCcLQKlbHCZo53RSJcQrwOrt+QHop8Ut
yWMcOQ6dk2JK5ISCW8B11XpFJWd/TAlQkLO2J3R7Il40g87k1UnHG58F7N37SNi1
Hku3AH4sARx8mmcQAUhVHHiriJQ6W8DCE6tX7RBoRcSgA5NK9iCMmX6s+X297Die
yttoGPfDPph6DTd/4SzL5HjQGsusfpYsJmIimNuksHUbyI/fwd7R1n8ho2ZYSbsQ
XLo4NtTc+mD+xu4Au/FAWCQeNxZf6I5iFlhLMvYpswNHIc/TAy9NdEkBaVVt7ILP
GtQNzEeNPdDMjyCsigqP7LtkB0tTuPngvJnZqMCAxnzBbQeLqv4+1MrjyQARAQAB
zR9MYXVuY2hwYWQgUFBBIGZvciB3aXJlZ3VhcmQtcHBhwsF4BBMBAgAiBQJYLHSZ
AhsDBgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRCuM4NfUEoaJUWCD/9i46Pu
YjRa1xLNTCfwMKhy+xPmi3oiB59iWYfUS82XNISJE2ZVdXbWAmlVVl3enGa1oY4w
aX2XZes4uAq/0S/QTZixHcCZs/vEVDdFg7UdvfswJ+eu4P/A6oh8JoJILMaIXhfy
92wEjFrI2NV3tB/3aee4nxJsUYLbBx3DhRzTfHYXiP1zKJxPWBilNLbme8vhYiLc
6PyUWFXzWms50Nk1c38mmMAv4lqlX7dC4U9HcZs3TT0oOC7oTU7l5F/0HMy0GzRl
Ual7mDmtvcKsUS8HRlCSPDE44hwnXmeuhcV5bRPAlyRlyP63n8zzlzfzQ1sgFjo8
vN7VEaQVxERManwpT3BTOfyFT82yUGHeGgTAs8FI3Fr6aGk04nH0xpPrCZCQfSAw
ZoziI0DM3iWl603NBFZM7brYJvebQrH8CpiaqzlcvxQe9KfOA9ootSC2pOdLFMa7
me8nZUSZCo2/9AfKpTlCl3szPmAeAHc/M++doc6VSIchaZgB2NybBLqbm/2hJhc0
HwWxODILKCzBfjabqfnd+SeOIZkQ5JjYNVGqy4vOv5zkeQ9wVGHurzCGKfJ953ab
bufG+23D72u9enVZT+L4zH666hdQ6zyM0lrYcrBfPPnZkrQxBIilpvlOdLYDieUE
fiJGS5WoFr1yr8b7oQxTrZlCeHk3r3FJIhv2dQ==
=3EYq
-----END PGP PUBLIC KEY BLOCK-----
EOF
		echo "deb http://ppa.launchpad.net/wireguard/wireguard/ubuntu bionic main" > /etc/apt/sources.list.d/wireguard-ubuntu-wireguard-bionic.list
		apt-get update
		# Try to install kernel headers for the running kernel and avoid a reboot. This
		# can fail, so it's important to run separately from the other apt-get command.
		apt-get install -y linux-headers-$(uname -r)
		# linux-headers-generic points to the latest headers. We install it because if
		# the system has an outdated kernel, there is no guarantee that old headers were
		# still downloadable and to provide suitable headers for future kernel updates.
		apt-get install -y linux-headers-generic
		apt-get install -y wireguard qrencode $firewall
	elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
		# Debian 10
		if ! grep -qs '^deb .* buster-backports main' /etc/apt/sources.list /etc/apt/sources.list.d/*.list; then
    		echo "deb http://deb.debian.org/debian buster-backports main" >> /etc/apt/sources.list
		fi
		apt-get update
		# Try to install kernel headers for the running kernel and avoid a reboot. This
		# can fail, so it's important to run separately from the other apt-get command.
		apt-get install -y linux-headers-$(uname -r)
		# There are cleaner ways to find out the $architecture, but we require an
		# specific format for the package name and this approach provides what we need.
		architecture=$(dpkg --get-selections 'linux-image-*-*' | cut -f 1 | grep -oE '[^-]*$' -m 1)
		# linux-headers-$architecture points to the latest headers. We install it
		# because if the system has an outdated kernel, there is no guarantee that old
		# headers were still downloadable and to provide suitable headers for future
		# kernel updates.
		apt-get install -y linux-headers-"$architecture"
		apt-get install -y wireguard qrencode bc $firewall
	elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
		# CentOS 8
		dnf install -y epel-release elrepo-release
		dnf install -y kmod-wireguard wireguard-tools qrencode $firewall
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
		# CentOS 7
		yum install -y epel-release https://www.elrepo.org/elrepo-release-7.el7.elrepo.noarch.rpm
		yum install -y yum-plugin-elrepo
		yum install -y kmod-wireguard wireguard-tools qrencode $firewall
		mkdir -p /etc/wireguard/
	elif [[ "$os" == "fedora" ]]; then
		# Fedora
		dnf install -y wireguard-tools qrencode $firewall
		mkdir -p /etc/wireguard/
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Generate wg0.conf
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $ip

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/30-wireguard-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/30-wireguard-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	if systemctl is-active --quiet firewalld.service; then
		# Using both permanent and not permanent rules to avoid a firewalld
		# reload.
		firewall-cmd --add-port="$port"/udp
		firewall-cmd --zone=trusted --add-source=10.7.0.0/24
		firewall-cmd --permanent --add-port="$port"/udp
		firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24
		# Set NAT for the VPN subnet
		firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
		if [[ -n "$ip6" ]]; then
			firewall-cmd --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --permanent --zone=trusted --add-source=fddd:2c4:2c4:2c4::/64
			firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
			firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to "$ip6"
		fi
	else
		# Create a service to set up persistent iptables rules
		iptables_path=$(command -v iptables)
		ip6tables_path=$(command -v ip6tables)
		echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to $ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s 10.7.0.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service
		if [[ -n "$ip6" ]]; then
			echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStart=$ip6tables_path -I FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s fddd:2c4:2c4:2c4::/64 ! -d fddd:2c4:2c4:2c4::/64 -j SNAT --to $ip6
ExecStop=$ip6tables_path -D FORWARD -s fddd:2c4:2c4:2c4::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
		fi
		echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service
		systemctl enable --now wg-iptables.service
	fi
	# If the server is behind NAT, use the correct IP address
	[[ ! -z "$public_ip" ]] && ip="$public_ip"
	# Generates the custom client.conf
	new_client_setup
	# Enable and start the wg-quick service
	systemctl enable --now wg-quick@wg0.service
	echo
	qrencode -t UTF8 < ~/"$client.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
	echo
	# If the kernel module didn't load, system probably had an outdated kernel
	# We'll try to help, but will not will not force a kernel upgrade upon the user
	if ! modprobe -nq wireguard; then
	    echo "Warning!"
	    echo "Installation was finished, but the WireGuard kernel module could not load."
	    if [[ "$os" == "ubuntu" && "$os_version" -eq 1804 ]]; then
	        echo 'Upgrade the kernel and headers with "apt-get install linux-generic" and restart.'
	    elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
	        echo "Upgrade the kernel with \"apt-get install linux-image-$architecture\" and restart."
	    elif [[ "$os" == "centos" && "$os_version" -le 8 ]]; then
			echo "Reboot your system to load the most recent kernel."
	    fi
	else
    	echo "Finished!"
	fi
	echo
	echo "Your client configuration is available at:" ~/"$client.conf"
	echo "If you want to add more clients, just run this script again."
else
	clear
	echo "Looks like WireGuard is already installed."
	echo
	echo "What do you want to do?"
	echo "   1) Add a new user"
	echo "   2) Remove an existing user"
	echo "   3) Remove WireGuard"
	echo "   4) Exit"
	read -p "Select an option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Select an option: " option
	done
	case "$option" in
		1)
			echo
			echo "Tell me a name for the client."
			read -p "Client name: " unsanitized_client
			# Allow a limited set of characters to avoid conflicts
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			while [[ -z "$client" || -n $(grep "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf) ]]; do
				echo "$client: invalid client name."
				read -p "Client name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client")
			done
			echo
			new_client_dns
			new_client_setup
			# Append the configuration to the WireGuard interface
			wg addconf wg0 <(wg-quick strip wg0)
			echo
			qrencode -t UTF8 < ~/"$client.conf"
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "Client $client added, configuration is available at:" ~/"$client.conf"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "You have no existing clients!"
				exit
			fi
			echo
			echo "Select the existing client you want to remove:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -p "Select one client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Select one client: " client_number
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -p "Do you really want to remove access for client $client? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Do you really want to remove access for client $client? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				# The following is the right way to avoid disrupting other active connections:
				# Remove from the live interface
				wg set wg0 peer $(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3) remove
				# Remove from the configuration file
				sed -i "/^# BEGIN_PEER $client/,/^# END_PEER $client/d" /etc/wireguard/wg0.conf
				echo
				echo "Client $client has been removed!"
			else
				echo
				echo "Removal of client $client aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Do you really want to remove WireGuard? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Do you really want to remove WireGuard? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				port=$(grep '^ListenPort' /etc/wireguard/wg0.conf | cut -d " " -f 3)
				if systemctl is-active --quiet firewalld.service; then
					ip=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep '\-s 10.7.0.0/24 '"'"'!'"'"' -d 10.7.0.0/24' | grep -oE '[^ ]+$')
					# Using both permanent and not permanent rules to avoid a firewalld reload.
					firewall-cmd --remove-port="$port"/udp
					firewall-cmd --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --permanent --remove-port="$port"/udp
					firewall-cmd --permanent --zone=trusted --remove-source=10.7.0.0/24
					firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
					firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s 10.7.0.0/24 ! -d 10.7.0.0/24 -j SNAT --to "$ip"
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
				rm -f /etc/sysctl.d/30-wireguard-forward.conf
				if [[ "$os" == "ubuntu" && "$os_version" -ge 2004 ]]; then
					# Ubuntu 20.04 or higher
					rm -rf /etc/wireguard/
					apt-get remove --purge -y wireguard wireguard-tools
				elif [[ "$os" == "ubuntu" && "$os_version" -eq 1804 ]]; then
					# Ubuntu 18.04
					rm -f /etc/apt/sources.list.d/wireguard-ubuntu-wireguard-bionic.list
					apt-key del E1B39B6EF6DDB96564797591AE33835F504A1A25
					rm -rf /etc/wireguard/
					apt-get remove --purge -y wireguard wireguard-dkms wireguard-tools
				elif [[ "$os" == "debian" && "$os_version" -eq 10 ]]; then
					# Debian 10
					rm -rf /etc/wireguard/
					apt-get remove --purge -y wireguard wireguard-dkms wireguard-tools
				elif [[ "$os" == "centos" && "$os_version" -eq 8 ]]; then
					# CentOS 8
					rm -rf /etc/wireguard/
					dnf remove -y kmod-wireguard wireguard-tools
				elif [[ "$os" == "centos" && "$os_version" -eq 7 ]]; then
					# CentOS 7
					rm -rf /etc/wireguard/
					yum remove -y kmod-wireguard wireguard-tools
				elif [[ "$os" == "fedora" ]]; then
					# Fedora
					rm -rf /etc/wireguard/
					dnf remove -y wireguard-tools
				fi
				echo
				echo "WireGuard removed!"
			else
				echo
				echo "Removal aborted!"
			fi
			exit
		;;
		4)
			exit
		;;
	esac
fi
