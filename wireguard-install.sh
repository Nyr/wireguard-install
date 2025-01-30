#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2020 Nyr. Released under the MIT License.

# Standards:
# All scripts should be installed to /opt/wg-inst (or other wginst_dir static) and have a unified naming scheme
# Using "wg-function-name.sh"

# Variable Naming Scheme:
# wginst_ = Global wireguard-installer statics, used for defaults
# wg_ = Global wireguard vars, used to pull current config or setup new config
# peer_ = Global peer vars, used to pull current config or setup new config
# rex_ = Global regex strings for unified comparisons
# All other vars should be local in functions and should not use these names, for clarity


# Globals for important things
# WGInst Global Statics
# Adjust version if changes are made to file formats or services
wginst_version="1.0"
wginst_ipv4_default="10.7.0.1"
wginst_ipv6_default="fddd:2c4:2c4:2c4::1"
wginst_port_default="51820"
wginst_dir="/opt/wg-inst"

# WG Global Vars - presets here
wg_installed="0"
wg_active="0"
wg_ipv6_enabled="0"
wg_num_clients=0
wg_free_octets=({2..254})
wg_clients_array=("")
wg_used_octets=("")
wg_pubkeys_array=("")


# Regex Globals for easy compares and validation
rex_ipv4="((25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])\.?\b){4}"
rex_ipv6="(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))"
rex_fqdn="(?=^.{1,254}$)(^(?>(?!\d+\.)[a-z0-9_\-]{1,63}\.?)+(?:[a-z]{2,})$)"



#	=============================================
#			STARTUP FUNCTIONS
#	=============================================

	# BEGIN_FUNC: DETECT_BLOCKERS
detect_blockers () {
	# Detect insufficient privileges
	if [[ $EUID > 0 ]]; then
		echo "This installer needs to be run with superuser privileges (sudo or root)."
		exit
	fi
	
	# Detect Debian users running the script with "sh" instead of bash
	if readlink /proc/$$/exe | grep -q "dash"; then
		echo 'This installer needs to be run with "bash", not "sh".'
		exit
	fi
	
	# Detect environments where $PATH does not include the sbin directories
	if ! grep -q sbin <<< "$PATH"; then
		echo '$PATH does not include sbin. Try using "su -" instead of "su".'
		exit
	fi
	
	# Detect unsupported distribution
	# $os_version variables aren't always in use, but are kept here for convenience
	local ostype="unsupported"
	local os_version="Unknown Version"
	local os_name="Unknown Name"
	if grep -qs "ubuntu" /etc/os-release; then
		os_name="Ubuntu"
		os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
		[[ $os_version -ge 2204 ]] && ostype="ubuntu"
		
	elif [[ -e /etc/debian_version ]]; then
		local debver="$(</etc/debian_version)"
		local sidstr="/sid"
		
		os_name="Debian Stable"
		os_version=$(grep -oE '[0-9]+' <<< "$debver" | head -1)
		
		[[ "$debver" =~ $sidstr ]] && local debiansid="true"
		[[ -n "$debiansid" ]] && os_name="Debian Testing/Unstable"
		[[ $os_version -ge 11 && -z "$debiansid" ]] && ostype="debian"
		
	elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
		os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
		os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
		[[ $os_version -ge 9 ]] && ostype="centos"
		
	elif [[ -e /etc/fedora-release ]]; then
		ostype="fedora"; os_name="Fedora Linux"
		os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
		
	fi
	
	if [[ "$ostype" == "unsupported" ]]; then
		echo \
"This installer seems to be running on an unsupported distribution.

This installer supports the following distributions:
Ubuntu 22.04 or higher
Debian Stable 11 or higher
CentOS/AlmaLinux/Rocky Linux 9 or higher
Fedora Linux

Detected distribution:
Name: $os_name
Version: $os_version"
		exit
	fi
	wg_os="$ostype"
	
}
	# END_FUNC: DETECT_BLOCKERS


	# BEGIN_FUNC: INITIAL_SETUP
initial_setup () {
	# Discard stdin. Needed when running from an one-liner which includes a newline
	read -N 999999 -t 0.001

	# Detect if BoringTun (userspace WireGuard) needs to be used
	if systemd-detect-virt -cq && ! grep -q '^wireguard ' /proc/modules; then
		# Running inside a container and the wireguard kernel module is not available
		if [ "$(uname -m)" != "x86_64" ]; then
			echo \
"In containerized systems without the wireguard kernel module, 
this installer supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
			exit
		fi
		# TUN device is required to use BoringTun
		if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
			echo \
"The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
			exit
		fi
		wg_use_boringtun="1"
	fi

	# Set up color display
	local colorterms="^(xterm-color|\.*-256color)$"
	if [[ "$TERM" =~ $colorterms ]]; then
		# Color Templates
		
		# Reset
		Color_Off='\033[0m'       # Text Reset

		# Regular Colors
		Black='\033[0;30m'        # Black
		Red='\033[0;31m'          # Red
		Green='\033[0;32m'        # Green
		Yellow='\033[0;33m'       # Yellow
		Blue='\033[0;34m'         # Blue
		Purple='\033[0;35m'       # Purple
		Cyan='\033[0;36m'         # Cyan
		White='\033[0;37m'        # White

		# Bold
		BBlack='\033[1;30m'       # Black
		BRed='\033[1;31m'         # Red
		BGreen='\033[1;32m'       # Green
		BYellow='\033[1;33m'      # Yellow
		BBlue='\033[1;34m'        # Blue
		BPurple='\033[1;35m'      # Purple
		BCyan='\033[1;36m'        # Cyan
		BWhite='\033[1;37m'       # White

		# Underline
		UBlack='\033[4;30m'       # Black
		URed='\033[4;31m'         # Red
		UGreen='\033[4;32m'       # Green
		UYellow='\033[4;33m'      # Yellow
		UBlue='\033[4;34m'        # Blue
		UPurple='\033[4;35m'      # Purple
		UCyan='\033[4;36m'        # Cyan
		UWhite='\033[4;37m'       # White

		# Background
		On_Black='\033[40m'       # Black
		On_Red='\033[41m'         # Red
		On_Green='\033[42m'       # Green
		On_Yellow='\033[43m'      # Yellow
		On_Blue='\033[44m'        # Blue
		On_Purple='\033[45m'      # Purple
		On_Cyan='\033[46m'        # Cyan
		On_White='\033[47m'       # White

		# High Intensity
		IBlack='\033[0;90m'       # Black
		IRed='\033[0;91m'         # Red
		IGreen='\033[0;92m'       # Green
		IYellow='\033[0;93m'      # Yellow
		IBlue='\033[0;94m'        # Blue
		IPurple='\033[0;95m'      # Purple
		ICyan='\033[0;96m'        # Cyan
		IWhite='\033[0;97m'       # White

		# Bold High Intensity
		BIBlack='\033[1;90m'      # Black
		BIRed='\033[1;91m'        # Red
		BIGreen='\033[1;92m'      # Green
		BIYellow='\033[1;93m'     # Yellow
		BIBlue='\033[1;94m'       # Blue
		BIPurple='\033[1;95m'     # Purple
		BICyan='\033[1;96m'       # Cyan
		BIWhite='\033[1;97m'      # White

		# High Intensity backgrounds
		On_IBlack='\033[0;100m'   # Black
		On_IRed='\033[0;101m'     # Red
		On_IGreen='\033[0;102m'   # Green
		On_IYellow='\033[0;103m'  # Yellow
		On_IBlue='\033[0;104m'    # Blue
		On_IPurple='\033[0;105m'  # Purple
		On_ICyan='\033[0;106m'    # Cyan
		On_IWhite='\033[0;107m'   # White
	fi
	
	# Set up some variables and configure things
	if [[ -e /etc/wireguard/wg0.conf ]]; then
		wg_installed="1"
		full_conf_file="$(</etc/wireguard/wg0.conf)"
		# $( printf "%s\n" "$full_conf_file" | command )
		
		local wgconf_version=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# VERSION\s)\b[\d\.]+\b" )
		
		# Detect if wgconf needs updated
		if [[ $wgconf_version -lt $wginst_version ]]; then
			# Insert any commands for upgrading the wg0.conf to newest configuration.
			# For 1.0 I've made the two versions incompatible
			if [[ "$wginst_version" == "1.0" ]]; then
				echo \
"The exsiting wg0.conf is incompatible with this installer. Recommend
you backup old configuration, uninstall wireguard and re-run this script."
				exit
			fi
		fi
		
		local list_of_client_names=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# BEGIN_PEER\s)\b\w+\b$" )
		local list_of_used_octets=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# OCTET\s)\b\d{1,3}\b$" )
		local list_of_pubkeys=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=PublicKey\s=\s)\b.+\b$" )
		
		local list_free_octets=$( printf "%s\n" "${wg_free_octets[@]}" | grep -vwF "${list_of_used_octets}" )
		wg_num_clients=$( wc -l <<< "${list_of_client_names}" )
		
		### ARRAY
		local SAVEIFS=$IFS
		IFS=$'\n'
		wg_free_octets=(${list_free_octets})
		
		wg_used_octets=("" ${list_of_used_octets})
		wg_clients_array=("" ${list_of_client_names})
		wg_pubkeys_array=("" ${list_of_pubkeys})
		
		# 0th entry is blank to allow 1-1 for picking names.
		# All arrays unsorted so they correspond exactly.
		IFS=$SAVEIFS
		### END ARRAY
		
		wg_endpoint=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# ENDPOINT\s)[\w\-:\.]+\b" )
		wg_port=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# PORT\s)[\d]+\b$" )
		wg_ipv4=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# IPV4\s)[\d\.]+\b$" )
		wg_ipv6=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# IPV6\s)[\w:-]+$" )
		wg_ipv6_enabled=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# IPV6EN\s)\d\b$" )
		wg_privkey=$( printf "%s\n" "$full_conf_file" | grep -oP "(?<=# PRIVKEY\s).+$" )
		wg_pubkey=$( wg pubkey <<< "$wg_privkey" )
		
		wg_ipv4_range=$( cut -d"." -f1-3 <<< "$wg_ipv4" )
		wg_ipv4_cidr="${wg_ipv4_range}.0/24"
		wg_ipv6_range=$( sed 's/:[^:]*$//' <<< "$wg_ipv6" )
		wg_ipv6_cidr="${wg_ipv6_range}:0/64"
		
		if systemctl is-active --quiet wg-quick@wg0.service; then wg_active="1"; fi
	fi
	
}
	# END_FUNC: INITIAL_SETUP


	# BEGIN_FUNC: PRINT_COLOR
print_color () {
	local pc_output=""
	for arg in "$@"; do
		pc_output="${pc_output}${arg}"
	done
	pc_output="${pc_output}${Color_Off}"
	echo -e "${pc_output}"
}
	# END_FUNC: PRINT_COLOR



#	=============================================
#			CLIENT FUNCTIONS
#	=============================================

	# BEGIN_FUNC: NEW_CLIENT_NAME
new_client_name () {
	local default_name="client_${peer_octet}"
	local unsanitized_client
	local name_prompt="Please provide a name for the client"
	local repl="[^a-z0-9]"
	
	if [[ $wg_num_clients -gt 0 ]]; then
		echo "The following clients are already present on the system:"
		echo "${wg_client_names}"
	else
		name_prompt="Please provide a name for the first client"
	fi
	
	until [[ -n "${unsanitized_client}" && ! "${list_of_client_names}" =~ "${unsanitized_client}" ]]; do
		[[ -n "${unsanitized_client}" ]] && echo "$unsanitized_client: name already exists."
		read -p "${name_prompt} [${default_name}]: " unsanitized_client
		: ${unsanitized_client:="${default_name}"}
		# Allow a limited length and set of characters to avoid conflicts
		unsanitized_client="${unsanitized_client,,}"
		unsanitized_client="${unsanitized_client::15}"
		unsanitized_client="${unsanitized_client//$repl/_}"
		#client=$(sed 's/[^\w-]/_/g' <<< "$unsanitized_client" | cut -c-15)
	done
	peer_name="${unsanitized_client}"
}
	# END_FUNC: NEW_CLIENT_NAME


	# BEGIN_FUNC: NEW_CLIENT_DNS
new_client_dns () {
	# Get the DNS entries out of the right resolv.conf
	# We pull entries that match our regex from either file, /etc preferred
	# Needed for systems running systemd-resolved
	local nsips_regex="(?<=^nameserver\s)(?!127\.)$rex_ipv4$"
	local csr_dns=$(grep -ioP "$nsips_regex" "/etc/resolv.conf")
	: ${csr_dns:=$(grep -ioP "$nsips_regex" "/run/systemd/resolve/resolv.conf")}
	# Split the nameservers by commas
	csr_dns="${csr_dns//$'\n'/, }"
	
	# Old way of doing it...
	#local csr_dns=$(grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -v '127.0.0.53' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | xargs | sed -e 's/ /, /g')
	
	local provider_array=(
		""
		"Current system resolvers"
		"Google"
		"Cloudflare"
		"OpenDNS"
		"Quad9"
		"Adguard"
	)
	local dns_array=(
		""
		"${csr_dns}"
		"8.8.8.8, 8.8.4.4"
		"1.1.1.1, 1.0.0.1"
		"208.67.222.222, 208.67.220.220"
		"9.9.9.9, 149.112.112.112"
		"94.140.14.14, 94.140.15.15"
	)
	local print_string
	local print_array=()
	
	for i in {1..6}; do
		print_array[i]=$( printf "%-27s(%s)\n" "${provider_array[i]}" "${dns_array[i]}" )
	done
	print_string=$( printf "%s\n" "${print_array[@]}" )
	
	# 27 characters for the provider name - "%-27s(%s)\n" "${provider_array[i]}" "${dns_array[i]}" - first var has 27 characters of spacing, second var in ()
	echo
	echo "   Select a DNS server for the client:"
	echo
	nl -s ') ' <<< "$print_string"
	echo; echo
	echo "     c) Custom"
	echo
	local dns_pick
	read -p "DNS server [1]: " dns_pick
	: ${dns_pick:="1"}
	until [[ "$dns_pick" =~ ^[1-6c]$ ]]; do
		echo
		echo "$dns_pick: invalid selection."
		read -p "DNS server [1]: " dns_pick
		: ${dns_pick:="1"}
	done
	echo
	if [[ "$dns_pick" == "c" ]]; then
		local dns_regex="^$rex_ipv4(, $rex_ipv4)*$"
		echo "Please enter a list of one or more DNS servers to use, separated by commas."
		echo "E.g. '8.8.8.8, 8.8.4.4'"
		echo
		read -p "DNS: " unsan_dns
		until [[ "${unsan_dns}" =~ $dns_regex ]]; do
			echo "$unsan_dns: Invalid DNS entry."
			read -p "DNS: " unsan_dns
		done
		dns_pick="0"
		dns_array[0]="${unsan_dns}"
	fi
	peer_dns="${dns_array[dns_pick]}"
}
	# END_FUNC: NEW_CLIENT_DNS


	# BEGIN_FUNC: NEW_CLIENT_PORT
new_client_port () {
	local port_input
	
	echo "By default, a client will listen through a random port number. However,"
	echo "some network setups require that the client use a fixed port number."
	echo
	echo "What port should the client listen on?  (r=Random)"
	echo
	until [[ "$port_input" == "r" ]] || [[ $port_input =~ ^[0-9]+$ && $port_input -gt 1024 && $port_input -le 65535 ]]; do
		[[ -n $port_input ]] && echo "$port_input: invalid port."
		read -p "Client Port [r]: " port_input
		: ${port_input:="r"}
	done
	
	peer_port="$port_input"	
}
	# END_FUNC: NEW_CLIENT_PORT


	# BEGIN_FUNC: NEW_CLIENT_SETUP
new_client_setup () {
	# Set up the new client entry in wg0 and make config files
	
	local peer_ipv4="${wg_ipv4_range}.${peer_octet}"
	local peer_ipv6="${wg_ipv6_range}:${peer_octet}"
	
	local peer_privkey=$(wg genkey)
	local peer_psk=$(wg genpsk)
	peer_pubkey=$(wg pubkey <<< "${peer_privkey}")
	
	local aip_str_1="${peer_ipv4}/32"
	local addr_str_1="${peer_ipv4}/24"
	if [[ "${wg_ipv6_enabled}" == "1" ]]; then
		local aip_str_2=", ${peer_ipv6}/128"
		local addr_str_2=", ${peer_ipv6}/64"
	fi
	
	local allowed_ips="${aip_str_1}${aip_str_2}"
	local addr_string="${addr_str_1}${addr_str_2}"
	# Configure client in the server
	local w0conf_peer_string="
# BEGIN_PEER ${peer_name}
# OCTET ${peer_octet}
[Peer]
PublicKey = ${peer_pubkey}
PresharedKey = ${peer_psk}
AllowedIPs = ${allowed_ips}
# END_PEER ${peer_name}
"
	printf "%s\n" "$w0conf_peer_string" >> /etc/wireguard/wg0.conf
	
	# Create client configuration
	# grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
	
	cat << EOF > /etc/wireguard/clients/"$peer_name".conf
[Interface]
Address = ${addr_string}
DNS = ${peer_dns}
PrivateKey = ${peer_privkey}
$([[ "$peer_port" != "r" ]] && echo "ListenPort = ${peer_port}")

[Peer]
PublicKey = ${wg_pubkey}
PresharedKey = ${peer_psk}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${wg_endpoint}:${wg_port}
PersistentKeepalive = 25
EOF
	
	if [[ "$wg_active" == "1" ]]; then
		wg addconf wg0 <(printf "%s\n" "$w0conf_peer_string")
	fi
}
	# END_FUNC: NEW_CLIENT_SETUP


	# END_FUNC: ADD_NEW_CLIENT
add_new_client () {
	# Take the first octet in the list of free octets
	peer_octet="${wg_free_octets[0]}"
	
	new_client_name
	# peer_name
	echo
	
	new_client_dns
	# peer_dns
	echo
	
	new_client_port
	# peer_port
	echo
	
	new_client_setup
	
	
	
	echo
	qrencode -t PNG -o /etc/wireguard/clients/"$peer_name".png < /etc/wireguard/clients/"$peer_name".conf
	qrencode -t ANSI256UTF8 < /etc/wireguard/clients/"$peer_name.conf"
	
	cp /etc/wireguard/clients/"$peer_name".conf $PWD/ > /dev/null 2>&1
	cp /etc/wireguard/clients/"$peer_name".png $PWD/"$peer_name".png > /dev/null 2>&1
	chown --silent --reference $PWD -R $PWD/"$peer_name".conf
	chown --silent --reference $PWD -R $PWD/"$peer_name".png
	echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
	echo
	echo "$peer_name added. Configuration and QR code PNG are in the current directory as: $peer_name.conf and $peer_name.png"
	echo "Backup copies of $peer_name.conf and $peer_name.png (the QR code) are located in /etc/wireguard/clients"
	
	### ARRAY
	local SAVEIFS=$IFS
	IFS=$'\n'
	wg_free_octets=("${wg_free_octets[@]:1}") # remove the first array entry from free octets
	((wg_num_clients++)) # Increase number of clients by one
	wg_clients_array+=("$peer_name") # Add peer name to end of client array
	wg_used_octets+=("$peer_octet") # Add peer octet to end of octet array
	wg_pubkeys_array+=("$peer_pubkey") # Add peer pubkey to end of pubkey array
	
	IFS=$SAVEIFS
	### END ARRAY
	
	unset peer_name
	unset peer_dns
	unset peer_octet
	unset peer_pubkey
	unset peer_port
	return
}
	# END_FUNC: ADD_NEW_CLIENT


	# BEGIN_FUNC: REMOVE_CLIENT
remove_client () {
	
	# wg_clients_array
	local client_number
	local client
	local pubkey
	local octet
	local remove_confirm
	local remove_message="removal aborted!"

	### ARRAY
	local SAVEIFS=$IFS
	IFS=$'\n'
	
	# No extra space because of blank in array list
	echo "Select the client to remove:"
	nl -s ') ' <<< "${wg_clients_array[@]}"
	echo
	read -p "Client: " client_number
	until [[ "$client_number" =~ ^[0-9]+$ && $client_number -le $wg_num_clients ]]; do
		echo "$client_number: invalid selection."
		read -p "Client: " client_number
	done
	# We have a number selected
	
	client="${wg_clients_array[client_number]}"
	pubkey="${wg_pubkeys_array[client_number]}"
	octet="${wg_used_octets[client_number]}"
	# octet may not be used in this function yet but gathering it anyway for convenience
	
	echo
	until [[ "$remove_confirm" =~ ^[yYnN]$ ]]; do
		[[ -n $remove_confirm ]] && echo "$remove_confirm: invalid selection."
		read -p "Confirm $client removal? [y/N]: " remove_confirm
		: ${remove_confirm:="n"}
	done
	if [[ "$remove_confirm" =~ ^[yY]$ ]]; then
		# The following is the right way to avoid disrupting other active connections:
		# old way: "$( sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)"
		# Remove from the live interface by selecting by public key
		if [[ "$wg_active" == "1" ]]; then
			wg set wg0 peer "${pubkey}" remove
		fi
		# Remove from the configuration file
		sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
		
		# Remove from internal arrays
		wg_clients_array=( "${wg_clients_array[@]:0:$((client_number-1))}" "${wg_clients_array[@]:$client_number}" )
		wg_pubkeys_array=( "${wg_pubkeys_array[@]:0:$((client_number-1))}" "${wg_pubkeys_array[@]:$client_number}" )
		wg_used_octets=( "${wg_used_octets[@]:0:$((client_number-1))}" "${wg_used_octets[@]:$client_number}" )
		remove_message="removed!"
		((wg_num_clients--)) # Decrease number of clients by one
	fi
	
	IFS=$SAVEIFS
	echo
	echo "$client ${remove_message}"
	return
}
	# END_FUNC: REMOVE_CLIENT



#	=============================================
#			INSTALL FUNCTIONS
#	=============================================

	# BEGIN_FUNC: CONFIGURE_DOWNLOADER
configure_downloader () {
	# Detect some Debian minimal setups where neither wget nor curl are installed, and set up the download command
	local dlapp
	local wget_args="-T 10 -t 1 -qO-"
	local curl_args="-m 10 -Ls"
	local dl_args="$curl_args"
	
	# The following logic first tests if curl is installed.
	# if not it sets the args for wget and tests if wget is installed
	if ! dlapp=$(command -v curl) && dl_args="$wget_args" && ! dlapp=$(command -v wget) ; then
		echo "Wget is required to use this installer."
		read -n1 -r -p "Press any key to install Wget and continue..."
		if [[ "$wg_os" =~ (fedora|centos) ]]; then dnf install -y wget; else
			apt-get update
			apt-get install -y wget
		fi
		dlapp=$(command -v wget)
	fi
	wg_dlcmd="$dlapp $dl_args"
}
	# END_FUNC: CONFIGURE_DOWNLOADER


	# BEGIN_FUNC: CONFIGURE_ENDPOINT
configure_endpoint () {
	# IP Selection Criteria:
	# No loopbacks.  Prefer internet routable.  User can set custom.
	# 0.x, 10.x, 127.x, 169.254.x, 172.16-31.x, 192.168.x are all not routable.
	local pip_1_oct="1?0" # 0.x and 10.x
	local pip_2_oct="169\.254|192\.168" # 169 and 192
	local pip_172="172\.(1[6789]|2[0-9]|3[01])" # 172.16-172.31
	# Stick all our filters together and we have a discard string
	local pip_discard_string="^(${pip_1_oct}|${pip_2_oct}|${pip_172})\."
	
	# IPv6 Criteria: Prefer GUA (Global Unicast Address) internet routable IPv6.
	# Always start with 2xxx and 3xxx
	
	# First, get all the inet addresses
	local ip_addr_full_output=$(ip addr)
	local ip_addr_inet_full_lines=$(printf "%s\n" "$ip_addr_full_output" | grep -ioP 'inet.*$')
	
	# Now just the inet/inet6 prefix and base address, skipping loopback addresses (scope host)
	local all_inet_ips_nlb=$(printf "%s\n" "$ip_addr_inet_full_lines" | grep -ioP 'inet6?\s[\d\.a-f:]+(?=[\/\s])(?!.*scope host.*$)')
	
	# Populate all IPv4s
	local all_ipv4=$(printf "%s\n" "$all_inet_ips_nlb" | grep -ioP '(?<=^inet\s).+$')
	
	# First, check for inet6 lines, if they exist, ipv6 enabled, so fill ipv6.  If none, ipv6 not enabled, don't use it.
	if [[ "$ip_addr_inet_full_lines" =~ "inet6" ]]; then
		wg_ipv6_enabled="1"
		local all_ipv6=$(printf "%s\n" "$all_inet_ips_nlb" | grep -ioP '(?<=^inet6\s).+$')
		local valid_ipv6=$(printf "%s\n" "$all_ipv6" | grep -iP '^[23][\da-f]{3}:')
	fi
	
	# Now, just because we might not have detected ANY public routable IPv4s, let's get some from the internet too.
	# Possible places to get IPs:
	# https://ipinfo.io/ip - https://ip4only.me/api/ - https://ipgrab.io/ - https://icanhazip.com/ - https://api.ipify.org/ - http://ip1.dynupdate.no-ip.com/
	# We try all of them in parallel, then combine the results, strip duplicates, and prompt the user with that.
	local xdir=$(mktemp -d)
	local url_array=(
	"https://ipinfo.io/ip > $xdir/wg_ipchk_1.tmp"
	"https://ip4only.me/api/ | cut -d ',' -f 2 > $xdir/wg_ipchk_2.tmp"
	"https://ipgrab.io/ > $xdir/wg_ipchk_3.tmp"
	"https://icanhazip.com/ > $xdir/wg_ipchk_4.tmp"
	"https://api.ipify.org/ > $xdir/wg_ipchk_5.tmp"
	"http://ip1.dynupdate.no-ip.com/ > $xdir/wg_ipchk_6.tmp" )
	for url in "${url_array[@]}"; do
		# Check all sites in parallel for our public IP
		eval "${wg_dlcmd} -4 ${url} 2>/dev/null &"
	done
	# We must wait for all of them to return, so if any timed out we get at least one.
	wait
	# Populate an array with the results (and delete our tmp files)
	local ip_array=()
	for i in {1..6}; do ip_array[$i]="$(<$xdir/wg_ipchk_${i}.tmp)"; done
	rm -rf "$xdir"
	all_ipv4=$(printf "%s\n" "${all_ipv4}" "${ip_array[@]}" | sort -u )
	# Now sorted all IPv4s and stripped duplicates
	local valid_ipv4=$(printf "%s\n" "$all_ipv4" | grep -vE "${pip_discard_string}")
	
	# Compile all IPs detected in system
	local all_ips=$(printf "%s\n" "${all_ipv4}" "${all_ipv6}" )
	local count_of_all_ips=$(wc -w <<< "${all_ips}")
	
	# Compile all valid (internet-routable) IPs
	local valid_ips=$( printf "%s\n" "${valid_ipv4}" "${valid_ipv6}" )
	local count_of_valid_ips=$(wc -w <<< "${valid_ips}")
	
	# Now to ask the user what to use.  We'll build a few strings for our prompts.
	
	local valid_prefix="Multiple"; local valid_addr="addresses were"
	local ip_list="${valid_ips}"; local ip_count="${count_of_valid_ips}"
	
	# Form our message to the user
	case "$count_of_valid_ips" in
		0 )
			ip_list="${all_ips}"; ip_count="${count_of_all_ips}"
			valid_prefix="No"
			local all_prefix="Multiple"; local all_addr="addresses were"
			case "$count_of_all_ips" in
				0 )
					all_prefix="No"
				;;
				1 )
					all_prefix="One"
					all_addr="address was"
				;;
			esac
			local all_string="${all_prefix} local IP ${all_addr} detected."
		;;
		1 )
			valid_prefix="One"
			valid_addr="address was"
		;;
	esac
	
	local valid_string="${valid_prefix} valid Internet-accessible IP ${valid_addr} detected."
	local full_string="$( printf "%s\n" "${valid_string}" "${all_string}" )"
	
	local accepted_input="c"
	local default_input="c"
	local ip_choice
	### ARRAY
	ip_array=("" "${ip_list}") # Array of IPs for choice with 0 pre-filled so 1=1
	
	# Ask what endpoint address to use
	printf "%s\n\n%s\n\n" "${full_string}" "   What endpoint address should clients use to connect?"
	if [[ $ip_count -gt 0 ]]; then
		nl -s ') ' <<< "$ip_list"
		default_input="1"
		echo; echo;
	fi
	for ((i=0;i<=ip_count;i++)); do accepted_input+="${i}"; done
	echo "     c) Custom"
	echo "     0) Abort Installation and Exit"
	echo
	
	until [[ -n "$ip_choice" && "$ip_choice" =~ [$accepted_input]$ ]]; do
		[[ -n "$ip_choice" ]] && echo "${ip_choice}: Invalid choice."
		read -p "Endpoint [${default_input}]: " ip_choice
		: ${ip_choice:="${default_input}"}
	done
	
	case "$ip_choice" in
		0 )
			echo "Installation aborted!"
			exit
		;;
		"c" ) 
			local ips_regex="^(${rex_ipv4})|(${rex_ipv6})$"
			echo "Please enter an endpoint address as either a valid IPv4 or IPv6 address, or an FQDN."
			read -p "Endpoint Address: " wg_endpoint
			wg_endpoint=${wg_endpoint,,}
			until [[ "$wg_endpoint" =~ $ips_regex  ]] || grep -qiP "$rex_fqdn" <<< "$wg_endpoint"; do
				echo "${wg_endpoint}: invalid endpoint address."
				read -p "Endpoint Address: " wg_endpoint
				wg_endpoint=${wg_endpoint,,}
			done
		;;
		* )
			wg_endpoint="${ip_array[ip_choice]}"
		;;
	esac
}
	# END_FUNC: CONFIGURE_ENDPOINT


	# BEGIN_FUNC: CONFIGURE_WGPORT
configure_wgport () {
	local portregex="^[0-9]+$"
	echo "What external port should WireGuard listen to?"
	read -p "Port [${wginst_port_default}]: " wg_port
	: ${wg_port:="${wginst_port_default}"}
	until [[ "$wg_port" =~ $portregex && $wg_port -le 65535 ]]; do
		echo "$wg_port: invalid port."
		read -p "Port [${wginst_port_default}]: " wg_port
		: ${wg_port:="${wginst_port_default}"}
	done
}
	# END_FUNC: CONFIGURE_WGPORT


	# BEGIN_FUNC: CONFIGURE_WGVPNIP
configure_wgvpnip () {
	local oct="\.(25[0-5]|(2[0-4]|1[0-9]|[1-9]|)[0-9])"
	local classA="10$oct"
	local classB="172\.(1[6789]|2[0-9]|3[01])"
	local classC="192\.168"
	local vpn_reg="^($classA|$classB|$classC)$oct\.1$"
	
	echo "Wireguard uses an internal IPv4 address for the VPN network, ending in .1"
	echo "This installer will accept any 10.x.x.1, 172.16-31.x.1, or 192.168.x.1 IP."
	echo "What VPN (internal) IPv4 address should WireGuard use?"
	read -p "VPN IPv4 Address [${wginst_ipv4_default}]: " wg_ipv4
	: ${wg_ipv4:=${wginst_ipv4_default}}
	until [[ "$wg_ipv4" =~ $vpn_reg ]]; do
		echo "$wg_ipv4: invalid VPN IPv4 address."
		read -p "VPN IPv4 Address [${wginst_ipv4_default}]: " wg_ipv4
		: ${wg_ipv4:=${wginst_ipv4_default}}
	done
	
	# Set IPv6 VPN address even if it's not used - for consistency
	wg_ipv6="${wginst_ipv6_default}"
	
	# Configure IP vars based on what we got
	wg_ipv4_range=$( cut -d"." -f1-3 <<< "$wg_ipv4" )
	wg_ipv4_cidr="${wg_ipv4_range}.0/24"
	# IPv6 numbers can be extrapolated even if we're not going to use them.
	# If we end up doing something more with them (let user pick etc) they're defined here already
	wg_ipv6_range=$( sed 's/:[^:]*$//' <<< "$wg_ipv6" )
	wg_ipv6_cidr="${wg_ipv6_range}:0/64"
	
}
	# END_FUNC: CONFIGURE_WGVPNIP


	# BEGIN_FUNC: CONFIGURE_BTUN_UPDATE
configure_btun_update () {
	# Set up automatic updates for BoringTun if the user is fine with that
	if [[ -n "$wg_use_boringtun" ]]; then
		echo "BoringTun will be installed to set up WireGuard in the system."
		read -p "Should automatic updates be enabled for it? [Y/n]: " wg_btun_updates
		: ${wg_btun_updates:="y"}
		until [[ "${wg_btun_updates,,}" =~ ^(y(es)?|no?)$ ]]; do
			echo "$wg_btun_updates: invalid selection."
			read -p "Should automatic updates be enabled for it? [Y/n]: " wg_btun_updates
			: ${wg_btun_updates:="y"}
		done
	fi
}
	# END_FUNC: CONFIGURE_BTUN_UPDATE


	# BEGIN_FUNC: CHECK_FIREWALL
check_firewall () {
	# We should install a firewall if firewalld or iptables are not already available/active.
	# If they are installed, we should still apply update through apt-get to ensure security.
	# Install a firewall if firewalld or iptables are not already available
	if systemctl is-active --quiet firewalld.service; then
		wg_firewall="firewalld"
	elif hash iptables 2>/dev/null || [[ "$wg_os" == "debian" || "$wg_os" == "ubuntu" ]]; then
		wg_firewall="iptables"
	else
		#if [[ "$wg_os" == "centos" || "$wg_os" == "fedora" ]]; then
		wg_firewall="firewalld"
		# We don't want to silently enable firewalld, so we give a subtle warning
		# If the user continues, firewalld will be installed and enabled during setup
		echo "firewalld, which is required to manage routing tables, will also be installed."
	fi
}	
	# END_FUNC: CHECK_FIREWALL


	# BEGIN_FUNC: INSTALL_BORINGTUN
install_boringtun () {
	# Grab the BoringTun binary using wget or curl and extract into the right place.
	# Don't use this service elsewhere without permission! Contact me before you do!
	local dl_url="https://wg.nyr.be/1/latest/download"
	local ck_url="https://wg.nyr.be/1/latest"
	
	$wg_dlcmd "$dl_url" 2>/dev/null | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
	
	#{ wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
	# Configure wg-quick to use BoringTun
	mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
	echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
	if [[ "$wg_btun_updates" =~ ^[y]$ ]]; then
		# Deploy upgrade script
		cat << 'EOF' > $wginst_dir/wg-boringtun-upgrade.sh
#!/bin/bash
latest=$( $wg_dlcmd "${ck_url}" 2>/dev/null )
# If server did not provide an appropriate response, exit
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable"
	exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	xdir=$(mktemp -d)
	# If download and extraction are successful, upgrade the boringtun binary
	if $wg_dlcmd "${dl_url}" 2>/dev/null | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
		systemctl stop wg-quick@wg0.service
		rm -f /usr/local/sbin/boringtun
		mv "$xdir"/boringtun /usr/local/sbin/boringtun
		systemctl start wg-quick@wg0.service
		echo "Succesfully updated to $(/usr/local/sbin/boringtun -V)"
	else
		echo "boringtun update failed"
	fi
	rm -rf "$xdir"
else
	echo "$current is up to date"
fi
EOF
		# Set up service file
		cat << EOF > /etc/systemd/system/boringtun-upgrade.service
[Unit]
Description=Upgrade check for boringtun

[Service]
Type=oneshot
ExecStart=${wginst_dir}/wg-boringtun-upgrade.sh
WorkingDirectory=/root/
EOF
		# And Timer
		cat << EOF > /etc/systemd/system/boringtun-upgrade.timer
[Unit]
Description=BoringTun-Upgrade

[Timer]
OnCalendar=Mon *-*-* 03:00:00
RandomizedDelaySec=3h
Persistent=true

[Install]
WantedBy=timers.target
EOF
		chmod 644 /etc/systemd/system/boringtun-upgrade.service
		chmod 644 /etc/systemd/system/boringtun-upgrade.timer
		chmod 744 $wginst_dir/boringtun-upgrade
		# Timer is set to run every monday between 3:00 and 6:00 randomized
		systemctl enable boringtun-upgrade.timer && systemctl start boringtun-upgrade.timer
	fi
}
	# END_FUNC: INSTALL_BORINGTUN


	# BEGIN_FUNC: INSTALL_PACKAGES
install_packages () {
	local deb_pack="wireguard"
	local cenfed_pack="wireguard-tools qrencode ca-certificates tar ${wg_firewall}"
	
	# if using BoringTun, install wg-tools without recommended packages for deb/ubu
	[[ -n "$wg_use_boringtun" ]] && deb_pack="wireguard-tools --no-install-recommends"
	
	# Install all packages as configured.
	case "$wg_os" in
		"ubuntu" )
			# Ubuntu
			apt-get update
			apt-get install -y qrencode ca-certificates $wg_firewall
			apt-get install -y $deb_pack
		;;
		"debian" )
			# Debian
			apt-get update
			apt-get install -y qrencode ca-certificates $wg_firewall
			apt-get install -y $deb_pack
		;;
		"centos" )
			# CentOS
			dnf install -y epel-release
			dnf install -y $cenfed_pack
		;;
		"fedora" )
			# Fedora Linux
			dnf install -y $cenfed_pack
			mkdir -p /etc/wireguard/
		;;
	esac
	
	# Install BoringTun if it's needed
	[[ -n "$wg_use_boringtun" ]] && install_boringtun
}
	# END_FUNC: INSTALL_PACKAGES


	# BEGIN_FUNC: GENERATE_FILES
generate_files () {
	local addr_string="${wg_ipv4}/24"
	[[ "$wg_ipv6_enabled" == "1" ]] && addr_string+=", ${wg_ipv6}/64"
	# Generate a private key
	wg_privkey=$(wg genkey)
	
	# Make a directory to store client backups in
	mkdir /etc/wireguard/clients
	
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# VERSION ${wginst_version}
# ENDPOINT ${wg_endpoint}
# PORT ${wg_port}
# IPV4 ${wg_ipv4}
# IPV6 ${wg_ipv6}
# IPV6EN ${wg_ipv6_enabled}
# PRIVKEY ${wg_privkey}

[Interface]
Address = ${addr_string}
PrivateKey = ${wg_privkey}
ListenPort = ${wg_port}
PreUp = ${wginst_dir}/wg0-preup.sh
PostUp = ${wginst_dir}/wg0-postup.sh
PreDown = ${wginst_dir}/wg0-predown.sh
PostDown = ${wginst_dir}/wg0-postdown.sh

EOF
	chown root:root /etc/wireguard/wg0.conf
	chmod 600 /etc/wireguard/wg0.conf
	
	cat << EOF > $wginst_dir/wg0-preup.sh
#! /bin/bash

# Do not alter any code between === signs
# =======================================
${wginst_dir}/fw-up.sh
# =======================================
# Below this point add any code you wish

EOF
	
	cat << EOF > $wginst_dir/wg0-postup.sh
#! /bin/bash

# Do not alter any code between === signs
# =======================================
# This space reserved for future code
# =======================================
# Below this point add any code you wish

EOF
	
	# No changes for postup-predown, so copy it
	cp $wginst_dir/wg0-postup.sh $wginst_dir/wg0-predown.sh
	
	cat << EOF > $wginst_dir/wg0-postdown.sh
#! /bin/bash

# Do not alter any code between === signs
# =======================================
${wginst_dir}/fw-down.sh
# =======================================
# Below this point add any code you wish

EOF
	
	cat << EOF > $wginst_dir/fw-up.sh
#! /bin/bash

# Do not alter the contents of this file

EOF

	cp $wginst_dir/fw-up.sh $wginst_dir/fw-down.sh
	chown root:root $wginst_dir/*.sh
	chmod 744 $wginst_dir/*.sh
	
}
	# END_FUNC: GENERATE_FILES


	# BEGIN_FUNC: SETUP_FIREWALL
setup_firewall () {
	# Enable IP Forwarding
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ "$wg_ipv6_enabled" == "1" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
		# Enable without waiting for a reboot or service restart
		echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
	fi
	
	# Instead of setting rules which must be remembered and re-referenced later, we should just
	# use the Pre-Up and Post-Down scripts to add the rules on interface up, and remove on down.
	# Then when it comes time to uninstall, we start by stopping the wg-quick service which will
	# bring the interface down and remove the rules for us.

	# Firewalld
	if [[ "$wg_firewall" == "firewalld" ]]; then
		# Firewalld
		# Since firewalld masquerade is not based on source, we need a bit of logic first
		if systemctl is-active --quiet firewalld.service && ! firewall-cmd -q --zone=public --query-masquerade ; then
			# masquerade is NOT already enabled so remove it on down
			local rem_masq="1"
		fi
		# IPv4 Firewalld
		# Up
		cat << EOF >> $wginst_dir/fw-up.sh
firewall-cmd -q --zone=public --add-masquerade
firewall-cmd -q --zone=public --add-port="${wg_port}/udp"
firewall-cmd -q --zone=trusted --add-source="${wg_ipv4_cidr}"
firewall-cmd -q --zone=trusted --add-rich-rule='rule family="ipv4" source address="${wg_ipv4_cidr}" destination not address="${wg_ipv4_cidr}" masquerade'

EOF
		# Down
		cat << EOF >> $wginst_dir/fw-down.sh
firewall-cmd -q --zone=trusted --remove-rich-rule='rule family="ipv4" source address="${wg_ipv4_cidr}" destination not address="${wg_ipv4_cidr}" masquerade'
firewall-cmd -q --zone=trusted --remove-source="${wg_ipv4_cidr}"
firewall-cmd -q --zone=public --remove-port="${wg_port}/udp"

EOF
		# End
		if [[ "$wg_ipv6_enabled" == "1" ]]; then
			# IPv6 Firewalld
			# Up
			cat << EOF >> $wginst_dir/fw-up.sh
firewall-cmd --zone=trusted --add-source="${wg_ipv6_cidr}"
firewall-cmd --zone=trusted --add-rich-rule='rule family="ipv6" source address="${wg_ipv6_cidr}" destination not address="${wg_ipv6_cidr}" masquerade'

EOF
			# Down
			cat << EOF >> $wginst_dir/fw-down.sh
firewall-cmd -q --zone=trusted --remove-rich-rule='rule family="ipv6" source address="${wg_ipv6_cidr}" destination not address="${wg_ipv6_cidr}" masquerade'
firewall-cmd -q --zone=trusted --remove-source="${wg_ipv6_cidr}"

EOF
			# End
		fi
		# Masquerade Logic
		[[ -n "$rem_masq" ]] && printf "%s\n\n" "firewall-cmd -q --zone=public --remove-masquerade" >> $wginst_dir/fw-down.sh
	else
		# IPTables
		local path_iptables=$(command -v iptables)
		local path_ip6tables=$(command -v ip6tables)
		
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			path_iptables=$(command -v iptables-legacy)
			path_ip6tables=$(command -v ip6tables-legacy)
		fi
		
		# IPv4 IPTables
		# Up
		cat << EOF >> $wginst_dir/fw-up.sh
${path_iptables} -t nat -A POSTROUTING -s "${wg_ipv4_cidr}" ! -d "${wg_ipv4_cidr}" -j SNAT --to "${wg_ipv4}"
${path_iptables} -I INPUT -p udp --dport "${port}" -j ACCEPT
${path_iptables} -I FORWARD -s "${wg_ipv4_cidr}" -j ACCEPT
${path_iptables} -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

EOF
		# Down
		cat << EOF >> $wginst_dir/fw-down.sh
${path_iptables} -t nat -D POSTROUTING -s "${wg_ipv4_cidr}" ! -d "${wg_ipv4_cidr}" -j SNAT --to "${wg_ipv4}"
${path_iptables} -D INPUT -p udp --dport "${port}" -j ACCEPT
${path_iptables} -D FORWARD -s "${wg_ipv4_cidr}" -j ACCEPT
${path_iptables} -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

EOF
		# End
		if [[ "$wg_ipv6_enabled" == "1" ]]; then
			# IPv6 IPTables
			# Up
			cat << EOF >> $wginst_dir/fw-up.sh
${path_ip6tables} -t nat -A POSTROUTING -s "{wg_ipv6_cidr}" ! -d "{wg_ipv6_cidr}" -j SNAT --to "${wg_ipv6}"
${path_ip6tables} -I FORWARD -s "{wg_ipv6_cidr}" -j ACCEPT
${path_ip6tables} -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

EOF
			# Down
			cat << EOF >> $wginst_dir/fw-down.sh
${path_ip6tables} -t nat -D POSTROUTING -s "{wg_ipv6_cidr}" ! -d "{wg_ipv6_cidr}" -j SNAT --to "${wg_ipv6}"
${path_ip6tables} -D FORWARD -s "{wg_ipv6_cidr}" -j ACCEPT
${path_ip6tables} -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

EOF
			# End
		fi
	fi
}
	# END_FUNC: SETUP_FIREWALL


	# BEGIN_FUNC: INSTALL_WIREGUARD
install_wireguard () {
	
	# Detect downloader and set up
	configure_downloader
	# wg_dlcmd
	
	clear
	echo 'Preparing WireGuard RoadWarrior Installation.'
	echo
	
	configure_endpoint
	# wg_endpoint
	# wg_ipv6_enabled
	echo
	
	configure_wgport
	# wg_port
	echo
	
	configure_wgvpnip
	# wg_ipv4
	# wg_ipv6
	echo
	
	configure_btun_update
	# wg_btun_updates
	echo
	
	echo "WireGuard installation is ready to begin."
	
	check_firewall
	# wg_firewall
	
	read -n1 -r -p "Press any key to continue..."
	
	# Make our dir for scripts
	mkdir $wginst_dir
	
	# Install All Packages
	install_packages
	
	# If firewalld was just installed, enable it
	if [[ "$wg_firewall" == "firewalld" ]] && ! systemctl is-active --quiet firewalld.service; then
		systemctl enable --now firewalld.service
	fi
	
	# Generate wg0.conf and script files
	generate_files
	
	# Set Up Firewall & Forwarding
	setup_firewall
	echo
	
	echo "Finished installing software. Now, we'll set up your first client."
	echo
	
	# Add First Client
	add_new_client
	echo
	
	# Enable and start the wg-quick service
	systemctl enable --now wg-quick@wg0.service
	wg_active="1"
	wg_installed="1"
	
	echo
	echo "Installation Finished!"
	echo "Firewall and interface up/down scripts are located in $wginst_dir/"
	return
}
	# END_FUNC: INSTALL_WIREGUARD



#	=============================================
#			UNINSTALL FUNCTIONS
#	=============================================

	# BEGIN_FUNC: UNINSTALL_WIREGUARD
uninstall_wireguard () {
	# Code
	local remove_confirm
	read -p "Confirm WireGuard removal? [y/N]: " remove_confirm
	: ${remove_confirm:="n"}
	until [[ "${remove_confirm,,}" =~ ^(y(es)?|no?)$ ]]; do
		echo "$remove_confirm: invalid selection."
		read -p "Confirm WireGuard removal? [y/N]: " remove_confirm
	done
	if [[ "${remove_confirm,,}" =~ ^y ]]; then
		systemctl disable --now wg-quick@wg0.service > /dev/null 2>&1
		systemctl disable --now boringtun-upgrade.timer > /dev/null 2>&1
		systemctl disable --now boringtun-upgrade.service > /dev/null 2>&1
		rm -rf /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
		rm -f /etc/systemd/system/boringtun-upgrade.service
		rm -f /etc/systemd/system/boringtun-upgrade.timer
		
		if [[ "$wg_os" == "ubuntu" ]]; then
			# Ubuntu
			apt-get remove --purge -y wireguard wireguard-tools
		elif [[ "$wg_os" == "debian" ]]; then
			# Debian
			apt-get remove --purge -y wireguard wireguard-tools
		elif [[ "$wg_os" == "centos" ]]; then
			# CentOS
			dnf remove -y wireguard-tools
		elif [[ "$wg_os" == "fedora" ]]; then
			# Fedora
			dnf remove -y wireguard-tools
		fi
		
		rm -f /usr/local/sbin/boringtun /usr/local/sbin/boringtun-upgrade
		rm -rf "${wginst_dir}"
		rm -rf /etc/wireguard/
		
		echo
		echo "WireGuard removed!"
		echo "The script will now exit"
		exit
	fi
	echo
	echo "WireGuard removal aborted!"
	return
}
	# END_FUNC: UNINSTALL_WIREGUARD



#	=============================================
#			MENU FUNCTIONS
#	=============================================

	# BEGIN_FUNC: DISPLAY_MENU
display_menu () {
	local Title_Name=" Wireguard RoadWarrior Utility "
	local Box_Head="==============================="
	local Title_String="${Box_Head}\n   ${Title_Name}\n   ${Box_Head}"
	local Install_Head=" Wireguard Installation Status "
	local Install_String
	local Install_Color
	local Allowed_Results="0"
	
	echo "$wg_ipv6_range"
	
	print_color "   ${Yellow}${On_Black}" "${Title_String}"
	echo
	if [[ $wg_installed -eq 1 ]]; then
		# Installed, use green text and 11 spaces before
		Install_Color="           ${Green}"
	else
		# Not Installed, use red text and 9 spaces before
		Install_Color="         ${Red}NOT "
	fi
	Install_String="${Box_Head}\n   ${Install_Head}\n   ${Install_Color}INSTALLED"
	print_color "   ${Yellow}${On_Black}" "${Install_String}"
	print_color "   ${Yellow}${On_Black}" "${Box_Head}"
	echo
	echo "   Choose an Option:"
	echo
	if [[ $wg_installed -ne 1 ]]; then
		print_color "     ${Green}${On_Black}" "1) Install Wireguard"
		Allowed_Results="${Allowed_Results}1"
	else
		if [[ $wg_num_clients -lt 253 ]]; then
			print_color "     ${Green}${On_Black}" "2) Create New Client"
			Allowed_Results="${Allowed_Results}2"
		fi
		if [[ $wg_num_clients -gt 0 ]]; then
			print_color "     ${Green}${On_Black}" "3) Remove an existing client"
			Allowed_Results="${Allowed_Results}3"
		fi
		echo
		print_color "     ${Red}${On_Black}" "8) Uninstall Wireguard"
		Allowed_Results="${Allowed_Results}8"
	fi
	echo
	echo
	echo "     0) Exit"
	echo

	read -p "Option: " option
	
	until [[ "$option" =~ ^[$Allowed_Results]$ ]]; do
		echo
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	echo
	
	case "$option" in
		1 )
			install_wireguard
		;;
		2 )
			add_new_client
		;;
		3 )
			remove_client
		;;
		8 )
			uninstall_wireguard
		;;
		0 )
			exit
		;;
	esac
	echo
	read -n1 -r -p "Press any key to return to the main menu..."
}
	# END_FUNC: DISPLAY_MENU



#	=============================================
#			RUN CODE
#	=============================================

detect_blockers
initial_setup
while true; do
	display_menu
done
exit