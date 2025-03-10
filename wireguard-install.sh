#!/bin/bash

# Check if WireGuard is already installed
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    # Check if yq is installed
    if ! command -v yq &> /dev/null; then
        echo "Error: 'yq' is required to parse the YAML configuration file."
        echo "Please install it (e.g., 'sudo snap install yq' on Ubuntu or download from https://github.com/mikefarah/yq)."
        exit 1
    fi

    # Ensure config.yaml exists
    if [[ ! -f config.yaml ]]; then
        echo "Error: 'config.yaml' not found in the current directory."
        exit 1
    fi

    # Read server configuration from YAML
    port=$(yq e '.server.port' config.yaml)
    mtu=$(yq e '.server.mtu' config.yaml)
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)

    # Read IPv4 configuration
    ipv4_enabled=$(yq e '.server.ipv4.enabled' config.yaml)
    if [[ "$ipv4_enabled" == "true" ]]; then
        server_ipv4=$(yq e '.server.ipv4.address' config.yaml)
        server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
        server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
        base_ipv4=$(echo "$server_ipv4_ip" | sed 's/\.[0-9]*$//')
    else
        echo "Error: IPv4 must be enabled for the server."
        exit 1
    fi

    # Read IPv6 configuration
    ipv6_enabled=$(yq e '.server.ipv6.enabled' config.yaml)
    if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
        server_ipv6=$(yq e '.server.ipv6.address' config.yaml)
        server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
        server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
        base_ipv6=$(echo "$server_ipv6_ip" | sed 's/::[0-9]*$/::/')
    fi

    # Generate server private key
    server_private_key=$(wg genkey)
    server_public_key=$(echo "$server_private_key" | wg pubkey)

    # Create wg0.conf with server configuration
    cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT will be set later by the script

[Interface]
Address = $server_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $server_ipv6" )
PrivateKey = $server_private_key
ListenPort = $port
$( [[ "$mtu" != "null" && -n "$mtu" ]] && echo "MTU = $mtu" )
EOF
    chmod 600 /etc/wireguard/wg0.conf

    # Read and configure clients from YAML
    number_of_clients=$(yq e '.clients | length' config.yaml)
    if [[ "$number_of_clients" -gt 0 ]]; then
        for i in $(seq 0 $(($number_of_clients - 1))); do
            client_name=$(yq e ".clients[$i].name" config.yaml)
            client_dns=$(yq e ".clients[$i].dns" config.yaml)
            client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
            client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
            client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

            # Assign client IPs (starting from .2, ::2, etc.)
            octet=$((i + 2))
            client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
            if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
                client_ipv6="${base_ipv6}${octet}/$server_ipv6_mask"
            fi

            # Generate client keys
            client_private_key=$(wg genkey)
            client_public_key=$(echo "$client_private_key" | wg pubkey)
            psk=$(wg genpsk)

            # Add client to wg0.conf
            cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${base_ipv4}.${octet}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${base_ipv6}${octet}/128" )
# END_PEER $client_name
EOF

            # Create client configuration file
            cat << EOF > ~/"${client_name}-wg0.conf"
[Interface]
Address = $client_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $client_ipv6" )
DNS = $client_dns
PrivateKey = $client_private_key
$( [[ "$client_mtu" != "null" && -n "$client_mtu" ]] && echo "MTU = $client_mtu" )

[Peer]
PublicKey = $server_public_key
PresharedKey = $psk
AllowedIPs = $client_allowed_ips
Endpoint = [to be set by script]:$port
PersistentKeepalive = $client_persistent_keepalive
EOF
            chmod 600 ~/"${client_name}-wg0.conf"
        done
    fi

    echo "Server and initial clients configured from config.yaml."
else
    # If WireGuard is already installed, proceed with existing script logic
    echo "WireGuard is already installed. Use the existing menu to manage clients."
    # Rest of your script (menu for adding/removing clients) goes here
fi

# Rest of your original script continues here
# (e.g., endpoint detection, firewall rules, enabling WireGuard, etc.)


# Install a firewall if firewalld or iptables are not already available
	if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
		if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			firewall="firewalld"
			# We don't want to silently enable firewalld, so we give a subtle warning
			# If the user continues, firewalld will be installed and enabled during setup
			echo "firewalld, which is required to manage routing tables, will also be installed."
		elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
			# iptables is way less invasive than firewalld so no warning is given
			firewall="iptables"
		fi
	fi
	read -n1 -r -p "Press any key to continue..."
	# Install WireGuard
	# If BoringTun is not required, set up with the WireGuard kernel module
	if [[ "$use_boringtun" -eq 0 ]]; then
		if [[ "$os" == "ubuntu" ]]; then
			# Ubuntu
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "debian" ]]; then
			# Debian
			apt-get update
			apt-get install -y wireguard qrencode $firewall
		elif [[ "$os" == "centos" ]]; then
			# CentOS
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode $firewall
		elif [[ "$os" == "fedora" ]]; then
			# Fedora
			dnf install -y wireguard-tools qrencode $firewall
			mkdir -p /etc/wireguard/
		fi
	# Else, BoringTun needs to be used
	else
		# Install required packages
		if [[ "$os" == "ubuntu" ]]; then
			# Ubuntu
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "debian" ]]; then
			# Debian
			apt-get update
			apt-get install -y qrencode ca-certificates $cron $firewall
			apt-get install -y wireguard-tools --no-install-recommends
		elif [[ "$os" == "centos" ]]; then
			# CentOS
			dnf install -y epel-release
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
		elif [[ "$os" == "fedora" ]]; then
			# Fedora
			dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
			mkdir -p /etc/wireguard/
		fi
		# Grab the BoringTun binary using wget or curl and extract into the right place.
		# Don't use this service elsewhere without permission! Contact me before you do!
		{ wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
		# Configure wg-quick to use BoringTun
		mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
		echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
		if [[ -n "$cron" ]] && [[ "$os" == "centos" || "$os" == "fedora" ]]; then
			systemctl enable --now crond.service
		fi
	fi
	# If firewalld was just installed, enable it
	if [[ "$firewall" == "firewalld" ]]; then
		systemctl enable --now firewalld.service
	fi
	# Generate wg0.conf
	cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT $([[ -n "$public_ip" ]] && echo "$public_ip" || echo "$ip")

[Interface]
Address = 10.7.0.1/24$([[ -n "$ip6" ]] && echo ", fddd:2c4:2c4:2c4::1/64")
PrivateKey = $(wg genkey)
ListenPort = $port

EOF
	chmod 600 /etc/wireguard/wg0.conf
	# Enable net.ipv4.ip_forward for the system
	echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
	# Enable without waiting for a reboot or service restart
	echo 1 > /proc/sys/net/ipv4/ip_forward
	if [[ -n "$ip6" ]]; then
		# Enable net.ipv6.conf.all.forwarding for the system
		echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
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
		# nf_tables is not available as standard in OVZ kernels. So use iptables-legacy
		# if we are in OVZ, with a nf_tables backend and iptables-legacy is available.
		if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
			iptables_path=$(command -v iptables-legacy)
			ip6tables_path=$(command -v ip6tables-legacy)
		fi
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
	# Generates the custom client.conf
	new_client_setup
	# Enable and start the wg-quick service
	systemctl enable --now wg-quick@wg0.service
	# Set up automatic updates for BoringTun if the user wanted to
	if [[ "$boringtun_updates" =~ ^[yY]$ ]]; then
		# Deploy upgrade script
		cat << 'EOF' > /usr/local/sbin/boringtun-upgrade
#!/bin/bash
latest=$(wget -qO- https://wg.nyr.be/1/latest 2>/dev/null || curl -sL https://wg.nyr.be/1/latest 2>/dev/null)
# If server did not provide an appropriate response, exit
if ! head -1 <<< "$latest" | grep -qiE "^boringtun.+[0-9]+\.[0-9]+.*$"; then
	echo "Update server unavailable"
	exit
fi
current=$(/usr/local/sbin/boringtun -V)
if [[ "$current" != "$latest" ]]; then
	download="https://wg.nyr.be/1/latest/download"
	xdir=$(mktemp -d)
	# If download and extraction are successful, upgrade the boringtun binary
	if { wget -qO- "$download" 2>/dev/null || curl -sL "$download" ; } | tar xz -C "$xdir" --wildcards "boringtun-*/boringtun" --strip-components 1; then
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
		chmod +x /usr/local/sbin/boringtun-upgrade
		# Add cron job to run the updater daily at a random time between 3:00 and 5:59
		{ crontab -l 2>/dev/null; echo "$(( $RANDOM % 60 )) $(( $RANDOM % 3 + 3 )) * * * /usr/local/sbin/boringtun-upgrade &>/dev/null" ; } | crontab -
	fi
	echo
	qrencode -t ANSI256UTF8 < ~/"$client.conf"
	echo -e '\xE2\x86\x91 That is a QR code containing the client configuration.'
	echo
	echo "Finished!"
	echo
	echo "The client configuration is available in:" ~/"$client.conf"
	echo "New clients can be added by running this script again."
else
	clear
	echo "WireGuard is already installed."
	echo
	echo "Select an option:"
	echo "   1) Add a new client"
	echo "   2) Remove an existing client"
	echo "   3) Remove WireGuard"
	echo "   4) Exit"
	read -p "Option: " option
	until [[ "$option" =~ ^[1-4]$ ]]; do
		echo "$option: invalid selection."
		read -p "Option: " option
	done
	case "$option" in
		1)
			echo
			echo "Provide a name for the client:"
			read -p "Name: " unsanitized_client
			# Allow a limited lenght and set of characters to avoid conflicts
			client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client$" /etc/wireguard/wg0.conf; do
				echo "$client: invalid name."
				read -p "Name: " unsanitized_client
				client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
			done
			echo
			new_client_dns
			new_client_setup
			# Append new client configuration to the WireGuard interface
			wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client/,/^# END_PEER $client/p" /etc/wireguard/wg0.conf)
			echo
			qrencode -t ANSI256UTF8 < ~/"$client.conf"
			echo -e '\xE2\x86\x91 That is a QR code containing your client configuration.'
			echo
			echo "$client added. Configuration available in:" ~/"$client.conf"
			exit
		;;
		2)
			# This option could be documented a bit better and maybe even be simplified
			# ...but what can I say, I want some sleep too
			number_of_clients=$(grep -c '^# BEGIN_PEER' /etc/wireguard/wg0.conf)
			if [[ "$number_of_clients" = 0 ]]; then
				echo
				echo "There are no existing clients!"
				exit
			fi
			echo
			echo "Select the client to remove:"
			grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | nl -s ') '
			read -p "Client: " client_number
			until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$number_of_clients" ]]; do
				echo "$client_number: invalid selection."
				read -p "Client: " client_number
			done
			client=$(grep '^# BEGIN_PEER' /etc/wireguard/wg0.conf | cut -d ' ' -f 3 | sed -n "$client_number"p)
			echo
			read -p "Confirm $client removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm $client removal? [y/N]: " remove
			done
			if [[ "$remove" =~ ^[yY]$ ]]; then
				# The following is the right way to avoid disrupting other active connections:
				# Remove from the live interface
				wg set wg0 peer "$(sed -n "/^# BEGIN_PEER $client$/,\$p" /etc/wireguard/wg0.conf | grep -m 1 PublicKey | cut -d " " -f 3)" remove
				# Remove from the configuration file
				sed -i "/^# BEGIN_PEER $client$/,/^# END_PEER $client$/d" /etc/wireguard/wg0.conf
				echo
				echo "$client removed!"
			else
				echo
				echo "$client removal aborted!"
			fi
			exit
		;;
		3)
			echo
			read -p "Confirm WireGuard removal? [y/N]: " remove
			until [[ "$remove" =~ ^[yYnN]*$ ]]; do
				echo "$remove: invalid selection."
				read -p "Confirm WireGuard removal? [y/N]: " remove
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
				rm -f /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
				rm -f /etc/sysctl.d/99-wireguard-forward.conf
				# Different stuff was installed depending on whether BoringTun was used or not
				if [[ "$use_boringtun" -eq 0 ]]; then
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "debian" ]]; then
						# Debian
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard wireguard-tools
					elif [[ "$os" == "centos" ]]; then
						# CentOS
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					fi
				else
					{ crontab -l 2>/dev/null | grep -v '/usr/local/sbin/boringtun-upgrade' ; } | crontab -
					if [[ "$os" == "ubuntu" ]]; then
						# Ubuntu
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "debian" ]]; then
						# Debian
						rm -rf /etc/wireguard/
						apt-get remove --purge -y wireguard-tools
					elif [[ "$os" == "centos" ]]; then
						# CentOS
						dnf remove -y wireguard-tools
						rm -rf /etc/wireguard/
					elif [[ "$os" == "fedora" ]]; then
						# Fedora
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
		4)
			exit
		;;
	esac
fi
