#!/bin/bash
#
# Modified version of https://github.com/Nyr/wireguard-install
# This version uses a YAML configuration file instead of interactive prompts
#

# Check if yq is installed (needed for YAML parsing)
if ! command -v yq &> /dev/null; then
    echo "yq is required for YAML parsing but it's not installed."
    echo "Installing yq..."

    # Detect OS and install yq
    if grep -qs "ubuntu\|debian" /etc/os-release; then
        apt-get update
        apt-get install -y wget
        wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
        chmod +x /usr/local/bin/yq
    elif grep -qs "centos\|fedora\|rhel" /etc/os-release; then
        yum install -y wget
        wget -qO /usr/local/bin/yq https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64
        chmod +x /usr/local/bin/yq
    else
        echo "Unsupported OS for automatic yq installation."
        exit 1
    fi
fi

# Default config file location
CONFIG_FILE="wireguard.yaml"

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Configuration file $CONFIG_FILE not found!"
    exit 1
fi

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
	echo 'This installer needs to be run with "bash", not "sh".'
	exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
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

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
	echo '$PATH does not include sbin. Try using "su -" instead of "su".'
	exit
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
if ! systemd-detect-virt -cq; then
	# Not running inside a container
	use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
	# Running inside a container, but the wireguard kernel module is available
	use_boringtun="0"
else
	# Running inside a container and the wireguard kernel module is not available
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
	# TUN device is required to use BoringTun
	if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
		echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
		exit
	fi
fi

# Read configuration from YAML file
read_yaml_config() {
    # Server configuration
    port=$(yq e '.server.port' "$CONFIG_FILE")
    server_mtu=$(yq e '.server.mtu' "$CONFIG_FILE")
    public_endpoint=$(yq e '.server.public_endpoint' "$CONFIG_FILE")
    host_interface=$(yq e '.server.host_interface' "$CONFIG_FILE")

    # IP configuration
    ipv4_enabled=$(yq e '.server.ipv4.enabled' "$CONFIG_FILE")
    ipv4_address=$(yq e '.server.ipv4.address' "$CONFIG_FILE")

    ipv6_enabled=$(yq e '.server.ipv6.enabled' "$CONFIG_FILE")
    ipv6_address=$(yq e '.server.ipv6.address' "$CONFIG_FILE")

    # Validate required values
    if [[ -z "$port" || "$port" == "null" ]]; then
        echo "Server port not specified in config file."
        exit 1
    fi

    if [[ -z "$server_mtu" || "$server_mtu" == "null" ]]; then
        server_mtu=1420
    fi

    # Handle empty public_endpoint
    if [[ "$public_endpoint" == "null" ]]; then
        public_endpoint=""
    fi

    # Use host_interface if specified
    if [[ -n "$host_interface" && "$host_interface" != "null" ]]; then
        # Check if interface exists
        if ! ip link show "$host_interface" &>/dev/null; then
            echo "Specified host interface $host_interface does not exist"
            exit 1
        fi
    fi
}

setup_wireguard() {
    # Install WireGuard
    if [[ "$use_boringtun" -eq 0 ]]; then
        if [[ "$os" == "ubuntu" ]]; then
            # Ubuntu
            apt-get update
            apt-get install -y wireguard qrencode
        elif [[ "$os" == "debian" ]]; then
            # Debian
            apt-get update
            apt-get install -y wireguard qrencode
        elif [[ "$os" == "centos" ]]; then
            # CentOS
            dnf install -y epel-release
            dnf install -y wireguard-tools qrencode
        elif [[ "$os" == "fedora" ]]; then
            # Fedora
            dnf install -y wireguard-tools qrencode
            mkdir -p /etc/wireguard/
        fi
    else
        # BoringTun installation
        if [[ "$os" == "ubuntu" ]]; then
            apt-get update
            apt-get install -y qrencode ca-certificates
            apt-get install -y wireguard-tools --no-install-recommends
        elif [[ "$os" == "debian" ]]; then
            apt-get update
            apt-get install -y qrencode ca-certificates
            apt-get install -y wireguard-tools --no-install-recommends
        elif [[ "$os" == "centos" ]]; then
            dnf install -y epel-release
            dnf install -y wireguard-tools qrencode ca-certificates tar
        elif [[ "$os" == "fedora" ]]; then
            dnf install -y wireguard-tools qrencode ca-certificates tar
            mkdir -p /etc/wireguard/
        fi

        # Install BoringTun
        { wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1

        # Configure wg-quick to use BoringTun
        mkdir -p /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
        echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
    fi

    # Setup firewall if needed
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            dnf install -y firewalld
            systemctl enable --now firewalld.service
        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            apt-get install -y iptables
        fi
    fi

    # Configure server IP addresses
    local server_ip
    local server_ip6

    if [[ "$ipv4_enabled" == "true" && -n "$ipv4_address" ]]; then
        server_ip=$(echo "$ipv4_address" | cut -d '/' -f 1)
        ipv4_subnet=$(echo "$ipv4_address" | cut -d '/' -f 2)
    else
        # Auto-detect IPv4 address
        if [[ -n "$host_interface" && "$host_interface" != "null" ]]; then
            server_ip=$(ip -4 addr show "$host_interface" | grep -oP '(?<=inet\s)[0-9.]+')
        elif [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
            server_ip=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
        else
            echo "Multiple IPv4 addresses detected, but none specified in config. Please specify server.ipv4.address in the config."
            exit 1
        fi
        server_ip="10.7.0.1"
        ipv4_subnet="24"
    fi

    if [[ "$ipv6_enabled" == "true" && -n "$ipv6_address" ]]; then
        server_ip6=$(echo "$ipv6_address" | cut -d '/' -f 1)
        ipv6_subnet=$(echo "$ipv6_address" | cut -d '/' -f 2)
        ipv6_config=", ${server_ip6}/${ipv6_subnet}"
    else
        ipv6_config=""
    fi

    # Generate wg0.conf
    local server_private_key=$(wg genkey)
    local server_public_key=$(echo "$server_private_key" | wg pubkey)

    # Determine endpoint IP
    local endpoint_ip
    if [[ -n "$public_endpoint" ]]; then
        endpoint_ip="$public_endpoint"
    else
        endpoint_ip="$server_ip"
        # If server IP is private, try to get public IP
        if echo "$server_ip" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
            get_public_ip=$(grep -m 1 -oE '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' <<< "$(wget -T 10 -t 1 -4qO- "http://ip1.dynupdate.no-ip.com/" || curl -m 10 -4Ls "http://ip1.dynupdate.no-ip.com/")")
            if [[ -n "$get_public_ip" ]]; then
                endpoint_ip="$get_public_ip"
            fi
        fi
    fi

    # Create server config
    cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT ${endpoint_ip}

[Interface]
Address = ${server_ip}/${ipv4_subnet}${ipv6_config}
PrivateKey = ${server_private_key}
ListenPort = ${port}
MTU = ${server_mtu}

EOF

    chmod 600 /etc/wireguard/wg0.conf

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward

    if [[ "$ipv6_enabled" == "true" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi

    # Configure firewall rules
    if systemctl is-active --quiet firewalld.service; then
        # Using firewalld
        firewall-cmd --add-port="$port"/udp
        firewall-cmd --zone=trusted --add-source=10.7.0.0/24
        firewall-cmd --permanent --add-port="$port"/udp
        firewall-cmd --permanent --zone=trusted --add-source=10.7.0.0/24

        # Extract base IPv4 address
        local base_ip=$(echo "$server_ip" | cut -d'.' -f1-3)

        # Set NAT for the VPN subnet
        firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s ${base_ip}.0/24 ! -d ${base_ip}.0/24 -j SNAT --to "$server_ip"
        firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s ${base_ip}.0/24 ! -d ${base_ip}.0/24 -j SNAT --to "$server_ip"

        if [[ "$ipv6_enabled" == "true" ]]; then
            local ipv6_prefix=$(echo "$server_ip6" | rev | cut -d ':' -f2- | rev)
            firewall-cmd --zone=trusted --add-source=${ipv6_prefix}::/64
            firewall-cmd --permanent --zone=trusted --add-source=${ipv6_prefix}::/64
            firewall-cmd --direct --add-rule ipv6 nat POSTROUTING 0 -s ${ipv6_prefix}::/64 ! -d ${ipv6_prefix}::/64 -j SNAT --to "$server_ip6"
            firewall-cmd --permanent --direct --add-rule ipv6 nat POSTROUTING 0 -s ${ipv6_prefix}::/64 ! -d ${ipv6_prefix}::/64 -j SNAT --to "$server_ip6"
        fi
    else
        # Create iptables service
        iptables_path=$(command -v iptables)
        ip6tables_path=$(command -v ip6tables)

        # Check for OpenVZ with nf_tables
        if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
            iptables_path=$(command -v iptables-legacy)
            ip6tables_path=$(command -v ip6tables-legacy)
        fi

        # Extract base IPv4 address
        local base_ip=$(echo "$server_ip" | cut -d'.' -f1-3)

        # Create iptables service
        echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s ${base_ip}.0/24 ! -d ${base_ip}.0/24 -j SNAT --to $server_ip
ExecStart=$iptables_path -I INPUT -p udp --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s ${base_ip}.0/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s ${base_ip}.0/24 ! -d ${base_ip}.0/24 -j SNAT --to $server_ip
ExecStop=$iptables_path -D INPUT -p udp --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s ${base_ip}.0/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" > /etc/systemd/system/wg-iptables.service

        if [[ "$ipv6_enabled" == "true" ]]; then
            local ipv6_prefix=$(echo "$server_ip6" | rev | cut -d ':' -f2- | rev)
            echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s ${ipv6_prefix}::/64 ! -d ${ipv6_prefix}::/64 -j SNAT --to $server_ip6
ExecStart=$ip6tables_path -I FORWARD -s ${ipv6_prefix}::/64 -j ACCEPT
ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$ip6tables_path -t nat -D POSTROUTING -s ${ipv6_prefix}::/64 ! -d ${ipv6_prefix}::/64 -j SNAT --to $server_ip6
ExecStop=$ip6tables_path -D FORWARD -s ${ipv6_prefix}::/64 -j ACCEPT
ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >> /etc/systemd/system/wg-iptables.service
        fi

        echo "RemainAfterExit=yes
[Install]
WantedBy=multi-user.target" >> /etc/systemd/system/wg-iptables.service

        systemctl enable --now wg-iptables.service
    fi

    # Create client configurations
    local client_count=$(yq e '.clients | length' "$CONFIG_FILE")

    # Extract base IPv4 address
    local base_ip=$(echo "$server_ip" | cut -d'.' -f1-3)

    for i in $(seq 0 $((client_count-1))); do
        local client_name=$(yq e ".clients[$i].name" "$CONFIG_FILE")
        local client_dns=$(yq e ".clients[$i].dns" "$CONFIG_FILE")
        local client_mtu=$(yq e ".clients[$i].mtu" "$CONFIG_FILE")
        local client_allowed_ips=$(yq e ".clients[$i].allowed_ips" "$CONFIG_FILE")
        local client_keepalive=$(yq e ".clients[$i].persistent_keepalive" "$CONFIG_FILE")

        # Set defaults if values are null/empty
        [[ "$client_mtu" == "null" ]] && client_mtu=1420
        [[ "$client_allowed_ips" == "null" ]] && client_allowed_ips="0.0.0.0/0, ::/0"
        [[ "$client_keepalive" == "null" ]] && client_keepalive=25

        # Generate client keys
        local client_private_key=$(wg genkey)
        local client_public_key=$(echo "$client_private_key" | wg pubkey)
        local client_preshared_key=$(wg genpsk)

        # Calculate client IP - base on octet 2
        local octet=$((i+2))
        local client_ip="${base_ip}.${octet}"

        # Configure client in the server
        cat << EOF >> /etc/wireguard/wg0.conf
# BEGIN_PEER $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $client_preshared_key
AllowedIPs = $client_ip/32$([ "$ipv6_enabled" == "true" ] && echo ", ${ipv6_prefix}::${octet}/128")
# END_PEER $client_name
EOF

        # Create client configuration file
        local client_ipv6=""
        [[ "$ipv6_enabled" == "true" ]] && client_ipv6=", ${ipv6_prefix}::${octet}/64"

        cat << EOF > ~/"$client_name.conf"
[Interface]
Address = $client_ip/24$client_ipv6
DNS = $client_dns
PrivateKey = $client_private_key
MTU = $client_mtu

[Peer]
PublicKey = $server_public_key
PresharedKey = $client_preshared_key
AllowedIPs = $client_allowed_ips
Endpoint = ${endpoint_ip}:${port}
PersistentKeepalive = $client_keepalive
EOF

        # Generate QR code
        qrencode -t ANSI256UTF8 < ~/"$client_name.conf"
        echo -e "Client configuration for $client_name created: ~/$client_name.conf"
    done

    # Enable and start WireGuard
    systemctl enable --now wg-quick@wg0.service

    echo "WireGuard installation complete!"
}

# Main execution flow
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    echo "WireGuard is not installed. Installing..."
    read_yaml_config
    setup_wireguard
else
    echo "WireGuard is already installed."
    echo "To reinstall, remove /etc/wireguard/wg0.conf and run this script again."
    exit 1
fi
