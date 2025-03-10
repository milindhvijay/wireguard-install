#!/bin/bash

# Ensure the script is run with Bash
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script must be run with Bash."
    exit 1
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Detect OS and version (simplified for common distributions)
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    os=${ID}
    os_version=${VERSION_ID}
else
    echo "Error: Cannot detect operating system."
    exit 1
fi

# Function to detect virtualization/container environment
check_virt() {
    if systemd-detect-virt --container &>/dev/null; then
        echo "container"
    elif systemd-detect-virt --vm &>/dev/null; then
        echo "vm"
    else
        echo "bare-metal"
    fi
}

# Determine if BoringTun should be used
virt=$(check_virt)
if [[ "$virt" == "container" || ! -f /sys/module/wireguard ]]; then
    use_boringtun="true"
else
    use_boringtun="false"
fi

# Main installation logic
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    ### YAML-Based Initial Setup ###

    # Check for yq
    if ! command -v yq &>/dev/null; then
        echo "Error: 'yq' is required to parse the YAML configuration. Please install it."
        exit 1
    fi

    # Check for config.yaml
    if [[ ! -f config.yaml ]]; then
        echo "Error: 'config.yaml' not found in the current directory."
        exit 1
    fi

    # Parse server configuration from YAML
    port=$(yq e '.server.port' config.yaml)
    mtu=$(yq e '.server.mtu' config.yaml)
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
    ipv4_enabled=$(yq e '.server.ipv4.enabled' config.yaml)
    server_ipv4=$(yq e '.server.ipv4.address' config.yaml)
    server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
    server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
    base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
    ipv6_enabled=$(yq e '.server.ipv6.enabled' config.yaml)
    server_ipv6=$(yq e '.server.ipv6.address' config.yaml)
    server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
    server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/::[0-9]*$/::/')

    # Generate server keys
    mkdir -p /etc/wireguard
    server_private_key=$(wg genkey)
    server_public_key=$(echo "$server_private_key" | wg pubkey)

    # Create server configuration file (wg0.conf)
    cat << EOF > /etc/wireguard/wg0.conf
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT [to be set]

[Interface]
Address = $server_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $server_ipv6" )
PrivateKey = $server_private_key
ListenPort = $port
$( [[ "$mtu" != "null" && -n "$mtu" ]] && echo "MTU = $mtu" )
EOF

    # Generate client configurations
    number_of_clients=$(yq e '.clients | length' config.yaml)
    if [[ $number_of_clients -gt 253 ]]; then
        echo "Warning: Number of clients exceeds 253, which may exceed the /24 subnet limit."
    fi

    for i in $(seq 0 $(($number_of_clients - 1))); do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        # Calculate client IPs (assuming server is .1, clients start at .2)
        octet=$((i + 2))
        client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            client_ipv6="${base_ipv6}${octet}/$server_ipv6_mask"
        fi

        # Generate client keys
        client_private_key=$(wg genkey)
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        psk=$(wg genpsk)

        # Append client to wg0.conf
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
Endpoint = [to be set]:$port
PersistentKeepalive = $client_persistent_keepalive
EOF

        # Set secure permissions for client configuration file
        chmod 600 ~/"${client_name}-wg0.conf"
    done

    # Set secure permissions for wg0.conf
    chmod 600 /etc/wireguard/wg0.conf

    # Detect public endpoint
    if [[ -n "$public_endpoint" && "$public_endpoint" != "null" ]]; then
        endpoint="$public_endpoint"
    else
        endpoint=$(wget -qO- http://ip1.dynupdate.no-ip.com/ || curl -s http://ip1.dynupdate.no-ip.com/)
        if [[ -z "$endpoint" ]]; then
            echo "Error: Could not auto-detect public IP."
            exit 1
        fi
    fi

    # Update client configuration files with the endpoint
    for client_conf in ~/*-wg0.conf; do
        sed -i "s/Endpoint = \[to be set\]:$port/Endpoint = $endpoint:$port/" "$client_conf"
    done

    # Activate the WireGuard interface explicitly
    echo "Activating WireGuard interface..."
    if wg-quick up wg0; then
        echo "WireGuard interface wg0 is now active."
    else
        echo "Error: Failed to activate wg0. Please check the configuration in /etc/wireguard/wg0.conf."
        exit 1
    fi

    # Optionally enable the service to start on boot
    systemctl enable wg-quick@wg0

    # Set VPN subnets for firewall rules
    if [[ "$ipv4_enabled" == "true" ]]; then
        vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
    fi
    if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
        vpn_ipv6_subnet=$(echo "$server_ipv6" | sed 's/::[0-9]*$/::\//')
        vpn_ipv6_subnet="${vpn_ipv6_subnet}$server_ipv6_mask"
    fi

    echo
    echo "WireGuard installation is ready to begin."

    ### System Setup (Adapted from Original Script) ###

    # Firewall detection
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            firewall="firewalld"
            echo "firewalld, which is required to manage routing tables, will also be installed."
        elif [[ "$os" == "debian" || "$os" == "ubuntu" ]]; then
            firewall="iptables"
        else
            echo "Error: No supported firewall detected."
            exit 1
        fi
    elif systemctl is-active --quiet firewalld.service; then
        firewall="firewalld"
    else
        firewall="iptables"
    fi

    # Package installation
    echo "Installing WireGuard packages..."
    if [[ "$os" == "ubuntu" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode
        if [[ "$use_boringtun" == "true" ]]; then
            apt-get install -y wireguard-tools
            wget -O /usr/local/bin/boringtun https://github.com/cloudflare/boringtun/releases/latest/download/boringtun
            chmod +x /usr/local/bin/boringtun
        fi
    elif [[ "$os" == "debian" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode
        if [[ "$use_boringtun" == "true" ]]; then
            apt-get install -y wireguard-tools
            wget -O /usr/local/bin/boringtun https://github.com/cloudflare/boringtun/releases/latest/download/boringtun
            chmod +x /usr/local/bin/boringtun
        fi
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        dnf install -y wireguard-tools qrencode
        if [[ "$firewall" == "firewalld" ]]; then
            dnf install -y firewalld
        fi
        if [[ "$use_boringtun" == "true" ]]; then
            wget -O /usr/local/bin/boringtun https://github.com/cloudflare/boringtun/releases/latest/download/boringtun
            chmod +x /usr/local/bin/boringtun
        fi
    else
        echo "Error: Unsupported OS."
        exit 1
    fi

    # Configure firewall
    if [[ "$firewall" == "firewalld" ]]; then
        systemctl enable --now firewalld
        firewall-cmd --permanent --add-port="$port"/udp
        firewall-cmd --permanent --zone=trusted --add-source="$vpn_ipv4_subnet"
        if [[ -n "$vpn_ipv6_subnet" ]]; then
            firewall-cmd --permanent --zone=trusted --add-source="$vpn_ipv6_subnet"
        fi
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        iptables -A FORWARD -s "$vpn_ipv4_subnet" -j ACCEPT
        if [[ -n "$vpn_ipv6_subnet" ]]; then
            ip6tables -A FORWARD -s "$vpn_ipv6_subnet" -j ACCEPT
        fi
        iptables -t nat -A POSTROUTING -s "$vpn_ipv4_subnet" -o eth0 -j MASQUERADE
        if [[ -n "$vpn_ipv6_subnet" ]]; then
            ip6tables -t nat -A POSTROUTING -s "$vpn_ipv6_subnet" -o eth0 -j MASQUERADE
        fi
        # Persist iptables (simplified)
        iptables-save > /etc/iptables/rules.v4
        if [[ -n "$vpn_ipv6_subnet" ]]; then
            ip6tables-save > /etc/iptables/rules.v6
        fi
    fi

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    if [[ -n "$vpn_ipv6_subnet" ]]; then
        sysctl -w net.ipv6.conf.all.forwarding=1
    fi
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    if [[ -n "$vpn_ipv6_subnet" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    fi

    # Start WireGuard service
    if [[ "$use_boringtun" == "true" ]]; then
        mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
        cat << EOF > /etc/systemd/system/wg-quick@wg0.service.d/override.conf
[Service]
ExecStart=
ExecStart=/usr/local/bin/boringtun wg0
ExecStart=/usr/bin/wg-quick up wg0
EOF
        systemctl daemon-reload
    fi
    systemctl enable --now wg-quick@wg0

    # Display client QR codes
    echo "WireGuard setup complete. Here are the client configurations:"
    for client_conf in ~/*-wg0.conf; do
        echo -e "\nClient: $(basename "$client_conf")"
        qrencode -t ANSI256UTF8 < "$client_conf"
        echo "Configuration file saved at: $client_conf"
    done

else
    ### Management Menu (Adapted from Original Script) ###

    echo "WireGuard is already installed."
    echo "Select an option:"
    echo "   1) Remove WireGuard"
    echo "   2) Exit"
    read -p "Option: " option

    case $option in
        1)
            systemctl disable --now wg-quick@wg0
            rm -rf /etc/wireguard
            rm -f /usr/local/bin/boringtun
            if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
                apt-get remove -y wireguard wireguard-tools
            elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                dnf remove -y wireguard-tools
            fi
            echo "WireGuard removed."
            ;;
        2)
            exit 0
            ;;
        *)
            echo "Invalid option."
            exit 1
            ;;
    esac
fi
