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

# Function to generate server and client configurations from YAML
generate_configs() {
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
    vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/::[0-9]*$/::/')

    # Generate server keys
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
            return 1
        fi
    fi

    # Update client configuration files with the endpoint
    for client_conf in ~/*-wg0.conf; do
        sed -i "s/Endpoint = \[to be set\]:$port/Endpoint = $endpoint:$port/" "$client_conf"
    done
}

# Main installation logic
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    ### System Setup ###

    # Package installation
    echo "Installing WireGuard packages..."
    if [[ "$os" == "ubuntu" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode
    elif [[ "$os" == "debian" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        dnf install -y wireguard-tools qrencode
    else
        echo "Error: Unsupported OS."
        exit 1
    fi

    ### YAML-Based Initial Setup ###

    # Check for yq and install if not present
    if ! command -v yq &>/dev/null; then
        echo "'yq' not found, installing it automatically..."
        wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq &&\
        chmod +x /usr/bin/yq
        if ! command -v yq &>/dev/null; then
            echo "Error: Failed to install 'yq'. Please install it manually."
            exit 1
        fi
    fi

    # Check for config.yaml
    if [[ ! -f config.yaml ]]; then
        echo "Error: 'config.yaml' not found in the current directory."
        exit 1
    fi

    # Save a backup of config.yaml for later comparison
    mkdir -p /etc/wireguard
    cp config.yaml /etc/wireguard/config.yaml.backup
    chmod 600 /etc/wireguard/config.yaml.backup

    # Generate configurations
    if ! generate_configs; then
        echo "Error: Failed to generate configurations."
        exit 1
    fi

    # Set VPN subnets (for IPv4 only, skipping IPv6 to avoid ip6tables issue)
    if [[ "$ipv4_enabled" == "true" ]]; then
        vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
    fi

    echo
    echo "WireGuard installation is ready to begin."

    # Firewall detection
    if ! systemctl is-active --quiet firewalld.service && ! hash iptables 2>/dev/null; then
        if [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            firewall="firewalld"
            echo "firewalld, which is required to manage routing tables, will also be installed."
            dnf install -y firewalld
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

    # Configure firewall (IPv4 only, simplified)
    if [[ "$firewall" == "firewalld" ]]; then
        systemctl enable --now firewalld
        firewall-cmd --permanent --add-port="$port"/udp
        firewall-cmd --permanent --zone=trusted --add-source="$vpn_ipv4_subnet"
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
    else
        iptables -A INPUT -p udp --dport "$port" -j ACCEPT
        iptables -A FORWARD -s "$vpn_ipv4_subnet" -j ACCEPT
        iptables -t nat -A POSTROUTING -s "$vpn_ipv4_subnet" -o eth0 -j MASQUERADE
    fi

    # Enable IP forwarding (IPv4 and IPv6)
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

    # Start WireGuard service
    echo "Activating WireGuard interface..."
    if systemctl enable --now wg-quick@wg0; then
        echo "WireGuard interface wg0 is now active."
    else
        echo "Error: Failed to activate wg0. Please check the configuration in /etc/wireguard/wg0.conf."
        exit 1
    fi

    # Display client QR codes
    echo "WireGuard setup complete. Here are the client configurations:"
    for client_conf in ~/*-wg0.conf; do
        echo -e "\nClient: $(basename "$client_conf")"
        qrencode -t ANSI256UTF8 < "$client_conf"
        echo "Configuration file saved at: $client_conf"
    done

else
    ### Management Menu ###

    echo "WireGuard is already installed."
    echo "Select an option:"
    echo "   1) Remove WireGuard"
    echo "   2) Re-create server and client configurations from YAML"
    echo "   3) Exit"
    read -p "Option: " option

    case $option in

        1)
            # Check for config.yaml
            if [[ ! -f config.yaml ]]; then
                echo "Error: 'config.yaml' not found in the current directory."
                exit 1
            fi

            # Compare with previous YAML backup
            if [[ -f /etc/wireguard/config.yaml.backup ]]; then
                if cmp -s config.yaml /etc/wireguard/config.yaml.backup; then
                    echo "No changes detected in config.yaml. No action taken."
                    exit 0
                fi
            fi

            # If different or no backup, proceed with regeneration
            echo "Regenerating configurations from config.yaml..."
            if ! generate_configs; then
                echo "Error: Failed to regenerate configurations."
                exit 1
            fi

            # Update the backup YAML
            cp config.yaml /etc/wireguard/config.yaml.backup
            chmod 600 /etc/wireguard/config.yaml.backup

            # Restart WireGuard service to apply new configuration
            echo "Restarting WireGuard service..."
            if systemctl restart wg-quick@wg0; then
                echo "WireGuard configurations updated and service restarted."
            else
                echo "Error: Failed to restart wg0. Please check the configuration in /etc/wireguard/wg0.conf."
                exit 1
            fi

            # Display client QR codes
            echo "Updated client configurations:"
            for client_conf in ~/*-wg0.conf; do
                echo -e "\nClient: $(basename "$client_conf")"
                qrencode -t ANSI256UTF8 < "$client_conf"
                echo "Configuration file saved at: $client_conf"
            done
            ;;

        2)
            systemctl disable --now wg-quick@wg0
            rm -rf /etc/wireguard
            if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
                apt-get remove -y wireguard wireguard-tools
            elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                dnf remove -y wireguard-tools
            fi
            echo "WireGuard removed."
            ;;

        3)
            exit 0
            ;;
        *)
            echo "Invalid option."
            exit 1
            ;;
    esac
fi
