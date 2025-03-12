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

# Function to generate full server and client configurations from YAML
generate_full_configs() {
    # Parse server configuration from YAML
    port=$(yq e '.server.port' config.yaml)
    mtu=$(yq e '.server.mtu' config.yaml)
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
    ipv4_enabled=$(yq e '.server.ipv4.enabled' config.yaml)
    server_ipv4=$(yq e '.server.ipv4.address' config.yaml)
    server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
    server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
    base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
    server_ipv4_last_octet=$(echo "$server_ipv4_ip" | cut -d '.' -f 4)
    ipv6_enabled=$(yq e '.server.ipv6.enabled' config.yaml)
    server_ipv6=$(yq e '.server.ipv6.address' config.yaml)
    server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
    server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
    vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/:[0-9a-f]*$//')
    server_ipv6_last_segment=$(echo "$server_ipv6_ip" | grep -o '[0-9a-f]*$')

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

    # Generate all client configurations
    number_of_clients=$(yq e '.clients | length' config.yaml)

    for i in $(seq 0 $(($number_of_clients - 1))); do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        # Calculate client IPs relative to server IP
        octet=$((server_ipv4_last_octet + i + 1))
        client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            client_ipv6_last_segment=$(printf "%x" $((16#$server_ipv6_last_segment + i + 1)))
            client_ipv6="${base_ipv6}:${client_ipv6_last_segment}/$server_ipv6_mask"
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
AllowedIPs = ${base_ipv4}.${octet}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${base_ipv6}:${client_ipv6_last_segment}/128" )
# END_PEER $client_name
EOF

        # Create client configuration file
        cat << EOF > ~/"${client_name}-wg0.conf"
[Interface]
Address = $client_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $client_ipv6" )
DNS = $client_dns
PrivateKey = $client_private_key
$( [[ "$client_mtu" != "null" && -n "$mtu" ]] && echo "MTU = $client_mtu" )

[Peer]
PublicKey = $server_public_key
PresharedKey = $psk
AllowedIPs = $client_allowed_ips
Endpoint = [to be set]:$port
PersistentKeepalive = $client_persistent_keepalive
EOF
        chmod 600 ~/"${client_name}-wg0.conf"
    done

    # Set secure permissions for wg0.conf
    chmod 600 /etc/wireguard/wg0.conf

    # Detect public endpoint, preferring IPv6
    if [[ -n "$public_endpoint" && "$public_endpoint" != "null" ]]; then
        endpoint="$public_endpoint"
    else
        # Check for global IPv6 address
        endpoint=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-f:]+' | head -n 1)
        if [[ -n "$endpoint" ]]; then
            endpoint="[$endpoint]" # Wrap IPv6 in brackets for WireGuard
        else
            # Fall back to IPv4
            endpoint=$(wget -qO- http://ip1.dynupdate.no-ip.com/ || curl -s http://ip1.dynupdate.no-ip.com/)
            if [[ -z "$endpoint" ]]; then
                echo "Error: Could not auto-detect public IP (neither IPv6 nor IPv4)."
                return 1
            fi
        fi
    fi

    # Update client configuration files with the endpoint
    for client_conf in ~/*-wg0.conf; do
        sed -i "s/Endpoint = \[to be set\]:$port/Endpoint = $endpoint:$port/" "$client_conf"
    done
}

# Function to regenerate specific client configurations
generate_client_configs() {
    local changed_clients=("$@") # Array of client indices to regenerate
    port=$(yq e '.server.port' config.yaml)
    ipv4_enabled=$(yq e '.server.ipv4.enabled' config.yaml)
    server_ipv4=$(yq e '.server.ipv4.address' config.yaml)
    server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
    server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
    base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
    server_ipv4_last_octet=$(echo "$server_ipv4_ip" | cut -d '.' -f 4)
    ipv6_enabled=$(yq e '.server.ipv6.enabled' config.yaml)
    server_ipv6=$(yq e '.server.ipv6.address' config.yaml)
    server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
    server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
    vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/:[0-9a-f]*$//')
    server_ipv6_last_segment=$(echo "$server_ipv6_ip" | grep -o '[0-9a-f]*$')
    server_public_key=$(wg show wg0 public-key)

    # Detect public endpoint, preferring IPv6
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
    if [[ -n "$public_endpoint" && "$public_endpoint" != "null" ]]; then
        endpoint="$public_endpoint"
    else
        # Check for global IPv6 address
        endpoint=$(ip -6 addr show scope global | grep -oP 'inet6 \K[0-9a-f:]+' | head -n 1)
        if [[ -n "$endpoint" ]]; then
            endpoint="[$endpoint]" # Wrap IPv6 in brackets for WireGuard
        else
            # Fall back to IPv4
            endpoint=$(wget -qO- http://ip1.dynupdate.no-ip.com/ || curl -s http://ip1.dynupdate.no-ip.com/)
            if [[ -z "$endpoint" ]]; then
                echo "Error: Could not auto-detect public IP (neither IPv6 nor IPv4)."
                return 1
            fi
        fi
    fi

    for i in "${changed_clients[@]}"; do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        # Calculate client IPs relative to server IP
        octet=$((server_ipv4_last_octet + i + 1))
        client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            client_ipv6_last_segment=$(printf "%x" $((16#$server_ipv6_last_segment + i + 1)))
            client_ipv6="${base_ipv6}:${client_ipv6_last_segment}/$server_ipv6_mask"
        fi

        # Generate client keys
        client_private_key=$(wg genkey)
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        psk=$(wg genpsk)

        # Remove old peer section from wg0.conf based on name (if it exists)
        old_name=$(yq e ".clients[$i].name" /etc/wireguard/config.yaml.backup)
        if [[ "$old_name" != "$client_name" && -n "$old_name" ]]; then
            sed -i "/# BEGIN_PEER $old_name/,/# END_PEER $old_name/d" /etc/wireguard/wg0.conf
            rm -f ~/"${old_name}-wg0.conf"
            echo "Removed old client configuration for '$old_name'."
        else
            sed -i "/# BEGIN_PEER $client_name/,/# END_PEER $client_name/d" /etc/wireguard/wg0.conf
        fi

        # Append updated client to wg0.conf
        cat << EOF >> /etc/wireguard/wg0.conf

# BEGIN_PEER $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${base_ipv4}.${octet}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${base_ipv6}:${client_ipv6_last_segment}/128" )
# END_PEER $client_name
EOF

        # Regenerate client configuration file
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
Endpoint = $endpoint:$port
PersistentKeepalive = $client_persistent_keepalive
EOF
        chmod 600 ~/"${client_name}-wg0.conf"
    done
}

# Function to configure firewall (called separately to ensure rules are applied before WG start)
configure_firewall() {
    local port="$1"
    local vpn_ipv4_subnet="$2"
    local vpn_ipv6_subnet="$3"
    local firewall="$4"

    # Configure firewall (IPv4 and IPv6 based on YAML settings)
    if [[ "$firewall" == "firewalld" ]]; then
        systemctl enable --now firewalld
        firewall-cmd --permanent --add-port="$port"/udp
        if [[ "$ipv4_enabled" == "true" ]]; then
            firewall-cmd --permanent --zone=trusted --add-source="$vpn_ipv4_subnet"
        fi
        if [[ "$ipv6_enabled" == "true" ]]; then
            firewall-cmd --permanent --zone=trusted --add-source="$vpn_ipv6_subnet"
        fi
        # Enable masquerading based on NAT settings for both IPv4 and IPv6
        if [[ ( "$ipv4_enabled" == "true" && "$(yq e '.server.ipv4.nat' config.yaml)" == "true" ) || ( "$ipv6_enabled" == "true" && "$(yq e '.server.ipv6.nat' config.yaml)" == "true" ) ]]; then
            firewall-cmd --permanent --add-masquerade
        fi
        firewall-cmd --reload
    else
        # iptables for IPv4
        if [[ "$ipv4_enabled" == "true" ]]; then
            iptables -A INPUT -p udp --dport "$port" -j ACCEPT
            iptables -A FORWARD -s "$vpn_ipv4_subnet" -j ACCEPT
            if [[ "$(yq e '.server.ipv4.nat' config.yaml)" == "true" ]]; then
                iptables -t nat -A POSTROUTING -s "$vpn_ipv4_subnet" -o $(yq e '.server.host_interface' config.yaml) -j MASQUERADE
            fi
        fi
        # ip6tables for IPv6
        if [[ "$ipv6_enabled" == "true" ]]; then
            ip6tables -A INPUT -p udp --dport "$port" -j ACCEPT
            ip6tables -A FORWARD -s "$vpn_ipv6_subnet" -j ACCEPT
            if [[ "$(yq e '.server.ipv6.nat' config.yaml)" == "true" ]]; then
                ip6tables -t nat -A POSTROUTING -s "$vpn_ipv6_subnet" -o $(yq e '.server.host_interface' config.yaml) -j MASQUERADE
            fi
        fi
    fi
}

# Function to clear existing firewall rules (for updates)
clear_firewall_rules() {
    local firewall="$1"
    if [[ "$firewall" == "firewalld" ]]; then
        firewall-cmd --permanent --remove-port="$port"/udp >/dev/null 2>&1
        if [[ "$ipv4_enabled" == "true" ]]; then
            firewall-cmd --permanent --zone=trusted --remove-source="$vpn_ipv4_subnet" >/dev/null 2>&1
        fi
        if [[ "$ipv6_enabled" == "true" ]]; then
            firewall-cmd --permanent --zone=trusted --remove-source="$vpn_ipv6_subnet" >/dev/null 2>&1
        fi
        firewall-cmd --permanent --remove-masquerade >/dev/null 2>&1
        firewall-cmd --reload
    else
        iptables -D INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
        iptables -D FORWARD -s "$vpn_ipv4_subnet" -j ACCEPT >/dev/null 2>&1
        iptables -t nat -D POSTROUTING -s "$vpn_ipv4_subnet" -o $(yq e '.server.host_interface' config.yaml) -j MASQUERADE >/dev/null 2>&1
        ip6tables -D INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
        ip6tables -D FORWARD -s "$vpn_ipv6_subnet" -j ACCEPT >/dev/null 2>&1
        ip6tables -t nat -D POSTROUTING -s "$vpn_ipv6_subnet" -o $(yq e '.server.host_interface' config.yaml) -j MASQUERADE >/dev/null 2>&1
    fi
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

    # Generate full configurations
    if ! generate_full_configs; then
        echo "Error: Failed to generate configurations."
        exit 1
    fi

    # Set VPN subnets
    if [[ "$ipv4_enabled" == "true" ]]; then
        vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
    fi
    if [[ "$ipv6_enabled" == "true" ]]; then
        vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
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

    # Configure firewall before starting WireGuard
    configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet" "$firewall"

    # Enable IP forwarding (IPv4 and IPv6)
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

    # Start WireGuard service
    echo "Activating WireGuard interface..."
    if systemctl enable --now wg-quick@wg0; then
        # Verify wg0 is actually up
        if ! wg show wg0 >/dev/null 2>&1; then
            echo "Warning: wg0 failed to start properly, attempting manual restart..."
            wg-quick down wg0 >/dev/null 2>&1
            wg-quick up wg0
            if wg show wg0 >/dev/null 2>&1; then
                echo "WireGuard interface wg0 is now active after manual restart."
            else
                echo "Error: Failed to activate wg0 even after manual restart. Please check /etc/wireguard/wg0.conf."
                exit 1
            fi
        else
            echo "WireGuard interface wg0 is now active."
        fi
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
    echo "   1) Re-create server and client configurations from YAML"
    echo "   2) Remove WireGuard"
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

                # Define variables needed for firewall
                port=$(yq e '.server.port' config.yaml)
                ipv4_enabled=$(yq e '.server.ipv4.enabled' config.yaml)
                server_ipv4=$(yq e '.server.ipv4.address' config.yaml)
                server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
                server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
                base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
                ipv6_enabled=$(yq e '.server.ipv6.enabled' config.yaml)
                server_ipv6=$(yq e '.server.ipv6.address' config.yaml)
                server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
                server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
                vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
                vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"

                # Firewall detection (for updates)
                if systemctl is-active --quiet firewalld.service; then
                    firewall="firewalld"
                else
                    firewall="iptables"
                fi

                # Check if server section changed
                yq e '.server' config.yaml > /tmp/server_new.yaml
                yq e '.server' /etc/wireguard/config.yaml.backup > /tmp/server_old.yaml
                if ! cmp -s /tmp/server_new.yaml /tmp/server_old.yaml; then
                    echo "Server configuration changed. Regenerating all configurations..."
                    if ! generate_full_configs; then
                        echo "Error: Failed to regenerate configurations."
                        rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                        exit 1
                    fi
                    cp config.yaml /etc/wireguard/config.yaml.backup
                    chmod 600 /etc/wireguard/config.yaml.backup

                    # Clear and reconfigure firewall rules
                    clear_firewall_rules "$firewall"
                    configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet" "$firewall"

                    # Display all client QR codes
                    echo "Updated client configurations:"
                    for client_conf in ~/*-wg0.conf; do
                        echo -e "\nClient: $(basename "$client_conf")"
                        qrencode -t ANSI256UTF8 < "$client_conf"
                        echo "Configuration file saved at: $client_conf"
                    done
                else
                    # Check for changes in clients
                    changed_clients=()
                    number_of_clients=$(yq e '.clients | length' config.yaml)
                    old_clients=$(yq e '.clients | length' /etc/wireguard/config.yaml.backup)
                    max_clients=$((number_of_clients > old_clients ? number_of_clients : old_clients))

                    for i in $(seq 0 $((max_clients - 1))); do
                        # Compare client names specifically
                        new_name=$(yq e ".clients[$i].name" config.yaml)
                        old_name=$(yq e ".clients[$i].name" /etc/wireguard/config.yaml.backup)
                        # If name changed or client is new/changed in any way
                        if [[ "$new_name" != "$old_name" ]] || ! cmp -s <(yq e ".clients[$i]" config.yaml) <(yq e ".clients[$i]" /etc/wireguard/config.yaml.backup); then
                            changed_clients+=("$i")
                        fi
                    done

                    if [[ ${#changed_clients[@]} -gt 0 ]]; then
                        echo "Regenerating configurations for changed clients: ${changed_clients[*]}..."
                        if ! generate_client_configs "${changed_clients[@]}"; then
                            echo "Error: Failed to regenerate client configurations."
                            rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                            exit 1
                        fi
                        cp config.yaml /etc/wireguard/config.yaml.backup
                        chmod 600 /etc/wireguard/config.yaml.backup

                        # Clear and reconfigure firewall rules (in case subnet changed in clients)
                        clear_firewall_rules "$firewall"
                        configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet" "$firewall"

                        # Display QR codes only for changed clients
                        echo "Updated client configurations:"
                        for i in "${changed_clients[@]}"; do
                            client_name=$(yq e ".clients[$i].name" config.yaml)
                            client_conf=~/"${client_name}-wg0.conf"
                            echo -e "\nClient: $(basename "$client_conf")"
                            qrencode -t ANSI256UTF8 < "$client_conf"
                            echo "Configuration file saved at: $client_conf"
                        done
                    else
                        echo "No actionable changes detected in client configurations."
                        rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                        exit 0
                    fi
                fi
                rm -f /tmp/server_new.yaml /tmp/server_old.yaml
            else
                # No backup exists, regenerate everything
                echo "No backup found. Regenerating all configurations..."
                if ! generate_full_configs; then
                    echo "Error: Failed to regenerate configurations."
                    exit 1
                fi
                cp config.yaml /etc/wireguard/config.yaml.backup
                chmod 600 /etc/wireguard/config.yaml.backup

                # Define variables for firewall
                port=$(yq e '.server.port' config.yaml)
                vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
                vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
                firewall="iptables" # Default for no backup case
                configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet" "$firewall"

                # Display all client QR codes
                echo "Updated client configurations:"
                for client_conf in ~/*-wg0.conf; do
                    echo -e "\nClient: $(basename "$client_conf")"
                    qrencode -t ANSI256UTF8 < "$client_conf"
                    echo "Configuration file saved at: $client_conf"
                done
            fi

            # Restart WireGuard service to apply new configuration
            echo "Restarting WireGuard service..."
            if systemctl restart wg-quick@wg0; then
                # Verify wg0 is actually up
                if ! wg show wg0 >/dev/null 2>&1; then
                    echo "Warning: wg0 failed to restart properly, attempting manual restart..."
                    wg-quick down wg0 >/dev/null 2>&1
                    wg-quick up wg0
                    if wg show wg0 >/dev/null 2>&1; then
                        echo "WireGuard interface wg0 is now active after manual restart."
                    else
                        echo "Error: Failed to restart wg0 even after manual restart. Please check /etc/wireguard/wg0.conf."
                        exit 1
                    fi
                else
                    echo "WireGuard configurations updated and service restarted."
                fi
            else
                echo "Error: Failed to restart wg0. Please check the configuration in /etc/wireguard/wg0.conf."
                exit 1
            fi
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
