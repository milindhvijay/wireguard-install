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
    # Default to 1420 if server mtu is not specified or null
    [[ "$mtu" == "null" || -z "$mtu" ]] && mtu=1420
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
    interface_name=$(yq e '.server.interface_name' config.yaml)
    # Default to wg0 if interface_name is not specified or null
    [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
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

    # Ensure keys directory exists
    mkdir -p "$(dirname "$0")/keys"

    # Generate and save server keys (directly in keys/)
    wg genkey > "$(dirname "$0")/keys/server-${interface_name}-private.key"
    server_private_key=$(cat "$(dirname "$0")/keys/server-${interface_name}-private.key")
    echo "$server_private_key" | wg pubkey > "$(dirname "$0")/keys/server-${interface_name}-public.key"
    server_public_key=$(cat "$(dirname "$0")/keys/server-${interface_name}-public.key")
    chmod 600 "$(dirname "$0")/keys/server-${interface_name}-private.key" "$(dirname "$0")/keys/server-${interface_name}-public.key"

    # Create server configuration file with dynamic interface name
    cat << EOF > /etc/wireguard/"${interface_name}.conf"
# Do not alter the commented lines
# They are used by wireguard-install
# ENDPOINT [to be set]

[Interface]
Address = $server_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $server_ipv6" )
PrivateKey = $server_private_key
ListenPort = $port
MTU = $mtu
EOF

    # Generate all client configurations and update YAML
    number_of_clients=$(yq e '.clients | length' config.yaml)

    # Temporary file for YAML updates
    cp config.yaml config.yaml.tmp

    # Ensure wireguard-configs directory exists
    mkdir -p "$(dirname "$0")/wireguard-configs"

    for i in $(seq 0 $(($number_of_clients - 1))); do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        # Default to 1420 if client mtu is not specified or null
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        # Calculate client IPs relative to server IP
        octet=$((server_ipv4_last_octet + i + 1))
        client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            client_ipv6_last_segment=$(printf "%x" $((16#$server_ipv6_last_segment + i + 1)))
            client_ipv6="${base_ipv6}:${client_ipv6_last_segment}/$server_ipv6_mask"
        fi

        # Update YAML with assigned client IPs
        yq e -i ".clients[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".clients[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
        fi

        # Create client-specific key subfolder
        client_key_dir="$(dirname "$0")/keys/${client_name}-${interface_name}"
        mkdir -p "$client_key_dir"

        # Generate and save client keys in the subfolder
        wg genkey > "$client_key_dir/${client_name}-${interface_name}-private.key"
        client_private_key=$(cat "$client_key_dir/${client_name}-${interface_name}-private.key")
        echo "$client_private_key" | wg pubkey > "$client_key_dir/${client_name}-${interface_name}-public.key"
        client_public_key=$(cat "$client_key_dir/${client_name}-${interface_name}-public.key")
        wg genpsk > "$client_key_dir/${client_name}-${interface_name}-psk.key"
        psk=$(cat "$client_key_dir/${client_name}-${interface_name}-psk.key")
        chmod 600 "$client_key_dir/${client_name}-${interface_name}-private.key" \
                  "$client_key_dir/${client_name}-${interface_name}-public.key" \
                  "$client_key_dir/${client_name}-${interface_name}-psk.key"

        # Append client to server config
        cat << EOF >> /etc/wireguard/"${interface_name}.conf"

# BEGIN_PEER $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${base_ipv4}.${octet}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${base_ipv6}:${client_ipv6_last_segment}/128" )
# END_PEER $client_name
EOF

        # Create client configuration file in wireguard-configs subfolder
        cat << EOF > "$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
[Interface]
Address = $client_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $client_ipv6" )
DNS = $client_dns
PrivateKey = $client_private_key
MTU = $client_mtu

[Peer]
PublicKey = $server_public_key
PresharedKey = $psk
AllowedIPs = $client_allowed_ips
Endpoint = [to be set]:$port
PersistentKeepalive = $client_persistent_keepalive
EOF
        chmod 600 "$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
    done

    # Replace original YAML with updated version
    mv config.yaml.tmp config.yaml

    # Set secure permissions for server config
    chmod 600 /etc/wireguard/"${interface_name}.conf"

    # Detect public endpoint, preferring IPv6
    if [[ -n "$public_endpoint" && "$public_endpoint" != "null" ]]; then
        endpoint="$public_endpoint"
    else
        # Check for global IPv6 address
        endpoint=$(wget -qO- https://api6.ipify.org || curl -s https://api6.ipify.org)
        if [[ -n "$endpoint" ]]; then
            endpoint="[$endpoint]" # Wrap IPv6 in brackets for WireGuard
        else
            # Fall back to IPv4
            endpoint=$(wget -qO- https://api4.ipify.org || curl -s https://api4.ipify.org)
            if [[ -z "$endpoint" ]]; then
                echo "Error: Could not auto-detect public IP (neither IPv6 nor IPv4)."
                return 1
            fi
        fi
    fi

    # Update client configuration files with the endpoint
    for client_conf in "$(dirname "$0")/wireguard-configs"/*-"${interface_name}.conf"; do
        sed -i "s/Endpoint = \[to be set\]:$port/Endpoint = $endpoint:$port/" "$client_conf"
    done
}

# Function to regenerate specific client configurations
generate_client_configs() {
    local changed_clients=("$@") # Array of client indices to regenerate
    port=$(yq e '.server.port' config.yaml)
    interface_name=$(yq e '.server.interface_name' config.yaml)
    # Default to wg0 if interface_name is not specified or null
    [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
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
    server_public_key=$(wg show "$interface_name" public-key)

    # Detect public endpoint, preferring IPv6
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
    if [[ -n "$public_endpoint" && "$public_endpoint" != "null" ]]; then
        endpoint="$public_endpoint"
    else
        # Check for global IPv6 address
        endpoint=$(wget -qO- https://api6.ipify.org || curl -s https://api6.ipify.org)
        if [[ -n "$endpoint" ]]; then
            endpoint="[$endpoint]" # Wrap IPv6 in brackets for WireGuard
        else
            # Fall back to IPv4
            endpoint=$(wget -qO- https://api4.ipify.org || curl -s https://api4.ipify.org)
            if [[ -z "$endpoint" ]]; then
                echo "Error: Could not auto-detect public IP (neither IPv6 nor IPv4)."
                return 1
            fi
        fi
    fi

    # Temporary file for YAML updates
    cp config.yaml config.yaml.tmp

    # Ensure directories exist
    mkdir -p "$(dirname "$0")/keys"
    mkdir -p "$(dirname "$0")/wireguard-configs"

    for i in "${changed_clients[@]}"; do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        # Default to 1420 if mtu is not specified or null
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        # Calculate client IPs relative to server IP
        octet=$((server_ipv4_last_octet + i + 1))
        client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            client_ipv6_last_segment=$(printf "%x" $((16#$server_ipv6_last_segment + i + 1)))
            client_ipv6="${base_ipv6}:${client_ipv6_last_segment}/$server_ipv6_mask"
        fi

        # Update YAML with assigned client IPs
        yq e -i ".clients[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".clients[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
        fi

        # Create client-specific key subfolder
        client_key_dir="$(dirname "$0")/keys/${client_name}-${interface_name}"
        mkdir -p "$client_key_dir"

        # Generate and save client keys in the subfolder
        wg genkey > "$client_key_dir/${client_name}-${interface_name}-private.key"
        client_private_key=$(cat "$client_key_dir/${client_name}-${interface_name}-private.key")
        echo "$client_private_key" | wg pubkey > "$client_key_dir/${client_name}-${interface_name}-public.key"
        client_public_key=$(cat "$client_key_dir/${client_name}-${interface_name}-public.key")
        wg genpsk > "$client_key_dir/${client_name}-${interface_name}-psk.key"
        psk=$(cat "$client_key_dir/${client_name}-${interface_name}-psk.key")
        chmod 600 "$client_key_dir/${client_name}-${interface_name}-private.key" \
                  "$client_key_dir/${client_name}-${interface_name}-public.key" \
                  "$client_key_dir/${client_name}-${interface_name}-psk.key"

        # Remove old peer section from server config based on name (if it exists)
        old_name=$(yq e ".clients[$i].name" /etc/wireguard/config.yaml.backup)
        if [[ "$old_name" != "$client_name" && -n "$old_name" ]]; then
            sed -i "/# BEGIN_PEER $old_name/,/# END_PEER $old_name/d" /etc/wireguard/"${interface_name}.conf"
            rm -f "$(dirname "$0")/wireguard-configs/${old_name}-${interface_name}.conf"
            rm -rf "$(dirname "$0")/keys/${old_name}-${interface_name}"
            echo "Removed old client configuration and keys for '$old_name'."
        else
            sed -i "/# BEGIN_PEER $client_name/,/# END_PEER $client_name/d" /etc/wireguard/"${interface_name}.conf"
        fi

        # Append updated client to server config
        cat << EOF >> /etc/wireguard/"${interface_name}.conf"

# BEGIN_PEER $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${base_ipv4}.${octet}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${base_ipv6}:${client_ipv6_last_segment}/128" )
# END_PEER $client_name
EOF

        # Regenerate client configuration file in wireguard-configs subfolder
        cat << EOF > "$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
[Interface]
Address = $client_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $client_ipv6" )
DNS = $client_dns
PrivateKey = $client_private_key
MTU = $client_mtu

[Peer]
PublicKey = $server_public_key
PresharedKey = $psk
AllowedIPs = $client_allowed_ips
Endpoint = $endpoint:$port
PersistentKeepalive = $client_persistent_keepalive
EOF
        chmod 600 "$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
    done

    # Replace original YAML with updated version
    mv config.yaml.tmp config.yaml
}

# Function to configure firewall with nftables
configure_firewall() {
    local port="$1"
    local vpn_ipv4_subnet="$2"
    local vpn_ipv6_subnet="$3"
    local host_interface=$(yq e '.server.host_interface' config.yaml)
    local ipv4_dynamic=$(yq e '.server.ipv4_dynamic' config.yaml)
    local ipv6_dynamic=$(yq e '.server.ipv6_dynamic' config.yaml)

    server_ipv4_static=$(ip -4 addr show "$host_interface" | grep -oP 'inet \K[\d.]+' | head -n 1)
    if [[ -z "$server_ipv4_static" && "$ipv4_enabled" == "true" && "$ipv4_dynamic" != "true" ]]; then
        echo "Error: Could not detect IPv4 address for $host_interface and ipv4_dynamic is not set to true."
        return 1
    fi

    server_ipv6_static=$(ip -6 addr show "$host_interface" scope global | grep -oP 'inet6 \K[0-9a-f:]+' | head -n 1)
    if [[ -z "$server_ipv6_static" && "$ipv6_enabled" == "true" && "$ipv6_dynamic" != "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
        echo "Error: Could not detect IPv6 address for $host_interface and ipv6_dynamic is not set to true."
        return 1
    fi

    cat << EOF > /etc/nftables.conf
#!/usr/sbin/nft -f

flush ruleset

table inet wireguard {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
        $( [[ "$ipv4_enabled" == "true" && "$ipv4_dynamic" == "true" ]] && echo "ip saddr $vpn_ipv4_subnet oifname \"$host_interface\" masquerade persistent" )
        $( [[ "$ipv4_enabled" == "true" && "$ipv4_dynamic" != "true" && -n "$server_ipv4_static" ]] && echo "ip saddr $vpn_ipv4_subnet oifname \"$host_interface\" snat to $server_ipv4_static persistent" )
        $( [[ "$ipv6_enabled" == "true" && "$ipv6_dynamic" == "true" ]] && echo "ip6 saddr $vpn_ipv6_subnet oifname \"$host_interface\" masquerade persistent" )
        $( [[ "$ipv6_enabled" == "true" && "$ipv6_dynamic" != "true" && -n "$server_ipv6_static" ]] && echo "ip6 saddr $vpn_ipv6_subnet oifname \"$host_interface\" snat to $server_ipv6_static persistent" )
    }
}
EOF

    nft -f /etc/nftables.conf
    systemctl enable nftables
    systemctl restart nftables
}

# Function to clear existing firewall rules with nftables
clear_firewall_rules() {
    nft flush ruleset
}

# Main installation logic
interface_name=$(yq e '.server.interface_name' config.yaml 2>/dev/null || echo "wg0")
[[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"

if [[ ! -e /etc/wireguard/${interface_name}.conf ]]; then
    ### System Setup ###

    echo "Installing WireGuard and nftables packages..."
    if [[ "$os" == "ubuntu" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode nftables
    elif [[ "$os" == "debian" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode nftables
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        dnf install -y wireguard-tools qrencode nftables
    else
        echo "Error: Unsupported OS."
        exit 1
    fi

    ### YAML-Based Initial Setup ###

    if ! command -v yq &>/dev/null; then
        echo "'yq' not found, installing it automatically..."
        wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq &&\
        chmod +x /usr/bin/yq
        if ! command -v yq &>/dev/null; then
            echo "Error: Failed to install 'yq'. Please install it manually."
            exit 1
        fi
    fi

    if [[ ! -f config.yaml ]]; then
        echo "Error: 'config.yaml' not found in the current directory."
        exit 1
    fi

    mkdir -p /etc/wireguard
    cp config.yaml /etc/wireguard/config.yaml.backup
    chmod 600 /etc/wireguard/config.yaml.backup

    if ! generate_full_configs; then
        echo "Error: Failed to generate configurations."
        exit 1
    fi

    if [[ "$ipv4_enabled" == "true" ]]; then
        vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
    fi
    if [[ "$ipv6_enabled" == "true" ]]; then
        vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    fi

    echo
    echo "WireGuard installation is ready to begin."

    configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

    echo "Activating WireGuard interface..."
    if systemctl enable --now wg-quick@${interface_name}; then
        if ! wg show ${interface_name} >/dev/null 2>&1; then
            echo "Warning: ${interface_name} failed to start properly, attempting manual restart..."
            wg-quick down ${interface_name} >/dev/null 2>&1
            wg-quick up ${interface_name}
            if wg show ${interface_name} >/dev/null 2>&1; then
                echo "WireGuard interface ${interface_name} is now active after manual restart."
            else
                echo "Error: Failed to activate ${interface_name} even after manual restart. Please check /etc/wireguard/${interface_name}.conf."
                exit 1
            fi
        else
            echo "WireGuard interface ${interface_name} is now active."
        fi
    else
        echo "Error: Failed to activate ${interface_name}. Please check the configuration in /etc/wireguard/${interface_name}.conf."
        exit 1
    fi

    echo "WireGuard setup complete. Here are the client configurations:"
    if ls "$(dirname "$0")/wireguard-configs"/*-"${interface_name}.conf" >/dev/null 2>&1; then
        mkdir -p "$(dirname "$0")/wireguard-configs/qr"
        for client_conf in "$(dirname "$0")/wireguard-configs"/*-"${interface_name}.conf"; do
            client_name=$(basename "$client_conf" .conf)
            qr_file="$(dirname "$0")/wireguard-configs/qr/${client_name}.png"
            echo -e "\nClient: $client_name"
            qrencode -t ANSI256UTF8 < "$client_conf"
            qrencode -o "$qr_file" < "$client_conf"
            echo "Configuration file saved at: $client_conf"
            echo "QR code image saved at: $qr_file"
        done
    else
        echo "No client configuration files found in $(dirname "$0")/wireguard-configs/."
    fi

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

            # Define variables needed for firewall and config generation
            port=$(yq e '.server.port' config.yaml)
            interface_name=$(yq e '.server.interface_name' config.yaml)
            # Default to wg0 if interface_name is not specified or null
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
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

            # Compare with previous YAML backup
            if [[ -f /etc/wireguard/config.yaml.backup ]]; then
                if cmp -s config.yaml /etc/wireguard/config.yaml.backup; then
                    echo "No changes detected in config.yaml. No action taken."
                    exit 0
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

                    # Clear and reconfigure firewall rules with nftables
                    clear_firewall_rules
                    configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

                    # Display all client QR codes
                    echo "Updated client configurations:"
                    if ls "$(dirname "$0")/wireguard-configs"/*-"${interface_name}.conf" >/dev/null 2>&1; then
                        mkdir -p "$(dirname "$0")/wireguard-configs/qr"
                        for client_conf in "$(dirname "$0")/wireguard-configs"/*-"${interface_name}.conf"; do
                            client_name=$(basename "$client_conf" .conf)
                            qr_file="$(dirname "$0")/wireguard-configs/qr/${client_name}.png"
                            echo -e "\nClient: $client_name"
                            qrencode -t ANSI256UTF8 < "$client_conf"
                            qrencode -o "$qr_file" < "$client_conf"
                            echo "Configuration file saved at: $client_conf"
                            echo "QR code image saved at: $qr_file"
                        done
                    else
                        echo "No client configuration files found in $(dirname "$0")/wireguard-configs/."
                    fi
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

                        # Clear and reconfigure firewall rules with nftables
                        clear_firewall_rules
                        configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

                        # Display QR codes only for changed clients
                        echo "Updated client configurations:"
                        mkdir -p "$(dirname "$0")/wireguard-configs/qr"
                        for i in "${changed_clients[@]}"; do
                            client_name=$(yq e ".clients[$i].name" config.yaml)
                            client_conf="$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
                            qr_file="$(dirname "$0")/wireguard-configs/qr/${client_name}-${interface_name}.png"
                            if [[ -f "$client_conf" ]]; then
                                echo -e "\nClient: ${client_name}-${interface_name}"
                                qrencode -t ANSI256UTF8 < "$client_conf"
                                qrencode -o "$qr_file" < "$client_conf"
                                echo "Configuration file saved at: $client_conf"
                                echo "QR code image saved at: $qr_file"
                            else
                                echo "Warning: Configuration file for $client_name not found at $client_conf."
                            fi
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

                # Clear and reconfigure firewall rules with nftables
                clear_firewall_rules
                configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

                # Display all client QR codes
                echo "Updated client configurations:"
                if ls "$(dirname "$0")/wireguard-configs"/*-"${interface_name}.conf" >/dev/null 2>&1; then
                    mkdir -p "$(dirname "$0")/wireguard-configs/qr"
                    for client_conf in "$(dirname "$0")/wireguard-configs"/*-"${interface_name}.conf"; do
                        client_name=$(basename "$client_conf" .conf)
                        qr_file="$(dirname "$0")/wireguard-configs/qr/${client_name}.png"
                        echo -e "\nClient: $client_name"
                        qrencode -t ANSI256UTF8 < "$client_conf"
                        qrencode -o "$qr_file" < "$client_conf"
                        echo "Configuration file saved at: $client_conf"
                        echo "QR code image saved at: $qr_file"
                    done
                else
                    echo "No client configuration files found in $(dirname "$0")/wireguard-configs/."
                fi
            fi

            # Restart WireGuard service to apply new configuration
            echo "Restarting WireGuard service..."
            if systemctl restart wg-quick@"$interface_name"; then
                # Verify interface is actually up
                if ! wg show "$interface_name" >/dev/null 2>&1; then
                    echo "Warning: $interface_name failed to restart properly, attempting manual restart..."
                    wg-quick down "$interface_name" >/dev/null 2>&1
                    wg-quick up "$interface_name"
                    if wg show "$interface_name" >/dev/null 2>&1; then
                        echo "WireGuard interface $interface_name is now active after manual restart."
                    else
                        echo "Error: Failed to restart $interface_name even after manual restart. Please check /etc/wireguard/${interface_name}.conf."
                        exit 1
                    fi
                else
                    echo "WireGuard configurations updated and service restarted."
                fi
            else
                echo "Error: Failed to restart $interface_name. Please check the configuration in /etc/wireguard/${interface_name}.conf."
                exit 1
            fi
            ;;
        2)
            interface_name=$(yq e '.server.interface_name' config.yaml)
            # Default to wg0 if interface_name is not specified or null
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            systemctl disable --now wg-quick@"$interface_name"

            # Stop and disable nftables if it’s only used for WireGuard, or clean up WireGuard rules
            if [[ -f /etc/nftables.conf ]]; then
                echo "Cleaning up WireGuard-specific nftables rules..."
                # Remove the wireguard table from the running configuration
                nft delete table inet wireguard 2>/dev/null || echo "No WireGuard table found in running config, skipping."

                # Backup the original nftables.conf
                cp /etc/nftables.conf /etc/nftables.conf.backup-$(date +%F-%T)

                # Remove WireGuard-specific section from /etc/nftables.conf
                sed -i '/table inet wireguard {/,/}/d' /etc/nftables.conf

                # If the file is now empty (or nearly empty), remove it and disable nftables
                if [[ ! -s /etc/nftables.conf || $(grep -v '^#!/usr/sbin/nft -f' /etc/nftables.conf | grep -v '^flush ruleset' | wc -l) -eq 0 ]]; then
                    rm -f /etc/nftables.conf
                    systemctl disable nftables
                    systemctl stop nftables
                    echo "Removed /etc/nftables.conf and disabled Fancy seeing you here! nftables service (no other rules present)."
                else
                    # Reload nftables to apply the updated rules
                    nft -f /etc/nftables.conf
                    echo "Updated /etc/nftables.conf to remove WireGuard rules."
                fi
            fi

            # Remove the wireguard-configs and keys directories
            if [[ -d "$(dirname "$0")/wireguard-configs" ]]; then
                rm -rf "$(dirname "$0")/wireguard-configs"
                echo "Removed client configuration directory (including QR codes): $(dirname "$0")/wireguard-configs"
            fi
            if [[ -d "$(dirname "$0")/keys" ]]; then
                rm -rf "$(dirname "$0")/keys"
                echo "Removed keys directory: $(dirname "$0")/keys"
            fi

            rm -rf /etc/wireguard
            if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
                apt-get remove -y wireguard wireguard-tools nftables
            elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
                dnf remove -y wireguard-tools nftables
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
