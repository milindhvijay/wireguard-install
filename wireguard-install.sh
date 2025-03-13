#!/bin/bash

# Ensure the script is run with Bash (not sh or another shell) since we use Bash-specific features like arrays
if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script must be run with Bash."
    exit 1
fi

# Check if the script is run as root, required for system changes like interface management and package installation
if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

# Detect the operating system and version from /etc/os-release for package manager compatibility
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    os=${ID}
    os_version=${VERSION_ID}
else
    echo "Error: Cannot detect operating system."
    exit 1
fi

# Function to clean up any existing WireGuard interfaces that conflict with the new server IPs
# This ensures IPs like 10.0.1.2/24 or 2a01:4f8:1c1b:743c::12/80 aren't stuck on old interfaces (e.g., vpn2)
cleanup_conflicting_interfaces() {
    local new_ipv4="$1"          # The new server's IPv4 address (e.g., 10.0.1.2)
    local new_ipv6="$2"          # The new server's IPv6 address (e.g., 2a01:4f8:1c1b:743c::12)
    local new_interface="$3"     # The new interface name (e.g., vpn3)

    # Iterate over all WireGuard interfaces currently active
    for iface in $(ip link show type wireguard | grep -oP '^\d+: \K\w+'); do
        # Skip the new interface we’re trying to create
        if [[ "$iface" != "$new_interface" ]]; then
            # Check if this interface is using either of the new IPs
            if ip addr show "$iface" | grep -q "$new_ipv4\|$new_ipv6"; then
                echo "Found conflicting interface '$iface' using IPs $new_ipv4 or $new_ipv6. Cleaning up..."
                # Stop and disable the service if it’s running
                systemctl stop wg-quick@"$iface" 2>/dev/null || echo "Service $iface not running."
                systemctl disable wg-quick@"$iface" 2>/dev/null || true
                # Delete the interface to free up the IPs
                ip link delete "$iface" 2>/dev/null || echo "Failed to delete $iface, may already be gone."
                # Remove the old config file
                rm -f "/etc/wireguard/${iface}.conf"
                echo "Removed conflicting interface '$iface' and its config."
            fi
        fi
    done
}

# Function to generate full server and client configurations from config.yaml
# This is used for initial setup or when the server config changes significantly
generate_full_configs() {
    # Extract server configuration from YAML
    port=$(yq e '.server.port' config.yaml)
    mtu=$(yq e '.server.mtu' config.yaml)
    [[ "$mtu" == "null" || -z "$mtu" ]] && mtu=1420  # Default MTU if not specified
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
    interface_name=$(yq e '.server.interface_name' config.yaml)
    [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"  # Default interface name
    ipv4_enabled=$(yq e '.server.ipv4.enabled' config.yaml)
    server_ipv4=$(yq e '.server.ipv4.address' config.yaml)
    server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)  # Extract IP without mask
    server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)  # Extract subnet mask
    base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)  # Base for client IPs (e.g., 10.0.1)
    server_ipv4_last_octet=$(echo "$server_ipv4_ip" | cut -d '.' -f 4)  # Last octet for incrementing
    ipv6_enabled=$(yq e '.server.ipv6.enabled' config.yaml)
    server_ipv6=$(yq e '.server.ipv6.address' config.yaml)
    server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)  # Extract IPv6 without prefix
    server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)  # Extract prefix length
    vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"  # Full subnet for firewall rules
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/:[0-9a-f]*$//')  # Base for client IPs (e.g., fd00::)
    server_ipv6_last_segment=$(echo "$server_ipv6_ip" | grep -o '[0-9a-f]*$')  # Last segment for incrementing

    # Clean up any conflicting interfaces before proceeding
    cleanup_conflicting_interfaces "$server_ipv4_ip" "$server_ipv6_ip" "$interface_name"

    # Create keys directory with restrictive permissions
    mkdir -p "$(dirname "$0")/keys"
    original_umask=$(umask)
    umask 077  # Ensure keys are only readable by root

    # Generate server keys
    wg genkey > "$(dirname "$0")/keys/server-${interface_name}-private.key"
    server_private_key=$(cat "$(dirname "$0")/keys/server-${interface_name}-private.key")
    echo "$server_private_key" | wg pubkey > "$(dirname "$0")/keys/server-${interface_name}-public.key"
    server_public_key=$(cat "$(dirname "$0")/keys/server-${interface_name}-public.key")
    chmod 600 "$(dirname "$0")/keys/server-${interface_name}-private.key" "$(dirname "$0")/keys/server-${interface_name}-public.key"

    # Write server configuration file
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

    # Process clients
    number_of_clients=$(yq e '.clients | length' config.yaml)
    cp config.yaml config.yaml.tmp  # Temporary file to update IPs
    mkdir -p "$(dirname "$0")/wireguard-configs"

    # Determine public endpoint (auto-detect if not specified)
    if [[ -n "$public_endpoint" && "$public_endpoint" != "null" ]]; then
        if [[ "$public_endpoint" =~ : && ! "$public_endpoint" =~ \. ]]; then
            endpoint="[$public_endpoint]"  # IPv6 needs brackets
        else
            endpoint="$public_endpoint"
        fi
    else
        endpoint=$(wget -qO- https://api6.ipify.org || curl -s https://api6.ipify.org)  # Try IPv6 first
        if [[ -n "$endpoint" ]]; then
            endpoint="[$endpoint]"
        else
            endpoint=$(wget -qO- https://api4.ipify.org || curl -s https://api4.ipify.org)  # Fall back to IPv4
            if [[ -z "$endpoint" ]]; then
                echo "Error: Could not auto-detect public IP (neither IPv6 nor IPv4)."
                return 1
            fi
        fi
    fi

    # Generate client configurations
    for i in $(seq 0 $(($number_of_clients - 1))); do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        # Calculate client IPs
        octet=$((server_ipv4_last_octet + i + 1))
        client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            client_ipv6_last_segment=$(printf "%x" $((16#$server_ipv6_last_segment + i + 1)))
            client_ipv6="${base_ipv6}:${client_ipv6_last_segment}/$server_ipv6_mask"
        fi

        # Update YAML with client IPs
        yq e -i ".clients[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".clients[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
        fi

        # Generate client keys
        client_key_dir="$(dirname "$0")/keys/${client_name}-${interface_name}"
        mkdir -p "$client_key_dir"
        wg genkey > "$client_key_dir/${client_name}-${interface_name}-private.key"
        client_private_key=$(cat "$client_key_dir/${client_name}-${interface_name}-private.key")
        echo "$client_private_key" | wg pubkey > "$client_key_dir/${client_name}-${interface_name}-public.key"
        client_public_key=$(cat "$client_key_dir/${client_name}-${interface_name}-public.key")
        wg genpsk > "$client_key_dir/${client_name}-${interface_name}-psk.key"
        psk=$(cat "$client_key_dir/${client_name}-${interface_name}-psk.key")
        chmod 600 "$client_key_dir/${client_name}-${interface_name}-private.key" \
                  "$client_key_dir/${client_name}-${interface_name}-public.key" \
                  "$client_key_dir/${client_name}-${interface_name}-psk.key"

        # Add client peer to server config
        cat << EOF >> /etc/wireguard/"${interface_name}.conf"

# BEGIN_PEER $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${base_ipv4}.${octet}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${base_ipv6}:${client_ipv6_last_segment}/128" )
# END_PEER $client_name
EOF

        # Write client config file
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

    # Restore original umask and finalize config
    umask "$original_umask"
    mv config.yaml.tmp config.yaml
    chmod 600 /etc/wireguard/"${interface_name}.conf"
}

# Function to regenerate specific client configurations when YAML changes
# This avoids regenerating everything when only client details change
generate_client_configs() {
    local changed_clients=("$@")  # Array of indices of changed clients
    port=$(yq e '.server.port' config.yaml)
    interface_name=$(yq e '.server.interface_name' config.yaml)
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
    server_public_key=$(wg show "$interface_name" public-key)  # Get existing server public key

    # Determine endpoint
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
    if [[ -n "$public_endpoint" && "$public_endpoint" != "null" ]]; then
        if [[ "$public_endpoint" =~ : && ! "$public_endpoint" =~ \. ]]; then
            endpoint="[$public_endpoint]"
        else
            endpoint="$public_endpoint"
        fi
    else
        endpoint=$(wget -qO- https://api6.ipify.org || curl -s https://api6.ipify.org)
        if [[ -n "$endpoint" ]]; then
            endpoint="[$endpoint]"
        else
            endpoint=$(wget -qO- https://api4.ipify.org || curl -s https://api4.ipify.org)
            if [[ -z "$endpoint" ]]; then
                echo "Error: Could not auto-detect public IP (neither IPv6 nor IPv4)."
                return 1
            fi
        fi
    fi

    # Prepare for client updates
    cp config.yaml config.yaml.tmp
    mkdir -p "$(dirname "$0")/keys"
    mkdir -p "$(dirname "$0")/wireguard-configs"
    original_umask=$(umask)
    umask 077

    # Process each changed client
    for i in "${changed_clients[@]}"; do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        # Calculate client IPs
        octet=$((server_ipv4_last_octet + i + 1))
        client_ipv4="${base_ipv4}.${octet}/$server_ipv4_mask"
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            client_ipv6_last_segment=$(printf "%x" $((16#$server_ipv6_last_segment + i + 1)))
            client_ipv6="${base_ipv6}:${client_ipv6_last_segment}/$server_ipv6_mask"
        fi

        # Update YAML
        yq e -i ".clients[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".clients[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
        fi

        # Generate client keys
        client_key_dir="$(dirname "$0")/keys/${client_name}-${interface_name}"
        mkdir -p "$client_key_dir"
        wg genkey > "$client_key_dir/${client_name}-${interface_name}-private.key"
        client_private_key=$(cat "$client_key_dir/${client_name}-${interface_name}-private.key")
        echo "$client_private_key" | wg pubkey > "$client_key_dir/${client_name}-${interface_name}-public.key"
        client_public_key=$(cat "$client_key_dir/${client_name}-${interface_name}-public.key")
        wg genpsk > "$client_key_dir/${client_name}-${interface_name}-psk.key"
        psk=$(cat "$client_key_dir/${client_name}-${interface_name}-psk.key")
        chmod 600 "$client_key_dir/${client_name}-${interface_name}-private.key" \
                  "$client_key_dir/${client_name}-${interface_name}-public.key" \
                  "$client_key_dir/${client_name}-${interface_name}-psk.key"

        # Remove old peer entry if name changed or update existing one
        old_name=$(yq e ".clients[$i].name" /etc/wireguard/config.yaml.backup)
        if [[ "$old_name" != "$client_name" && -n "$old_name" ]]; then
            sed -i "/# BEGIN_PEER $old_name/,/# END_PEER $old_name/d" /etc/wireguard/"${interface_name}.conf"
            rm -f "$(dirname "$0")/wireguard-configs/${old_name}-${interface_name}.conf"
            rm -rf "$(dirname "$0")/keys/${old_name}-${interface_name}"
            echo "Removed old client configuration and keys for '$old_name'."
        else
            sed -i "/# BEGIN_PEER $client_name/,/# END_PEER $client_name/d" /etc/wireguard/"${interface_name}.conf"
        fi

        # Add updated peer to server config
        cat << EOF >> /etc/wireguard/"${interface_name}.conf"

# BEGIN_PEER $client_name
[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${base_ipv4}.${octet}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${base_ipv6}:${client_ipv6_last_segment}/128" )
# END_PEER $client_name
EOF

        # Write updated client config
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

    # Finalize
    umask "$original_umask"
    mv config.yaml.tmp config.yaml
}

# Function to configure nftables firewall for NAT
# Sets up masquerade or SNAT based on dynamic/static IP settings
configure_firewall() {
    local port="$1"
    local vpn_ipv4_subnet="$2"
    local vpn_ipv6_subnet="$3"
    local host_interface=$(yq e '.server.host_interface' config.yaml)
    local ipv4_dynamic=$(yq e '.server.ipv4.dynamic' config.yaml)  # Fixed typo from ipv4_dynamic
    local ipv6_dynamic=$(yq e '.server.ipv6.dynamic' config.yaml)  # Fixed typo from ipv6_dynamic

    # Get static IPs for SNAT if not dynamic
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

    # Write nftables configuration
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

    # Apply and enable nftables
    nft -f /etc/nftables.conf
    systemctl enable nftables
    systemctl restart nftables
}

# Function to clear existing nftables rules
# Used before reapplying new rules to avoid duplicates
clear_firewall_rules() {
    nft flush ruleset
}

# Main logic starts here
# Check if the desired interface config exists to determine if this is an initial setup or management task
interface_name=$(yq e '.server.interface_name' config.yaml 2>/dev/null || echo "wg0")
[[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"

if [[ ! -e /etc/wireguard/${interface_name}.conf ]]; then
    ### Initial Setup ###

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

    # Install yq if not present (YAML parser)
    if ! command -v yq &>/dev/null; then
        echo "'yq' not found, installing it automatically..."
        wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq &&\
        chmod +x /usr/bin/yq
        if ! command -v yq &>/dev/null; then
            echo "Error: Failed to install 'yq'. Please install it manually."
            exit 1
        fi
    fi

    # Ensure config.yaml exists
    if [[ ! -f config.yaml ]]; then
        echo "Error: 'config.yaml' not found in the current directory."
        exit 1
    fi

    # Prepare WireGuard directory and backup config
    mkdir -p /etc/wireguard
    cp config.yaml /etc/wireguard/config.yaml.backup
    chmod 600 /etc/wireguard/config.yaml.backup

    # Generate all configurations
    if ! generate_full_configs; then
        echo "Error: Failed to generate configurations."
        exit 1
    fi

    # Set subnet variables for firewall (defined in generate_full_configs)
    if [[ "$ipv4_enabled" == "true" ]]; then
        vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
    fi
    if [[ "$ipv6_enabled" == "true" ]]; then
        vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    fi

    echo
    echo "WireGuard installation is ready to begin."

    # Configure firewall rules
    configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

    # Enable IP forwarding
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv6.conf.all.forwarding=1
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf

    # Start WireGuard service
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

    # Display client configurations and generate QR codes
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
    ### Management Menu for Existing Installation ###

    echo "WireGuard is already installed."
    echo "Select an option:"
    echo "   1) Re-create server and client configurations from YAML"
    echo "   2) Remove WireGuard"
    echo "   3) Exit"
    read -p "Option: " option

    case $option in
        1)
            # Re-create configurations based on YAML changes
            if [[ ! -f config.yaml ]]; then
                echo "Error: 'config.yaml' not found in the current directory."
                exit 1
            fi

            # Extract key server details
            port=$(yq e '.server.port' config.yaml)
            interface_name=$(yq e '.server.interface_name' config.yaml)
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

            if [[ -f /etc/wireguard/config.yaml.backup ]]; then
                # Compare current and backup YAML to detect changes
                if cmp -s config.yaml /etc/wireguard/config.yaml.backup; then
                    echo "No changes detected in config.yaml. No action taken."
                    exit 0
                fi

                # Handle interface name change
                old_interface_name=$(yq e '.server.interface_name' /etc/wireguard/config.yaml.backup)
                [[ "$old_interface_name" == "null" || -z "$old_interface_name" ]] && old_interface_name="wg0"
                if [[ "$interface_name" != "$old_interface_name" ]]; then
                    echo "Interface name changed from '$old_interface_name' to '$interface_name'. Cleaning up old interface..."
                    systemctl stop wg-quick@"$old_interface_name" 2>/dev/null || echo "Old service $old_interface_name not running."
                    systemctl disable wg-quick@"$old_interface_name" 2>/dev/null || true
                    ip link delete "$old_interface_name" 2>/dev/null || echo "Old interface $old_interface_name not found or already removed."
                    if [[ -f "/etc/wireguard/${old_interface_name}.conf" ]]; then
                        rm -f "/etc/wireguard/${old_interface_name}.conf"
                        echo "Removed old configuration file: /etc/wireguard/${old_interface_name}.conf"
                    fi
                fi

                # Check if server config changed
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

                    clear_firewall_rules
                    configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

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
                    # Only client changes detected
                    changed_clients=()
                    number_of_clients=$(yq e '.clients | length' config.yaml)
                    old_clients=$(yq e '.clients | length' /etc/wireguard/config.yaml.backup)
                    max_clients=$((number_of_clients > old_clients ? number_of_clients : old_clients))

                    for i in $(seq 0 $((max_clients - 1))); do
                        new_name=$(yq e ".clients[$i].name" config.yaml)
                        old_name=$(yq e ".clients[$i].name" /etc/wireguard/config.yaml.backup)
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

                        clear_firewall_rules
                        configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

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
                # No backup exists, treat as full regeneration
                echo "No backup found. Regenerating all configurations..."
                if ! generate_full_configs; then
                    echo "Error: Failed to regenerate configurations."
                    exit 1
                fi
                cp config.yaml /etc/wireguard/config.yaml.backup
                chmod 600 /etc/wireguard/config.yaml.backup

                clear_firewall_rules
                configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

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

            # Restart WireGuard with updated config
            echo "Restarting WireGuard service with new interface '$interface_name'..."
            if systemctl restart wg-quick@"$interface_name"; then
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
            # Remove WireGuard completely
            interface_name=$(yq e '.server.interface_name' config.yaml)
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            systemctl disable --now wg-quick@"$interface_name"

            # Clean up nftables rules
            if [[ -f /etc/nftables.conf ]]; then
                echo "Cleaning up WireGuard-specific nftables rules..."
                nft delete table inet wireguard 2>/dev/null || echo "No WireGuard table found in running config, skipping."
                cp /etc/nftables.conf /etc/nftables.conf.backup-$(date +%F-%T)
                sed -i '/table inet wireguard {/,/}/d' /etc/nftables.conf

                if [[ ! -s /etc/nftables.conf || $(grep -v '^#!/usr/sbin/nft -f' /etc/nftables.conf | grep -v '^flush ruleset' | wc -l) -eq 0 ]]; then
                    rm -f /etc/nftables.conf
                    systemctl disable nftables
                    systemctl stop nftables
                    echo "Removed /etc/nftables.conf and disabled nftables service (no other rules present)."
                else
                    nft -f /etc/nftables.conf
                    echo "Updated /etc/nftables.conf to remove WireGuard rules."
                fi
            fi

            # Remove generated files
            if [[ -d "$(dirname "$0")/wireguard-configs" ]]; then
                rm -rf "$(dirname "$0")/wireguard-configs"
                echo "Removed client configuration directory (including QR codes): $(dirname "$0")/wireguard-configs"
            fi
            if [[ -d "$(dirname "$0")/keys" ]]; then
                rm -rf "$(dirname "$0")/keys"
                echo "Removed keys directory: $(dirname "$0")/keys"
            fi

            # Uninstall WireGuard
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
