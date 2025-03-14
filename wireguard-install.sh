#!/bin/bash

if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script must be run with Bash."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    os=${ID}
    os_version=${VERSION_ID}
else
    echo "Error: Cannot detect operating system."
    exit 1
fi

# Helper function to check if an IPv4 address is in use
is_ipv4_in_use() {
    local ip="$1"
    local used_ips=("${@:2}")
    for used_ip in "${used_ips[@]}"; do
        if [[ "$used_ip" == "$ip" ]]; then
            return 0  # True, IP is in use
        fi
    done
    return 1  # False, IP is not in use
}

# Helper function to check if an IPv6 address is in use
is_ipv6_in_use() {
    local ip="$1"
    local used_ips=("${@:2}")
    for used_ip in "${used_ips[@]}"; do
        if [[ "$used_ip" == "$ip" ]]; then
            return 0  # True, IP is in use
        fi
    done
    return 1  # False, IP is not in use
}

# Helper function to find the next available IPv4 address
find_next_ipv4() {
    local base_ipv4="$1"
    local mask="$2"
    local used_ips=("${@:3}")
    local octet=2  # Start after the server IP (e.g., 10.0.0.1 -> 10.0.0.2)
    local max_octet=$((256 - 1))  # Assuming a /24 subnet for simplicity
    while [[ $octet -le $max_octet ]]; do
        local candidate="${base_ipv4}.${octet}"
        if ! is_ipv4_in_use "$candidate" "${used_ips[@]}"; then
            echo "$candidate/$mask"
            return 0
        fi
        ((octet++))
    done
    echo "Error: No available IPv4 addresses in $base_ipv4.0/$mask."
    return 1
}

# Helper function to find the next available IPv6 address
find_next_ipv6() {
    local base_ipv6="$1"
    local mask="$2"
    local used_ips=("${@:3}")
    local segment=2  # Start after the server IP (e.g., fd00::1 -> fd00::2)
    local max_segment=$((16#ffff))  # Assuming a /112 subnet for simplicity
    while [[ $segment -le $max_segment ]]; do
        local candidate_segment=$(printf "%x" "$segment")
        local candidate="${base_ipv6}:${candidate_segment}"
        if ! is_ipv6_in_use "$candidate" "${used_ips[@]}"; then
            echo "$candidate/$mask"
            return 0
        fi
        ((segment++))
    done
    echo "Error: No available IPv6 addresses in $base_ipv6::$mask."
    return 1
}

# Helper function to check for duplicate client names
check_duplicate_client_names() {
    local number_of_clients=$(yq e '.clients | length' config.yaml)
    local -A names_seen
    for i in $(seq 0 $(($number_of_clients - 1))); do
        local client_name=$(yq e ".clients[$i].name" config.yaml)
        if [[ -z "$client_name" || "$client_name" == "null" ]]; then
            echo "Error: Client at index $i has no name specified in config.yaml."
            return 1
        fi
        if [[ -n "${names_seen[$client_name]}" ]]; then
            echo "Error: Duplicate client name '$client_name' found in config.yaml."
            return 1
        fi
        names_seen["$client_name"]=1
    done
    return 0
}

cleanup_conflicting_interfaces() {
    local new_ipv4="$1"
    local new_ipv6="$2"
    local new_interface="$3"

    for iface in $(ip link show type wireguard | grep -oP '^\d+: \K\w+'); do
        if [[ "$iface" != "$new_interface" ]]; then
            if ip addr show "$iface" | grep -q "$new_ipv4\|$new_ipv6"; then
                echo "Found conflicting interface '$iface' using IPs $new_ipv4 or $new_ipv6. Cleaning up..."
                systemctl stop wg-quick@"$iface" 2>/dev/null || echo "Service $iface not running."
                systemctl disable wg-quick@"$iface" 2>/dev/null || true
                ip link delete "$iface" 2>/dev/null || echo "Failed to delete $iface, may already be gone."
                rm -f "/etc/wireguard/${iface}.conf"
                echo "Removed conflicting interface '$iface' and its config."
            fi
        fi
    done
}

generate_full_configs() {
    # Check for duplicate client names before proceeding
    if ! check_duplicate_client_names; then
        return 1
    fi

    port=$(yq e '.server.port' config.yaml)
    mtu=$(yq e '.server.mtu' config.yaml)
    [[ "$mtu" == "null" || -z "$mtu" ]] && mtu=1420
    public_endpoint=$(yq e '.server.public_endpoint' config.yaml)
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
    vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/:[0-9a-f]*$//')

    cleanup_conflicting_interfaces "$server_ipv4_ip" "$server_ipv6_ip" "$interface_name"

    mkdir -p "$(dirname "$0")/keys"
    original_umask=$(umask)
    umask 077

    wg genkey > "$(dirname "$0")/keys/server-${interface_name}-private.key"
    server_private_key=$(cat "$(dirname "$0")/keys/server-${interface_name}-private.key")
    echo "$server_private_key" | wg pubkey > "$(dirname "$0")/keys/server-${interface_name}-public.key"
    server_public_key=$(cat "$(dirname "$0")/keys/server-${interface_name}-public.key")
    chmod 600 "$(dirname "$0")/keys/server-${interface_name}-private.key" "$(dirname "$0")/keys/server-${interface_name}-public.key"

    cat << EOF > /etc/wireguard/"${interface_name}.conf"
[Interface]
Address = $server_ipv4$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $server_ipv6" )
PrivateKey = $server_private_key
ListenPort = $port
MTU = $mtu
EOF

    number_of_clients=$(yq e '.clients | length' config.yaml)
    cp config.yaml config.yaml.tmp
    mkdir -p "$(dirname "$0")/wireguard-configs"

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

    # Collect all assigned IPs from config.yaml
    local -a used_ipv4s=("$server_ipv4_ip")
    local -a used_ipv6s=("$server_ipv6_ip")
    for i in $(seq 0 $(($number_of_clients - 1))); do
        local ipv4=$(yq e ".clients[$i].ipv4_address" config.yaml)
        local ipv6=$(yq e ".clients[$i].ipv6_address" config.yaml)
        [[ "$ipv4" != "null" && -n "$ipv4" ]] && used_ipv4s+=("$(echo "$ipv4" | cut -d '/' -f 1)")
        [[ "$ipv6" != "null" && -n "$ipv6" ]] && used_ipv6s+=("$(echo "$ipv6" | cut -d '/' -f 1)")
    done

    for i in $(seq 0 $(($number_of_clients - 1))); do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        client_ipv4=$(yq e ".clients[$i].ipv4_address" config.yaml)
        if [[ "$ipv4_enabled" == "true" && ( "$client_ipv4" == "null" || -z "$client_ipv4" ) ]]; then
            client_ipv4=$(find_next_ipv4 "$base_ipv4" "$server_ipv4_mask" "${used_ipv4s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv4"
                return 1
            fi
            used_ipv4s+=("$(echo "$client_ipv4" | cut -d '/' -f 1)")
        fi

        client_ipv6=$(yq e ".clients[$i].ipv6_address" config.yaml)
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 && ( "$client_ipv6" == "null" || -z "$client_ipv6" ) ]]; then
            client_ipv6=$(find_next_ipv6 "$base_ipv6" "$server_ipv6_mask" "${used_ipv6s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv6"
                return 1
            fi
            used_ipv6s+=("$(echo "$client_ipv6" | cut -d '/' -f 1)")
        fi

        yq e -i ".clients[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".clients[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
        fi

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

        client_ipv4_ip=$(echo "$client_ipv4" | cut -d '/' -f 1)
        client_ipv6_ip=$(echo "$client_ipv6" | cut -d '/' -f 1)
        cat << EOF >> /etc/wireguard/"${interface_name}.conf"

[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${client_ipv4_ip}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${client_ipv6_ip}/128" )
EOF

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
$( [[ "$client_persistent_keepalive" != "null" && -n "$client_persistent_keepalive" ]] && echo "PersistentKeepalive = $client_persistent_keepalive" )
EOF
        chmod 600 "$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
    done

    umask "$original_umask"
    mv config.yaml.tmp config.yaml
    chmod 600 /etc/wireguard/"${interface_name}.conf"
}

generate_client_configs() {
    local changed_clients=("$@")

    # Check for duplicate client names before proceeding
    if ! check_duplicate_client_names; then
        return 1
    fi

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
    vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/:[0-9a-f]*$//')
    server_public_key=$(wg show "$interface_name" public-key)

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

    cp config.yaml config.yaml.tmp
    mkdir -p "$(dirname "$0")/keys"
    mkdir -p "$(dirname "$0")/wireguard-configs"
    original_umask=$(umask)
    umask 077

    # Collect all assigned IPs from config.yaml and existing config
    local -a used_ipv4s=("$server_ipv4_ip")
    local -a used_ipv6s=("$server_ipv6_ip")
    local number_of_clients=$(yq e '.clients | length' config.yaml)
    for i in $(seq 0 $(($number_of_clients - 1))); do
        local ipv4=$(yq e ".clients[$i].ipv4_address" config.yaml)
        local ipv6=$(yq e ".clients[$i].ipv6_address" config.yaml)
        [[ "$ipv4" != "null" && -n "$ipv4" ]] && used_ipv4s+=("$(echo "$ipv4" | cut -d '/' -f 1)")
        [[ "$ipv6" != "null" && -n "$ipv6" ]] && used_ipv6s+=("$(echo "$ipv6" | cut -d '/' -f 1)")
    done

    for i in "${changed_clients[@]}"; do
        client_name=$(yq e ".clients[$i].name" config.yaml)
        client_dns=$(yq e ".clients[$i].dns" config.yaml)
        client_mtu=$(yq e ".clients[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".clients[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".clients[$i].persistent_keepalive" config.yaml)

        client_ipv4=$(yq e ".clients[$i].ipv4_address" config.yaml)
        if [[ "$ipv4_enabled" == "true" && ( "$client_ipv4" == "null" || -z "$client_ipv4" ) ]]; then
            client_ipv4=$(find_next_ipv4 "$base_ipv4" "$server_ipv4_mask" "${used_ipv4s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv4"
                return 1
            fi
            used_ipv4s+=("$(echo "$client_ipv4" | cut -d '/' -f 1)")
        fi

        client_ipv6=$(yq e ".clients[$i].ipv6_address" config.yaml)
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 && ( "$client_ipv6" == "null" || -z "$client_ipv6" ) ]]; then
            client_ipv6=$(find_next_ipv6 "$base_ipv6" "$server_ipv6_mask" "${used_ipv6s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv6"
                return 1
            fi
            used_ipv6s+=("$(echo "$client_ipv6" | cut -d '/' -f 1)")
        fi

        yq e -i ".clients[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".clients[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
        fi

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

        client_ipv4_ip=$(echo "$client_ipv4" | cut -d '/' -f 1)
        client_ipv6_ip=$(echo "$client_ipv6" | cut -d '/' -f 1)
        client_allowed_ips_combined="${client_ipv4_ip}/32$( [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${client_ipv6_ip}/128" )"

        # Handle name change cleanup
        old_name=$(yq e ".clients[$i].name" /etc/wireguard/config.yaml.backup)
        if [[ "$old_name" != "$client_name" && -n "$old_name" ]]; then
            rm -f "$(dirname "$0")/wireguard-configs/${old_name}-${interface_name}.conf"
            rm -rf "$(dirname "$0")/keys/${old_name}-${interface_name}"
        fi

        # Remove the old [Peer] entry and preserve all others with consistent spacing
        temp_file=$(mktemp)
        awk -v ip="$client_ipv4_ip" '
        BEGIN { in_section = 0; buffer = ""; need_blank = 0 }
        /^\[(Interface|Peer)\]$/ {
            if (in_section && keep) {
                if (need_blank) { print "" }
                print buffer
                need_blank = 1
            }
            in_section = 1; keep = ($1 == "[Interface]" ? 1 : 0); buffer = $0 "\n"; next
        }
        in_section && /AllowedIPs =/ {
            if ($0 ~ ip) { keep = 0 } else { keep = 1 }
            buffer = buffer $0 "\n"; next
        }
        in_section && /^$/ {
            if (keep) {
                if (need_blank) { print "" }
                print buffer
                need_blank = 1
            }
            in_section = 0; buffer = ""; next
        }
        in_section { buffer = buffer $0 "\n"; next }
        END { if (in_section && keep) { if (need_blank) { print "" } print buffer } }
        ' /etc/wireguard/"${interface_name}.conf" > "$temp_file"
        mv "$temp_file" /etc/wireguard/"${interface_name}.conf"
        chmod 600 /etc/wireguard/"${interface_name}.conf"

        # Append the new [Peer] entry with exactly one blank line before it
        if [[ -s /etc/wireguard/"${interface_name}.conf" ]]; then
            sed -i -e :a -e '/^\n*$/{$d;N;};/\n$/ba' /etc/wireguard/"${interface_name}.conf"
            echo "" >> /etc/wireguard/"${interface_name}.conf"
        fi
        cat << EOF >> /etc/wireguard/"${interface_name}.conf"
[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = $client_allowed_ips_combined
EOF

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
$( [[ "$client_persistent_keepalive" != "null" && -n "$client_persistent_keepalive" ]] && echo "PersistentKeepalive = $client_persistent_keepalive" )
EOF
        chmod 600 "$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
    done

    umask "$original_umask"
    mv config.yaml.tmp config.yaml
}

configure_firewall() {
    local port="$1"
    local vpn_ipv4_subnet="$2"
    local vpn_ipv6_subnet="$3"
    local host_interface=$(yq e '.server.host_interface' config.yaml)
    local ipv4_nat=$(yq e '.server.ipv4.nat' config.yaml)
    local ipv6_nat=$(yq e '.server.ipv6.nat' config.yaml)
    local ipv4_dynamic=$(yq e '.server.ipv4.dynamic' config.yaml)
    local ipv6_dynamic=$(yq e '.server.ipv6.dynamic' config.yaml)
    local ipv4_enabled=$(yq e '.server.ipv4.enabled' config.yaml)
    local ipv6_enabled=$(yq e '.server.ipv6.enabled' config.yaml)

    # Validate required variables
    if [[ -z "$host_interface" || "$host_interface" == "null" ]]; then
        echo "Error: host_interface is not set in config.yaml."
        return 1
    fi
    if [[ "$ipv4_enabled" == "true" && -z "$vpn_ipv4_subnet" ]]; then
        echo "Error: vpn_ipv4_subnet is not set but IPv4 is enabled."
        return 1
    fi
    if [[ "$ipv6_enabled" == "true" && -z "$vpn_ipv6_subnet" ]]; then
        echo "Error: vpn_ipv6_subnet is not set but IPv6 is enabled."
        return 1
    fi

    server_ipv4_static=$(ip -4 addr show "$host_interface" | grep -oP 'inet \K[\d.]+' | head -n 1)
    if [[ -z "$server_ipv4_static" && "$ipv4_nat" == "true" && "$ipv4_dynamic" != "true" ]]; then
        echo "Error: Could not detect IPv4 address for $host_interface and ipv4.dynamic is not set to true."
        return 1
    fi
    server_ipv6_static=$(ip -6 addr show "$host_interface" scope global | grep -oP 'inet6 \K[0-9a-f:]+' | head -n 1)
    if [[ -z "$server_ipv6_static" && "$ipv6_nat" == "true" && "$ipv6_dynamic" != "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
        echo "Error: Could not detect IPv6 address for $host_interface and ipv6.dynamic is not set to true."
        return 1
    fi

    # Always start with a fresh file, backing up the old one
    if [[ -f /etc/nftables.conf ]]; then
        cp /etc/nftables.conf /etc/nftables.conf.backup-$(date +%F-%T)
    fi
    local temp_file=$(mktemp)
    echo "#!/usr/sbin/nft -f" > "$temp_file"

    # Build NAT rules as an array
    local -a nat_rules=()
    if [[ "$ipv4_nat" == "true" && "$ipv4_enabled" == "true" ]]; then
        if [[ "$ipv4_dynamic" == "true" ]]; then
            nat_rules+=("ip saddr $vpn_ipv4_subnet oifname \"$host_interface\" masquerade persistent")
        elif [[ -n "$server_ipv4_static" ]]; then
            nat_rules+=("ip saddr $vpn_ipv4_subnet oifname \"$host_interface\" snat to $server_ipv4_static persistent")
        fi
    fi
    if [[ "$ipv6_nat" == "true" && "$ipv6_enabled" == "true" ]]; then
        if [[ "$ipv6_dynamic" == "true" ]]; then
            nat_rules+=("ip6 saddr $vpn_ipv6_subnet oifname \"$host_interface\" masquerade persistent")
        elif [[ -n "$server_ipv6_static" ]]; then
            nat_rules+=("ip6 saddr $vpn_ipv6_subnet oifname \"$host_interface\" snat to $server_ipv6_static persistent")
        fi
    fi

    # Append the WireGuard table if there are rules
    if [[ ${#nat_rules[@]} -gt 0 ]]; then
        {
            echo ""
            echo "table inet wireguard {"
            echo "    chain postrouting {"
            echo "        type nat hook postrouting priority 100; policy accept;"
            for rule in "${nat_rules[@]}"; do
                echo "        $rule;"
            done
            echo "    }"
            echo "}"
        } >> "$temp_file"
    fi

    # Move the temporary file to /etc/nftables.conf
    mv "$temp_file" /etc/nftables.conf
    chmod 600 /etc/nftables.conf

    # Apply the updated ruleset
    if ! nft -f /etc/nftables.conf; then
        echo "Error: Failed to apply nftables configuration. Restoring backup."
        mv /etc/nftables.conf.backup-$(date +%F-%T) /etc/nftables.conf
        nft -f /etc/nftables.conf
        return 1
    fi
    systemctl enable nftables
    systemctl restart nftables
}

clear_firewall_rules() {
    # Delete the WireGuard table from the running ruleset, if it exists
    nft delete table inet wireguard 2>/dev/null || echo "No WireGuard table found in running config, skipping."
}

interface_name=$(yq e '.server.interface_name' config.yaml 2>/dev/null || echo "wg0")
[[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"

if [[ ! -e /etc/wireguard/${interface_name}.conf ]]; then
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

    # Check for duplicate client names before proceeding with fresh install
    if ! check_duplicate_client_names; then
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
    echo "WireGuard is already installed."
    echo "Select an option:"
    echo "   1) Re-create server and client configurations from YAML"
    echo "   2) Remove WireGuard"
    echo "   3) Exit"
    read -p "Option: " option

    case $option in
        1)
            if [[ ! -f config.yaml ]]; then
                echo "Error: 'config.yaml' not found in the current directory."
                exit 1
            fi

            # Check for duplicate client names before proceeding with regeneration
            if ! check_duplicate_client_names; then
                exit 1
            fi

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
                if cmp -s config.yaml /etc/wireguard/config.yaml.backup; then
                    echo "No changes detected in config.yaml. No action taken."
                    exit 0
                fi

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
            interface_name=$(yq e '.server.interface_name' config.yaml)
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            systemctl disable --now wg-quick@"$interface_name"

            if [[ -f /etc/nftables.conf ]]; then
                echo "Cleaning up WireGuard-specific nftables rules..."
                cp /etc/nftables.conf /etc/nftables.conf.backup-$(date +%F-%T)
                # Remove the wireguard table block and clean up any trailing newlines or braces
                sed -i '/table inet wireguard {/,/}/d; /^\s*$/d; /^}/d' /etc/nftables.conf

                if [[ ! -s /etc/nftables.conf || $(grep -v '^#!/usr/sbin/nft -f' /etc/nftables.conf | grep -v '^\s*$' | wc -l) -eq 0 ]]; then
                    rm -f /etc/nftables.conf
                    systemctl disable nftables
                    systemctl stop nftables
                    echo "Removed /etc/nftables.conf and disabled nftables service (no meaningful rules remain)."
                else
                    if ! nft -f /etc/nftables.conf; then
                        echo "Error: Failed to apply updated nftables configuration. Restoring backup."
                        mv /etc/nftables.conf.backup-$(date +%F-%T) /etc/nftables.conf
                        nft -f /etc/nftables.conf
                    else
                        echo "Updated /etc/nftables.conf to remove WireGuard rules."
                    fi
                fi
            fi

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
