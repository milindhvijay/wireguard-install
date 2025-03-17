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

is_ipv4_in_use() {
    local ip="$1"
    local used_ips=("${@:2}")
    for used_ip in "${used_ips[@]}"; do
        if [[ "$used_ip" == "$ip" ]]; then
            return 0
        fi
    done
    return 1
}

is_ipv6_in_use() {
    local ip="$1"
    local used_ips=("${@:2}")
    for used_ip in "${used_ips[@]}"; do
        if [[ "$used_ip" == "$ip" ]]; then
            return 0
        fi
    done
    return 1
}

find_next_ipv4() {
    local base_ipv4="$1"
    local mask="$2"
    local used_ips=("${@:3}")
    local octet=2
    local max_octet=$((256 - 1))
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

find_next_ipv6() {
    local base_ipv6="$1"
    local mask="$2"
    local used_ips=("${@:3}")
    local segment=2
    local max_segment=$((16#ffff))
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

check_duplicate_client_names() {
    local number_of_clients=$(yq e '.remote_peer | length' config.yaml)
    local -A names_seen
    for i in $(seq 0 $(($number_of_clients - 1))); do
        local client_name=$(yq e ".remote_peer[$i].name" config.yaml)
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
    if ! check_duplicate_client_names; then
        return 1
    fi

    port=$(yq e '.local_peer.port' config.yaml)
    mtu=$(yq e '.local_peer.mtu' config.yaml)
    [[ "$mtu" == "null" || -z "$mtu" ]] && mtu=1420
    public_endpoint=$(yq e '.local_peer.public_endpoint' config.yaml)
    interface_name=$(yq e '.local_peer.interface_name' config.yaml)
    [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
    ipv4_enabled=$(yq e '.local_peer.ipv4.enabled' config.yaml)
    server_ipv4=$(yq e '.local_peer.ipv4.gateway' config.yaml)
    server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
    server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
    base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
    ipv6_enabled=$(yq e '.local_peer.ipv6.enabled' config.yaml)
    server_ipv6=$(yq e '.local_peer.ipv6.gateway' config.yaml)
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

    number_of_clients=$(yq e '.remote_peer | length' config.yaml)
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

    local -a used_ipv4s=("$server_ipv4_ip")
    local -a used_ipv6s=("$server_ipv6_ip")
    for i in $(seq 0 $(($number_of_clients - 1))); do
        local ipv4=$(yq e ".remote_peer[$i].ipv4_address" config.yaml)
        local ipv6=$(yq e ".remote_peer[$i].ipv6_address" config.yaml)
        [[ "$ipv4" != "null" && -n "$ipv4" ]] && used_ipv4s+=("$(echo "$ipv4" | cut -d '/' -f 1)")
        [[ "$ipv6" != "null" && -n "$ipv6" ]] && used_ipv6s+=("$(echo "$ipv6" | cut -d '/' -f 1)")
    done

    for i in $(seq 0 $(($number_of_clients - 1))); do
        client_name=$(yq e ".remote_peer[$i].name" config.yaml)
        client_dns=$(yq e ".remote_peer[$i].dns" config.yaml)
        client_mtu=$(yq e ".remote_peer[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".remote_peer[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".remote_peer[$i].persistent_keepalive" config.yaml)

        client_ipv4=$(yq e ".remote_peer[$i].ipv4_address" config.yaml)
        if [[ "$ipv4_enabled" == "true" && ( "$client_ipv4" == "null" || -z "$client_ipv4" ) ]]; then
            client_ipv4=$(find_next_ipv4 "$base_ipv4" "$server_ipv4_mask" "${used_ipv4s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv4"
                return 1
            fi
            used_ipv4s+=("$(echo "$client_ipv4" | cut -d '/' -f 1)")
        fi

        client_ipv6=$(yq e ".remote_peer[$i].ipv6_address" config.yaml)
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 && ( "$client_ipv6" == "null" || -z "$client_ipv6" ) ]]; then
            client_ipv6=$(find_next_ipv6 "$base_ipv6" "$server_ipv6_mask" "${used_ipv6s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv6"
                return 1
            fi
            used_ipv6s+=("$(echo "$client_ipv6" | cut -d '/' -f 1)")
        fi

        yq e -i ".remote_peer[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".remote_peer[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
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

    if ! check_duplicate_client_names; then
        return 1
    fi

    port=$(yq e '.local_peer.port' config.yaml)
    interface_name=$(yq e '.local_peer.interface_name' config.yaml)
    [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
    ipv4_enabled=$(yq e '.local_peer.ipv4.enabled' config.yaml)
    server_ipv4=$(yq e '.local_peer.ipv4.gateway' config.yaml)
    server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
    server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
    base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
    ipv6_enabled=$(yq e '.local_peer.ipv6.enabled' config.yaml)
    server_ipv6=$(yq e '.local_peer.ipv6.gateway' config.yaml)
    server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
    server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
    vpn_ipv6_subnet="${server_ipv6_ip}/${server_ipv6_mask}"
    base_ipv6=$(echo "$server_ipv6_ip" | sed 's/:[0-9a-f]*$//')
    server_public_key=$(wg show "$interface_name" public-key)

    public_endpoint=$(yq e '.local_peer.public_endpoint' config.yaml)
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

    local -a used_ipv4s=("$server_ipv4_ip")
    local -a used_ipv6s=("$server_ipv6_ip")
    local number_of_clients=$(yq e '.remote_peer | length' config.yaml)
    for i in $(seq 0 $(($number_of_clients - 1))); do
        local ipv4=$(yq e ".remote_peer[$i].ipv4_address" config.yaml)
        local ipv6=$(yq e ".remote_peer[$i].ipv6_address" config.yaml)
        [[ "$ipv4" != "null" && -n "$ipv4" ]] && used_ipv4s+=("$(echo "$ipv4" | cut -d '/' -f 1)")
        [[ "$ipv6" != "null" && -n "$ipv6" ]] && used_ipv6s+=("$(echo "$ipv6" | cut -d '/' -f 1)")
    done

    for i in "${changed_clients[@]}"; do
        client_name=$(yq e ".remote_peer[$i].name" config.yaml)
        client_dns=$(yq e ".remote_peer[$i].dns" config.yaml)
        client_mtu=$(yq e ".remote_peer[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".remote_peer[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".remote_peer[$i].persistent_keepalive" config.yaml)

        client_ipv4=$(yq e ".remote_peer[$i].ipv4_address" config.yaml)
        if [[ "$ipv4_enabled" == "true" && ( "$client_ipv4" == "null" || -z "$client_ipv4" ) ]]; then
            client_ipv4=$(find_next_ipv4 "$base_ipv4" "$server_ipv4_mask" "${used_ipv4s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv4"
                return 1
            fi
            used_ipv4s+=("$(echo "$client_ipv4" | cut -d '/' -f 1)")
        fi

        client_ipv6=$(yq e ".remote_peer[$i].ipv6_address" config.yaml)
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 && ( "$client_ipv6" == "null" || -z "$client_ipv6" ) ]]; then
            client_ipv6=$(find_next_ipv6 "$base_ipv6" "$server_ipv6_mask" "${used_ipv6s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_ipv6"
                return 1
            fi
            used_ipv6s+=("$(echo "$client_ipv6" | cut -d '/' -f 1)")
        fi

        yq e -i ".remote_peer[$i].ipv4_address = \"$client_ipv4\"" config.yaml.tmp
        if [[ "$ipv6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".remote_peer[$i].ipv6_address = \"$client_ipv6\"" config.yaml.tmp
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

        old_name=$(yq e ".remote_peer[$i].name" "$(dirname "$0")/config.yaml.backup")
        if [[ "$old_name" != "$client_name" && -n "$old_name" ]]; then
            rm -f "$(dirname "$0")/wireguard-configs/${old_name}-${interface_name}.conf"
            rm -rf "$(dirname "$0")/keys/${old_name}-${interface_name}"
        fi

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
    local host_interface=$(yq e '.local_peer.host_interface' config.yaml)
    local ipv4_nat=$(yq e '.local_peer.ipv4.nat44' config.yaml)
    local ipv6_nat=$(yq e '.local_peer.ipv6.nat66' config.yaml)
    local ipv4_dynamic=$(yq e '.local_peer.ipv4.dynamic' config.yaml)
    local ipv6_dynamic=$(yq e '.local_peer.ipv6.dynamic' config.yaml)
    local ipv4_enabled=$(yq e '.local_peer.ipv4.enabled' config.yaml)
    local ipv6_enabled=$(yq e '.local_peer.ipv6.enabled' config.yaml)

    local ipv4_snat_ip=$(yq e '.local_peer.ipv4.nat44_public_IP' config.yaml)
    local ipv6_snat_ip=$(yq e '.local_peer.ipv6.nat66_public_IP' config.yaml)

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
    server_ipv6_static=$(ip -6 addr show "$host_interface" scope global | grep -oP 'inet6 \K[0-9a-f:]+' | head -n 1)

    if [[ "$ipv4_snat_ip" == "null" || -z "$ipv4_snat_ip" ]]; then
        ipv4_snat_ip="$server_ipv4_static"
    fi

    if [[ "$ipv6_snat_ip" == "null" || -z "$ipv6_snat_ip" ]]; then
        ipv6_snat_ip="$server_ipv6_static"
    fi

    if [[ "$ipv4_nat" == "true" && "$ipv4_dynamic" != "true" && -z "$ipv4_snat_ip" ]]; then
        echo "Error: No IPv4 SNAT IP available. Either specify local_peer.ipv4.nat44_public_IP, ensure host_interface has an IPv4, or set ipv4.dynamic to true."
        return 1
    fi

    if [[ "$ipv6_nat" == "true" && "$ipv6_dynamic" != "true" && -z "$ipv6_snat_ip" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
        echo "Error: No IPv6 SNAT IP available. Either specify local_peer.ipv6.nat66_public_IP, ensure host_interface has an IPv6, or set ipv6.dynamic to true."
        return 1
    fi

    local -a nat_rules=()
    if [[ "$ipv4_nat" == "true" && "$ipv4_enabled" == "true" ]]; then
        if [[ "$ipv4_dynamic" == "true" ]]; then
            nat_rules+=("ip saddr $vpn_ipv4_subnet oifname \"$host_interface\" masquerade persistent")
        elif [[ -n "$ipv4_snat_ip" ]]; then
            nat_rules+=("ip saddr $vpn_ipv4_subnet oifname \"$host_interface\" snat to $ipv4_snat_ip persistent")
        fi
    fi

    if [[ "$ipv6_nat" == "true" && "$ipv6_enabled" == "true" ]]; then
        if [[ "$ipv6_dynamic" == "true" ]]; then
            nat_rules+=("ip6 saddr $vpn_ipv6_subnet oifname \"$host_interface\" masquerade persistent")
        elif [[ -n "$ipv6_snat_ip" ]]; then
            nat_rules+=("ip6 saddr $vpn_ipv6_subnet oifname \"$host_interface\" snat to $ipv6_snat_ip persistent")
        fi
    fi

    if [[ ${#nat_rules[@]} -eq 0 ]]; then
        echo "No firewall rules needed for WireGuard."
        return 0
    fi

    local wireguard_table=$(cat << EOF
table inet wireguard {
    chain postrouting {
        type nat hook postrouting priority 100; policy accept;
$(for rule in "${nat_rules[@]}"; do echo "        $rule;"; done)
    }
}
EOF
)

    if [[ -f /etc/nftables.conf && -s /etc/nftables.conf ]]; then
        cp /etc/nftables.conf /etc/nftables.conf.backup-$(date +%F-%T)

        if grep -q "table inet wireguard" /etc/nftables.conf; then
            temp_file=$(mktemp)
            awk -v new_table="$wireguard_table" '
            BEGIN { skip = 0; brace_count = 0; printed = 0; }
            /table inet wireguard {/ {
                skip = 1;
                brace_count = 1;
                if (!printed) {
                    print new_table;
                    printed = 1;
                }
                next;
            }
            skip == 1 && /\{/ { brace_count++; }
            skip == 1 && /\}/ {
                brace_count--;
                if (brace_count == 0) {
                    skip = 0;
                    next;
                }
            }
            skip == 0 { print $0; }
            END { if (!printed) print new_table; }
            ' /etc/nftables.conf > "$temp_file"

            mv "$temp_file" /etc/nftables.conf
        else
            if ! grep -q "^#!/usr/sbin/nft -f" /etc/nftables.conf; then
                temp_file=$(mktemp)
                echo '#!/usr/sbin/nft -f' > "$temp_file"
                cat /etc/nftables.conf >> "$temp_file"
                mv "$temp_file" /etc/nftables.conf
            fi

            echo "" >> /etc/nftables.conf
            echo "$wireguard_table" >> /etc/nftables.conf
        fi
    else
        echo '#!/usr/sbin/nft -f' > /etc/nftables.conf
        echo "" >> /etc/nftables.conf
        echo "$wireguard_table" >> /etc/nftables.conf
    fi

    chmod 600 /etc/nftables.conf

    if ! nft -f /etc/nftables.conf; then
        echo "Error: Failed to apply nftables configuration. Restoring backup."
        if [[ -f /etc/nftables.conf.backup-$(date +%F-%T) ]]; then
            mv /etc/nftables.conf.backup-$(date +%F-%T) /etc/nftables.conf
            nft -f /etc/nftables.conf
        fi
        return 1
    fi

    systemctl enable nftables
    systemctl restart nftables

    echo "Firewall rules for WireGuard have been configured."
    return 0
}

clear_firewall_rules() {
    nft delete table inet wireguard 2>/dev/null || echo "No WireGuard table found in running config, skipping."
}

interface_name=$(yq e '.local_peer.interface_name' config.yaml 2>/dev/null || echo "wg0")
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

    if ! check_duplicate_client_names; then
        exit 1
    fi

    mkdir -p /etc/wireguard
    cp config.yaml "$(dirname "$0")/config.yaml.backup"
    chmod 600 "$(dirname "$0")/config.yaml.backup"

    if ! generate_full_configs; then
        echo "Error: Failed to generate configurations."
        exit 1
    fi

    ipv4_enabled=$(yq e '.local_peer.ipv4.enabled' config.yaml)
    ipv6_enabled=$(yq e '.local_peer.ipv6.enabled' config.yaml)
    server_ipv4=$(yq e '.local_peer.ipv4.gateway' config.yaml)
    server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
    server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
    base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
    server_ipv6=$(yq e '.local_peer.ipv6.gateway' config.yaml)
    server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
    server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
    port=$(yq e '.local_peer.port' config.yaml)

    if [[ "$ipv4_enabled" == "true" ]]; then
        vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
    fi
    if [[ "$ipv6_enabled" == "true" ]]; then
        segments_to_keep=$((server_ipv6_mask / 16))
        if [[ $segments_to_keep -gt 0 ]]; then
            ipv6_prefix=$(echo "$server_ipv6_ip" | awk -F: '{
                for(i=1; i<='"$segments_to_keep"'; i++) {
                    if(i==1) prefix=$i;
                    else prefix=prefix":"$i;
                }
                print prefix;
            }')

            if [[ "$ipv6_prefix" == *: ]]; then
                vpn_ipv6_subnet="${ipv6_prefix}:/$server_ipv6_mask"
            else
                vpn_ipv6_subnet="${ipv6_prefix}::/$server_ipv6_mask"
            fi
        else
            vpn_ipv6_subnet="::/$server_ipv6_mask"
        fi
        vpn_ipv6_subnet=$(echo "$vpn_ipv6_subnet" | sed 's/:::/::/')
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

            if ! check_duplicate_client_names; then
                exit 1
            fi

            port=$(yq e '.local_peer.port' config.yaml)
            interface_name=$(yq e '.local_peer.interface_name' config.yaml)
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            ipv4_enabled=$(yq e '.local_peer.ipv4.enabled' config.yaml)
            server_ipv4=$(yq e '.local_peer.ipv4.gateway' config.yaml)
            server_ipv4_ip=$(echo "$server_ipv4" | cut -d '/' -f 1)
            server_ipv4_mask=$(echo "$server_ipv4" | cut -d '/' -f 2)
            base_ipv4=$(echo "$server_ipv4_ip" | cut -d '.' -f 1-3)
            ipv6_enabled=$(yq e '.local_peer.ipv6.enabled' config.yaml)
            server_ipv6=$(yq e '.local_peer.ipv6.gateway' config.yaml)
            server_ipv6_ip=$(echo "$server_ipv6" | cut -d '/' -f 1)
            server_ipv6_mask=$(echo "$server_ipv6" | cut -d '/' -f 2)
            vpn_ipv4_subnet="${base_ipv4}.0/$server_ipv4_mask"
            ipv6_network=$(echo "$server_ipv6_ip" | sed -E 's/:[^:]*$/::/')
            vpn_ipv6_subnet="${ipv6_network}/${server_ipv6_mask}"

            if [[ -f "$(dirname "$0")/config.yaml.backup" ]]; then
                if cmp -s config.yaml "$(dirname "$0")/config.yaml.backup"; then
                    echo "No changes detected in config.yaml. No action taken."
                    exit 0
                fi

                old_interface_name=$(yq e '.local_peer.interface_name' "$(dirname "$0")/config.yaml.backup")
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

                yq e '.local_peer' config.yaml > /tmp/server_new.yaml
                yq e '.local_peer' "$(dirname "$0")/config.yaml.backup" > /tmp/server_old.yaml
                if ! cmp -s /tmp/server_new.yaml /tmp/server_old.yaml; then
                    echo "Server configuration changed. Regenerating all configurations..."
                    if ! generate_full_configs; then
                        echo "Error: Failed to regenerate configurations."
                        rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                        exit 1
                    fi
                    cp config.yaml "$(dirname "$0")/config.yaml.backup"
                    chmod 600 "$(dirname "$0")/config.yaml.backup"

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
                    number_of_clients=$(yq e '.remote_peer | length' config.yaml)
                    old_clients=$(yq e '.remote_peer | length' "$(dirname "$0")/config.yaml.backup")
                    max_clients=$((number_of_clients > old_clients ? number_of_clients : old_clients))

                    for i in $(seq 0 $((max_clients - 1))); do
                        new_name=$(yq e ".remote_peer[$i].name" config.yaml)
                        old_name=$(yq e ".remote_peer[$i].name" "$(dirname "$0")/config.yaml.backup")
                        if [[ "$new_name" != "$old_name" ]] || ! cmp -s <(yq e ".remote_peer[$i]" config.yaml) <(yq e ".remote_peer[$i]" "$(dirname "$0")/config.yaml.backup"); then
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
                        cp config.yaml "$(dirname "$0")/config.yaml.backup"
                        chmod 600 "$(dirname "$0")/config.yaml.backup"

                        clear_firewall_rules
                        configure_firewall "$port" "$vpn_ipv4_subnet" "$vpn_ipv6_subnet"

                        echo "Updated client configurations:"
                        mkdir -p "$(dirname "$0")/wireguard-configs/qr"
                        for i in "${changed_clients[@]}"; do
                            client_name=$(yq e ".remote_peer[$i].name" config.yaml)
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
                cp config.yaml "$(dirname "$0")/config.yaml.backup"
                chmod 600 "$(dirname "$0")/config.yaml.backup"

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
            interface_name=$(yq e '.local_peer.interface_name' config.yaml)
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            systemctl disable --now wg-quick@"$interface_name"

            if [[ -f /etc/nftables.conf ]]; then
                echo "Cleaning up WireGuard-specific nftables rules..."
                cp /etc/nftables.conf /etc/nftables.conf.backup-$(date +%F-%T)

                temp_file=$(mktemp)

                if grep -q "table inet wireguard" /etc/nftables.conf; then
                    awk '
                    BEGIN { skip = 0; brace_count = 0; }
                    /table inet wireguard {/ { skip = 1; brace_count = 1; next; }
                    skip == 1 && /\{/ { brace_count++; }
                    skip == 1 && /\}/ {
                        brace_count--;
                        if (brace_count == 0) {
                            skip = 0;
                            next;
                        }
                    }
                    skip == 0 { print $0; }
                    ' /etc/nftables.conf > "$temp_file"

                    awk 'NF {p=1} p' "$temp_file" > /etc/nftables.conf

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
                else
                    echo "No WireGuard table found in nftables configuration."
                fi

                rm -f "$temp_file"
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
