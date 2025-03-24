#!/bin/bash

if [ -z "$BASH_VERSION" ]; then
    echo "Error: This script must be run with Bash."
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    echo "Error: This script must be run as root."
    exit 1
fi

declare -a rollback_actions=()

if ! command -v yq &>/dev/null; then
    echo "'yq' not found, installing it automatically..."
    ARCH=$(uname -m)
    case "$ARCH" in
        x86_64)
            wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && \
            chmod +x /usr/bin/yq
            ;;
        aarch64)
            wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_arm64 -O /usr/bin/yq && \
            chmod +x /usr/bin/yq
            ;;
        *)
            echo "Error: Unsupported architecture '$ARCH'. Supported architectures are 'x86_64' (AMD64) and 'aarch64' (ARM64)."
            echo "Please install 'yq' manually for your system."
            exit 1
            ;;
    esac
    rollback_actions+=("rm -f /usr/bin/yq")
    if ! command -v yq &>/dev/null; then
        echo "Error: Failed to install 'yq'. Please install it manually."
        exit 1
    fi
fi

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    os=${ID}
    os_version=${VERSION_ID}
else
    echo "Error: Cannot detect operating system."
    exit 1
fi

# Set interface_name after yq is available
if [[ ! -f config.yaml ]]; then
    echo "Error: 'config.yaml' not found in the current directory."
    exit 1
fi
interface_name=$(yq e '.local_peer.interface_name' config.yaml)
if [[ "$interface_name" == "null" || -z "$interface_name" ]]; then
    interface_name="wg0"
fi

sysctl_backup=""

# Rollback function to undo changes on failure
rollback_on_failure() {
    echo "Error detected. Rolling back changes..."
    for ((i=${#rollback_actions[@]}-1; i>=0; i--)); do
        echo "Executing rollback: ${rollback_actions[$i]}"
        eval "${rollback_actions[$i]}" 2>/dev/null || echo "Warning: Rollback action '${rollback_actions[$i]}' failed."
    done
    echo "Rollback complete."
    exit 1
}

is_inet_in_use() {
    local ip="$1"
    local used_ips=("${@:2}")
    for used_ip in "${used_ips[@]}"; do
        if [[ "$used_ip" == "$ip" ]]; then
            return 0
        fi
    done
    return 1
}

is_inet6_in_use() {
    local ip="$1"
    local used_ips=("${@:2}")
    for used_ip in "${used_ips[@]}"; do
        if [[ "$used_ip" == "$ip" ]]; then
            return 0
        fi
    done
    return 1
}

find_next_inet() {
    local base_inet="$1"
    local mask="$2"
    local used_ips=("${@:3}")
    local octet=2
    local max_octet=$((256 - 1))
    while [[ $octet -le $max_octet ]]; do
        local candidate="${base_inet}.${octet}"
        if ! is_inet_in_use "$candidate" "${used_ips[@]}"; then
            echo "$candidate/$mask"
            return 0
        fi
        ((octet++))
    done
    echo "Error: No available inet addresses in $base_inet.0/$mask."
    return 1
}

find_next_inet6() {
    local base_inet6="$1"
    local mask="$2"
    local used_ips=("${@:3}")
    local segment=2
    local max_segment=$((16#ffff))
    while [[ $segment -le $max_segment ]]; do
        local candidate_segment=$(printf "%x" "$segment")
        local candidate="${base_inet6}:${candidate_segment}"
        if ! is_inet6_in_use "$candidate" "${used_ips[@]}"; then
            echo "$candidate/$mask"
            return 0
        fi
        ((segment++))
    done
    echo "Error: No available inet6 addresses in $base_inet6::$mask."
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
    local new_inet="$1"
    local new_inet6="$2"
    local new_interface="$3"

    for iface in $(ip link show type wireguard | grep -oP '^\d+: \K\w+'); do
        if [[ "$iface" != "$new_interface" ]]; then
            if ip addr show "$iface" | grep -q "$new_inet\|$new_inet6"; then
                echo "Found conflicting interface '$iface' using IPs $new_inet or $new_inet6. Cleaning up..."
                systemctl stop wg-quick@"$iface" 2>/dev/null || echo "Service $iface not running."
                systemctl disable wg-quick@"$iface" 2>/dev/null || true
                ip link delete "$iface" 2>/dev/null || echo "Failed to delete $iface, may already be gone."
                rm -f "/etc/wireguard/${iface}.conf"
                echo "Removed conflicting interface '$iface' and its config."
            fi
        fi
    done
}

get_existing_client_key() {
    local client_name="$1"
    local conf_file="$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
    if [[ -f "$conf_file" ]]; then
        local key=$(grep "^PrivateKey" "$conf_file" | cut -d '=' -f 2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ -n "$key" ]]; then
            echo "$key"
            return 0
        else
            echo "Warning: No PrivateKey found in $conf_file" >&2
            return 1
        fi
    else
        echo "Warning: Config file $conf_file not found" >&2
        return 1
    fi
}

validate_key() {
    local key="$1"
    local key_length=$(echo -n "$key" | wc -c)
    if [[ $key_length -ne 44 ]]; then
        echo "Error: Key length ($key_length) is not 44 characters: $key" >&2
        return 1
    fi
    echo "$key" | wg pubkey >/dev/null 2>&1 || {
        echo "Error: Invalid key format: $key" >&2
        return 1
    }
    return 0
}

generate_full_configs() {
    if ! check_duplicate_client_names; then
        return 1
    fi

    port=$(yq e '.local_peer.port' config.yaml)
    mtu=$(yq e '.local_peer.mtu' config.yaml)
    [[ "$mtu" == "null" || -z "$mtu" ]] && mtu=1420
    public_endpoint=$(yq e '.local_peer.public_endpoint' config.yaml)
    [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
    inet_enabled=$(yq e '.local_peer.inet.enabled' config.yaml)
    server_inet=$(yq e '.local_peer.inet.gateway' config.yaml)
    server_inet_ip=$(echo "$server_inet" | cut -d '/' -f 1)
    server_inet_mask=$(echo "$server_inet" | cut -d '/' -f 2)
    base_inet=$(echo "$server_inet_ip" | cut -d '.' -f 1-3)
    inet6_enabled=$(yq e '.local_peer.inet6.enabled' config.yaml)
    server_inet6=$(yq e '.local_peer.inet6.gateway' config.yaml)
    server_inet6_ip=$(echo "$server_inet6" | cut -d '/' -f 1)
    server_inet6_mask=$(echo "$server_inet6" | cut -d '/' -f 2)
    base_inet6=$(echo "$server_inet6_ip" | sed 's/:[0-9a-f]*$//')

    cleanup_conflicting_interfaces "$server_inet_ip" "$server_inet6_ip" "$interface_name"

    original_umask=$(umask)
    umask 077

    # Server keys
    if [[ -f "/etc/wireguard/${interface_name}.conf" ]]; then
        server_private_key=$(grep "^PrivateKey" "/etc/wireguard/${interface_name}.conf" | cut -d '=' -f 2- | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        if [[ -z "$server_private_key" ]] || ! validate_key "$server_private_key"; then
            echo "Invalid or missing server private key in /etc/wireguard/${interface_name}.conf, generating new one" >&2
            server_private_key=$(wg genkey)
        fi
    else
        server_private_key=$(wg genkey)
    fi
    server_public_key=$(echo "$server_private_key" | wg pubkey) || {
        echo "Error: Failed to generate server public key" >&2
        return 1
    }
    echo "Server Private Key: $server_private_key" >&2
    echo "Server Public Key: $server_public_key" >&2

    cat << EOF > "/etc/wireguard/${interface_name}.conf"
[Interface]
Address = $server_inet$( [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $server_inet6" )
PrivateKey = $server_private_key
ListenPort = $port
MTU = $mtu
EOF
    rollback_actions+=("rm -f /etc/wireguard/${interface_name}.conf")

    number_of_clients=$(yq e '.remote_peer | length' config.yaml)
    cp config.yaml config.yaml.tmp
    rollback_actions+=("rm -f config.yaml.tmp")
    mkdir -p "$(dirname "$0")/wireguard-configs"
    rollback_actions+=("rm -rf \"$(dirname "$0")/wireguard-configs\"")

    # Endpoint logic (unchanged)
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
                echo "Error: Could not auto-detect public IP (neither inet6 nor inet)." >&2
                return 1
            fi
        fi
    fi

    local -a used_inets=("$server_inet_ip")
    local -a used_inet6s=("$server_inet6_ip")

    for i in $(seq 0 $(($number_of_clients - 1))); do
        client_name=$(yq e ".remote_peer[$i].name" config.yaml)
        client_dns=$(yq e ".remote_peer[$i].dns" config.yaml)
        client_mtu=$(yq e ".remote_peer[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".remote_peer[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".remote_peer[$i].persistent_keepalive" config.yaml)

        # Use existing IPs if they exist
        client_inet=$(yq e ".remote_peer[$i].inet_address" config.yaml)
        if [[ "$inet_enabled" == "true" && ( "$client_inet" == "null" || -z "$client_inet" ) ]]; then
            client_inet=$(find_next_inet "$base_inet" "$server_inet_mask" "${used_inets[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_inet" >&2
                return 1
            fi
        fi
        used_inets+=("$(echo "$client_inet" | cut -d '/' -f 1)")

        client_inet6=$(yq e ".remote_peer[$i].inet6_address" config.yaml)
        if [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 && ( "$client_inet6" == "null" || -z "$client_inet6" ) ]]; then
            client_inet6=$(find_next_inet6 "$base_inet6" "$server_inet6_mask" "${used_inet6s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_inet6" >&2
                return 1
            fi
        fi
        used_inet6s+=("$(echo "$client_inet6" | cut -d '/' -f 1)")

        # Client keys
        client_private_key=$(get_existing_client_key "$client_name")
        if [[ $? -ne 0 ]] || ! validate_key "$client_private_key"; then
            echo "Generating new private key for $client_name" >&2
            client_private_key=$(wg genkey)
        fi
        client_public_key=$(echo "$client_private_key" | wg pubkey) || {
            echo "Error: Failed to generate public key for $client_name" >&2
            return 1
        }
        psk=$(wg genpsk)
        echo "Client $client_name Private Key: $client_private_key" >&2
        echo "Client $client_name Public Key: $client_public_key" >&2

        client_inet_ip=$(echo "$client_inet" | cut -d '/' -f 1)
        client_inet6_ip=$(echo "$client_inet6" | cut -d '/' -f 1)
        cat << EOF >> "/etc/wireguard/${interface_name}.conf"

[Peer]
PublicKey = $client_public_key
PresharedKey = $psk
AllowedIPs = ${client_inet_ip}/32$( [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${client_inet6_ip}/128" )
EOF

        yq e -i ".remote_peer[$i].inet_address = \"$client_inet\"" config.yaml.tmp
        if [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
            yq e -i ".remote_peer[$i].inet6_address = \"$client_inet6\"" config.yaml.tmp
        fi

        cat << EOF > "$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
[Interface]
Address = $client_inet$( [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $client_inet6" )
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
    chmod 600 "/etc/wireguard/${interface_name}.conf"
}

generate_client_configs() {
    local changed_clients=("$@")

    if ! check_duplicate_client_names; then
        return 1
    fi

    port=$(yq e '.local_peer.port' config.yaml)
    [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
    inet_enabled=$(yq e '.local_peer.inet.enabled' config.yaml)
    server_inet=$(yq e '.local_peer.inet.gateway' config.yaml)
    server_inet_ip=$(echo "$server_inet" | cut -d '/' -f 1)
    server_inet_mask=$(echo "$server_inet" | cut -d '/' -f 2)
    base_inet=$(echo "$server_inet_ip" | cut -d '.' -f 1-3)
    inet6_enabled=$(yq e '.local_peer.inet6.enabled' config.yaml)
    server_inet6=$(yq e '.local_peer.inet6.gateway' config.yaml)
    server_inet6_ip=$(echo "$server_inet6" | cut -d '/' -f 1)
    server_inet6_mask=$(echo "$server_inet6" | cut -d '/' -f 2)
    base_inet6=$(echo "$server_inet6_ip" | sed 's/:[0-9a-f]*$//')
    server_public_key=$(wg show "$interface_name" public-key)

    # Endpoint logic remains the same
    # ... (keep existing endpoint detection code) ...

    cp config.yaml config.yaml.tmp
    mkdir -p "$(dirname "$0")/wireguard-configs"
    original_umask=$(umask)
    umask 077

    local -a used_inets=("$server_inet_ip")
    local -a used_inet6s=("$server_inet6_ip")
    local number_of_clients=$(yq e '.remote_peer | length' config.yaml)
    for i in $(seq 0 $(($number_of_clients - 1))); do
        local inet=$(yq e ".remote_peer[$i].inet_address" config.yaml)
        local inet6=$(yq e ".remote_peer[$i].inet6_address" config.yaml)
        [[ "$inet" != "null" && -n "$inet" ]] && used_inets+=("$(echo "$inet" | cut -d '/' -f 1)")
        [[ "$inet6" != "null" && -n "$inet6" ]] && used_inet6s+=("$(echo "$inet6" | cut -d '/' -f 1)")
    done

    for i in "${changed_clients[@]}"; do
        client_name=$(yq e ".remote_peer[$i].name" config.yaml)
        client_dns=$(yq e ".remote_peer[$i].dns" config.yaml)
        client_mtu=$(yq e ".remote_peer[$i].mtu" config.yaml)
        [[ "$client_mtu" == "null" || -z "$client_mtu" ]] && client_mtu=1420
        client_allowed_ips=$(yq e ".remote_peer[$i].allowed_ips" config.yaml)
        client_persistent_keepalive=$(yq e ".remote_peer[$i].persistent_keepalive" config.yaml)

        # Preserve existing IPs if they exist
        client_inet=$(yq e ".remote_peer[$i].inet_address" config.yaml)
        if [[ "$inet_enabled" == "true" && ( "$client_inet" == "null" || -z "$client_inet" ) ]]; then
            client_inet=$(find_next_inet "$base_inet" "$server_inet_mask" "${used_inets[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_inet"
                return 1
            fi
            used_inets+=("$(echo "$client_inet" | cut -d '/' -f 1)")
        fi

        client_inet6=$(yq e ".remote_peer[$i].inet6_address" config.yaml)
        if [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 && ( "$client_inet6" == "null" || -z "$client_inet6" ) ]]; then
            client_inet6=$(find_next_inet6 "$base_inet6" "$server_inet6_mask" "${used_inet6s[@]}")
            if [[ $? -ne 0 ]]; then
                echo "$client_inet6"
                return 1
            fi
            used_inet6s+=("$(echo "$client_inet6" | cut -d '/' -f 1)")
        fi

        # Preserve existing keys
        client_private_key=$(get_existing_client_key "$client_name")
        if [[ -z "$client_private_key" ]]; then
            client_private_key=$(wg genkey)
        fi
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        psk=$(wg genpsk)

        # Update config.yaml with IPs only if they were newly generated
        if [[ "$(yq e ".remote_peer[$i].inet_address" config.yaml)" == "null" ]]; then
            yq e -i ".remote_peer[$i].inet_address = \"$client_inet\"" config.yaml.tmp
        fi
        if [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 && "$(yq e ".remote_peer[$i].inet6_address" config.yaml)" == "null" ]]; then
            yq e -i ".remote_peer[$i].inet6_address = \"$client_inet6\"" config.yaml.tmp
        fi

        client_private_key=$(wg genkey)
        client_public_key=$(echo "$client_private_key" | wg pubkey)
        psk=$(wg genpsk)

        client_inet_ip=$(echo "$client_inet" | cut -d '/' -f 1)
        client_inet6_ip=$(echo "$client_inet6" | cut -d '/' -f 1)
        client_allowed_ips_combined="${client_inet_ip}/32$( [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", ${client_inet6_ip}/128" )"

        old_name=$(yq e ".remote_peer[$i].name" "$(dirname "$0")/config.yaml.backup")
        if [[ "$old_name" != "$client_name" && -n "$old_name" ]]; then
            rm -f "$(dirname "$0")/wireguard-configs/${old_name}-${interface_name}.conf"
        fi

        temp_file=$(mktemp)
        awk -v ip="$client_inet_ip" '
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
Address = $client_inet$( [[ "$inet6_enabled" == "true" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]] && echo ", $client_inet6" )
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
    local vpn_inet_subnet="$2"
    local vpn_inet6_subnet="$3"
    local host_interface=$(yq e '.local_peer.host_interface' config.yaml)
    local inet_nat=$(yq e '.local_peer.inet.nat44' config.yaml)
    local inet6_nat=$(yq e '.local_peer.inet6.nat66' config.yaml)
    local inet_dynamic=$(yq e '.local_peer.inet.dynamic' config.yaml)
    local inet6_dynamic=$(yq e '.local_peer.inet6.dynamic' config.yaml)
    local inet_enabled=$(yq e '.local_peer.inet.enabled' config.yaml)
    local inet6_enabled=$(yq e '.local_peer.inet6.enabled' config.yaml)

    local inet_snat_ip=$(yq e '.local_peer.inet.nat44_public_IP' config.yaml)
    local inet6_snat_ip=$(yq e '.local_peer.inet6.nat66_public_IP' config.yaml)

    if [[ -z "$host_interface" || "$host_interface" == "null" ]]; then
        echo "Error: host_interface is not set in config.yaml."
        return 1
    fi
    if [[ "$inet_enabled" == "true" && -z "$vpn_inet_subnet" ]]; then
        echo "Error: vpn_inet_subnet is not set but inet is enabled."
        return 1
    fi
    if [[ "$inet6_enabled" == "true" && -z "$vpn_inet6_subnet" ]]; then
        echo "Error: vpn_inet6_subnet is not set but inet6 is enabled."
        return 1
    fi

    server_inet_static=$(ip -4 addr show "$host_interface" | grep -oP 'inet \K[\d.]+' | head -n 1)
    server_inet6_static=$(ip -6 addr show "$host_interface" scope global | grep -oP 'inet6 \K[0-9a-f:]+' | head -n 1)

    if [[ "$inet_snat_ip" == "null" || -z "$inet_snat_ip" ]]; then
        inet_snat_ip="$server_inet_static"
    fi
    if [[ "$inet6_snat_ip" == "null" || -z "$inet6_snat_ip" ]]; then
        inet6_snat_ip="$server_inet6_static"
    fi

    if [[ "$inet_nat" == "true" && "$inet_dynamic" != "true" && -z "$inet_snat_ip" ]]; then
        echo "Error: No inet SNAT IP available. Either specify local_peer.inet.nat44_public_IP, ensure host_interface has an inet, or set inet.dynamic to true."
        return 1
    fi
    if [[ "$inet6_nat" == "true" && "$inet6_dynamic" != "true" && -z "$inet6_snat_ip" && $(ip -6 addr | grep -c 'inet6 [23]') -gt 0 ]]; then
        echo "Error: No inet6 SNAT IP available. Either specify local_peer.inet6.nat66_public_IP, ensure host_interface has an inet6, or set inet6.dynamic to true."
        return 1
    fi

    local -a nat_rules=()
    if [[ "$inet_nat" == "true" && "$inet_enabled" == "true" ]]; then
        if [[ "$inet_dynamic" == "true" ]]; then
            nat_rules+=("ip saddr $vpn_inet_subnet oifname \"$host_interface\" masquerade persistent")
        elif [[ -n "$inet_snat_ip" ]]; then
            nat_rules+=("ip saddr $vpn_inet_subnet oifname \"$host_interface\" snat to $inet_snat_ip persistent")
        fi
    fi
    if [[ "$inet6_nat" == "true" && "$inet6_enabled" == "true" ]]; then
        if [[ "$inet6_dynamic" == "true" ]]; then
            nat_rules+=("ip6 saddr $vpn_inet6_subnet oifname \"$host_interface\" masquerade persistent")
        elif [[ -n "$inet6_snat_ip" ]]; then
            nat_rules+=("ip6 saddr $vpn_inet6_subnet oifname \"$host_interface\" snat to $inet6_snat_ip persistent")
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

    mkdir -p /etc/nftables
    rollback_actions+=("rm -f /etc/nftables/wg.nft")
    local nft_file="/etc/nftables/wg.nft"

    echo '#!/usr/sbin/nft -f' > "$nft_file"
    echo "" >> "$nft_file"
    echo "$wireguard_table" >> "$nft_file"
    chmod 600 "$nft_file"

    if ! nft -f "$nft_file"; then
        echo "Error: Failed to apply nftables configuration from $nft_file."
        return 1
    fi
    rollback_actions+=("nft delete table inet wireguard")

    systemctl restart nftables
    rollback_actions+=("systemctl restart nftables")
    echo "Firewall rules for WireGuard have been configured in $nft_file."
    return 0
}

clear_firewall_rules() {
    local nft_file="/etc/nftables/wg.nft"

    nft delete table inet wireguard 2>/dev/null || echo "No WireGuard table found in running config, skipping."
    if [[ -f "$nft_file" ]]; then
        rm -f "$nft_file"
        echo "Removed WireGuard nftables configuration file: $nft_file"
    else
        echo "No $nft_file file found, skipping file removal."
    fi

    systemctl restart nftables
}

interface_name=$(yq e '.local_peer.interface_name' config.yaml 2>/dev/null || echo "wg0")
[[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"

if [[ ! -e /etc/wireguard/${interface_name}.conf ]]; then
    # Enable error trapping for first run
    trap 'rollback_on_failure' ERR

    echo "Installing WireGuard and other dependencies..."
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt update

        # Ensure nftables is installed (but don't remove it in rollback)
        if dpkg -l | grep -q '^ii\s*nftables\s'; then
            echo "nftables is already installed."
        else
            echo "nftables is not installed, installing it now..."
            apt install -y nftables
        fi

        # Install other required packages
        apt install -y wireguard qrencode ipcalc
        rollback_actions+=("apt remove -y wireguard wireguard-tools qrencode ipcalc --purge")

        if ! command -v ipcalc &>/dev/null; then
            echo "Error: Failed to install 'ipcalc'. Please install it manually."
            exit 1
        fi
    else
        echo "Error: Unsupported OS."
        exit 1
    fi

    if [[ ! -f config.yaml ]]; then
        echo "Error: 'config.yaml' not found in the current directory."
        exit 1
    fi

    if ! check_duplicate_client_names; then
        exit 1
    fi

    mkdir -p /etc/wireguard
    rollback_actions+=("rm -rf /etc/wireguard")
    cp config.yaml "$(dirname "$0")/config.yaml.backup"
    rollback_actions+=("rm -f \"$(dirname "$0")/config.yaml.backup\"")
    chmod 600 "$(dirname "$0")/config.yaml.backup"

    if ! generate_full_configs; then
        echo "Error: Failed to generate configurations."
        exit 1
    fi

    inet_enabled=$(yq e '.local_peer.inet.enabled' config.yaml)
    inet6_enabled=$(yq e '.local_peer.inet6.enabled' config.yaml)
    server_inet=$(yq e '.local_peer.inet.gateway' config.yaml)
    server_inet6=$(yq e '.local_peer.inet6.gateway' config.yaml)
    server_inet6_mask=$(yq e '.local_peer.inet6.gateway' config.yaml | cut -d '/' -f 2)
    port=$(yq e '.local_peer.port' config.yaml)

    if [[ "$inet_enabled" == "true" ]]; then
        vpn_inet_subnet=$(ipcalc "$server_inet" | grep -oP 'Network:\s*\K[\d.]+/\d+')
        if [[ -z "$ loosevpn_inet_subnet" ]]; then
            echo "Error: Failed to calculate inet subnet using ipcalc for $server_inet."
            exit 1
        fi
    fi

    if [[ "$inet6_enabled" == "true" ]]; then
        if [[ $server_inet6_mask -lt 0 || $server_inet6_mask -gt 128 ]]; then
            echo "Error: Invalid prefix length. Must be between 0 and 128."
            exit 1
        fi
        vpn_inet6_subnet=$(ipcalc "$server_inet6" | grep -oP 'Prefix:\s*\K[0-9a-f:]+/\d+')
        if [[ -z "$vpn_inet6_subnet" ]]; then
            echo "Error: Failed to calculate inet6 subnet using ipcalc for $server_inet6."
            exit 1
        fi
    fi

    echo
    echo "WireGuard installation is ready to begin."

    # Backup sysctl.conf
    sysctl_backup="/etc/sysctl.conf.backup-$(date +%F-%T)"
    cp /etc/sysctl.conf "$sysctl_backup" || {
        echo "Error: Failed to backup /etc/sysctl.conf to $sysctl_backup"
        rollback_on_failure
    }
    rollback_actions+=("mv \"$sysctl_backup\" /etc/sysctl.conf")

    # Apply runtime settings with explicit checks
    if ! sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1; then
        echo "Error: Failed to set net.ipv4.ip_forward=1 at runtime"
        rollback_on_failure
    fi
    if ! sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null 2>&1; then
        echo "Error: Failed to set net.ipv6.conf.all.forwarding=1 at runtime"
        rollback_on_failure
    fi

    # Check file state without triggering ERR trap
    set +e  # Disable exit-on-error for grep
    ipv4_forward_active=$(grep -c "^net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf || true)
    ipv6_forward_active=$(grep -c "^net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf || true)
    set -e  # Re-enable exit-on-error

    settings_added_by_script=false

    # Handle IPv4 forwarding
    if [[ $ipv4_forward_active -eq 0 ]]; then
        if grep -q "^#\s*net\.ipv4\.ip_forward\s*=\s*1" /etc/sysctl.conf; then
            echo "Found commented net.ipv4.ip_forward=1, attempting to uncomment..."
            if ! sed -i "s|^#\s*net\.ipv4\.ip_forward\s*=\s*1|net.ipv4.ip_forward=1|" /etc/sysctl.conf; then
                echo "Error: Failed to uncomment net.ipv4.ip_forward=1"
                rollback_on_failure
            fi
            echo "Uncommented net.ipv4.ip_forward=1"
            settings_added_by_script=true
        else
            echo "No net.ipv4.ip_forward=1 found, appending..."
            if ! echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf; then
                echo "Error: Failed to append net.ipv4.ip_forward=1"
                rollback_on_failure
            fi
            echo "Added net.ipv4.ip_forward=1"
            settings_added_by_script=true
        fi
    fi

    # Handle IPv6 forwarding
    if [[ $ipv6_forward_active -eq 0 ]]; then
        if grep -q "^#\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1" /etc/sysctl.conf; then
            echo "Found commented net.ipv6.conf.all.forwarding=1, attempting to uncomment..."
            if ! sed -i "s|^#\s*net\.ipv6\.conf\.all\.forwarding\s*=\s*1|net.ipv6.conf.all.forwarding=1|" /etc/sysctl.conf; then
                echo "Error: Failed to uncomment net.ipv6.conf.all.forwarding=1"
                rollback_on_failure
            fi
            echo "Uncommented net.ipv6.conf.all.forwarding=1"
            settings_added_by_script=true
        else
            echo "No net.ipv6.conf.all.forwarding=1 found, appending..."
            if ! echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf; then
                echo "Error: Failed to append net.ipv6.conf.all.forwarding=1"
                rollback_on_failure
            fi
            echo "Added net.ipv6.conf.all.forwarding=1"
            settings_added_by_script=true
        fi
    fi

    # Add rollback action only if we modified the file
    if [[ "$settings_added_by_script" == "true" ]]; then
        rollback_actions+=("sed -i 's|^net\.ipv4\.ip_forward\s*=\s*1|#net.ipv4.ip_forward=1|' /etc/sysctl.conf; sed -i 's|^net\.ipv6\.conf\.all\.forwarding\s*=\s*1|#net.ipv6.conf.all.forwarding=1|' /etc/sysctl.conf; sysctl -p || echo 'Warning: sysctl -p failed during rollback'")
    fi

    # Reload sysctl to apply file changes
    if ! sysctl -p /etc/sysctl.conf >/dev/null 2>&1; then
        echo "Warning: Failed to reload sysctl.conf, but continuing..."
    fi

    configure_firewall "$port" "$vpn_inet_subnet" "$vpn_inet6_subnet"

    echo "Activating WireGuard interface..."
    if systemctl enable --now wg-quick@${interface_name}; then
        rollback_actions+=("systemctl disable --now wg-quick@${interface_name}")
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
        rollback_actions+=("rm -rf \"$(dirname "$0")/wireguard-configs/qr\"")
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

    trap - ERR
else
    echo "WireGuard is already installed."
    echo "Select an option:"
    echo "   1) Re-create server and client configurations from YAML"
    echo "   2) Remove a Client"
    echo "   3) Update yq"
    echo "   4) Remove WireGuard"
    echo "   5) Exit"
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
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            inet_enabled=$(yq e '.local_peer.inet.enabled' config.yaml)
            server_inet=$(yq e '.local_peer.inet.gateway' config.yaml)
            server_inet_ip=$(echo "$server_inet" | cut -d '/' -f 1)
            server_inet_mask=$(echo "$server_inet" | cut -d '/' -f 2)
            base_inet=$(echo "$server_inet_ip" | cut -d '.' -f 1-3)
            inet6_enabled=$(yq e '.local_peer.inet6.enabled' config.yaml)
            server_inet6=$(yq e '.local_peer.inet6.gateway' config.yaml)
            server_inet6_mask=$(echo "$server_inet6" | cut -d '/' -f 2)

            if [[ "$inet_enabled" == "true" ]]; then
                vpn_inet_subnet=$(ipcalc "$server_inet" | grep -oP 'Network:\s*\K[\d.]+/\d+')
                if [[ -z "$vpn_inet_subnet" ]]; then
                    echo "Error: Failed to calculate inet subnet using ipcalc for $server_inet."
                    exit 1
                fi
            fi

            if [[ "$inet6_enabled" == "true" ]]; then
                if [[ $server_inet6_mask -lt 0 || $server_inet6_mask -gt 128 ]]; then
                    echo "Error: Invalid prefix length. Must be between 0 and 128."
                    exit 1
                fi
                vpn_inet6_subnet=$(ipcalc "$server_inet6" | grep -oP 'Prefix:\s*\K[0-9a-f:]+/\d+')
                if [[ -z "$vpn_inet6_subnet" ]]; then
                    echo "Error: Failed to calculate inet6 subnet using ipcalc for $server_inet6."
                    exit 1
                fi
            fi

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

                old_clients=$(yq e '.remote_peer | length' "$(dirname "$0")/config.yaml.backup")
                new_clients=$(yq e '.remote_peer | length' config.yaml)
                declare -A current_names
                for i in $(seq 0 $((new_clients - 1))); do
                    client_name=$(yq e ".remote_peer[$i].name" config.yaml)
                    current_names["$client_name"]=1
                done

                for i in $(seq 0 $((old_clients - 1))); do
                    old_name=$(yq e ".remote_peer[$i].name" "$(dirname "$0")/config.yaml.backup")
                    if [[ -n "$old_name" && -z "${current_names[$old_name]}" ]]; then
                        echo "Detected removed client: $old_name. Cleaning up..."
                        client_conf="$(dirname "$0")/wireguard-configs/${old_name}-${interface_name}.conf"
                        if [[ -f "$client_conf" ]]; then
                            rm -f "$client_conf"
                            echo "Removed client config: $client_conf"
                        fi
                        qr_file="$(dirname "$0")/wireguard-configs/qr/${old_name}-${interface_name}.png"
                        if [[ -f "$qr_file" ]]; then
                            rm -f "$qr_file"
                            echo "Removed QR code: $qr_file"
                        fi
                    fi
                done

                old_server_inet=$(yq e '.local_peer.inet.gateway' "$(dirname "$0")/config.yaml.backup")
                old_server_inet6=$(yq e '.local_peer.inet6.gateway' "$(dirname "$0")/config.yaml.backup")
                gateway_changed=false
                if [[ "$inet_enabled" == "true" && "$server_inet" != "$old_server_inet" ]]; then
                    echo "inet gateway changed from '$old_server_inet' to '$server_inet'."
                    gateway_changed=true
                fi
                if [[ "$inet6_enabled" == "true" && "$server_inet6" != "$old_server_inet6" ]]; then
                    echo "inet6 gateway changed from '$old_server_inet6' to '$server_inet6'."
                    gateway_changed=true
                fi

                if [[ "$gateway_changed" == "true" ]]; then
                    echo "Gateway changed. Regenerating all configurations with updated client IPs..."
                    if ! generate_full_configs; then
                        echo "Error: Failed to regenerate configurations."
                        rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                        exit 1
                    fi
                    cp config.yaml "$(dirname "$0")/config.yaml.backup"
                    chmod 600 "$(dirname "$0")/config.yaml.backup"

                    clear_firewall_rules
                    configure_firewall "$port" "$vpn_inet_subnet" "$vpn_inet6_subnet"

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
                    yq e '.local_peer' config.yaml > /tmp/server_new.yaml
                    yq e '.local_peer' "$(dirname "$0")/config.yaml.backup" > /tmp/server_old.yaml
                    if ! cmp -s /tmp/server_new.yaml /tmp/server_old.yaml; then
                        echo "Server configuration changed (but not gateway). Regenerating all configurations..."
                        if ! generate_full_configs; then
                            echo "Error: Failed to regenerate configurations."
                            rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                            exit 1
                        fi
                        cp config.yaml "$(dirname "$0")/config.yaml.backup"
                        chmod 600 "$(dirname "$0")/config.yaml.backup"

                        clear_firewall_rules
                        configure_firewall "$port" "$vpn_inet_subnet" "$vpn_inet6_subnet"

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

                        for i in $(seq 0 $((number_of_clients - 1))); do
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
                            configure_firewall "$port" "$vpn_inet_subnet" "$vpn_inet6_subnet"

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
                            echo "No actionable changes detected in client configurations (after cleanup)."
                            rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                            cp config.yaml "$(dirname "$0")/config.yaml.backup"
                            chmod 600 "$(dirname "$0")/config.yaml.backup"
                            exit 0
                        fi
                    fi
                    rm -f /tmp/server_new.yaml /tmp/server_old.yaml
                fi
            else
                echo "No backup found. Regenerating all configurations..."
                if ! generate_full_configs; then
                    echo "Error: Failed to regenerate configurations."
                    exit 1
                fi
                cp config.yaml "$(dirname "$0")/config.yaml.backup"
                chmod 600 "$(dirname "$0")/config.yaml.backup"

                clear_firewall_rules
                configure_firewall "$port" "$vpn_inet_subnet" "$vpn_inet6_subnet"

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
            if [[ ! -f config.yaml ]]; then
                echo "Error: 'config.yaml' not found in the current directory."
                exit 1
            fi

            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            number_of_clients=$(yq e '.remote_peer | length' config.yaml)

            if [[ $number_of_clients -eq 0 ]]; then
                echo "No clients defined in config.yaml."
                exit 0
            fi

            echo "Current clients:"
            for i in $(seq 0 $(($number_of_clients - 1))); do
                client_name=$(yq e ".remote_peer[$i].name" config.yaml)
                echo "   $((i + 1))) $client_name"
            done

            read -p "Enter the number of the client to delete (1-$number_of_clients, or 'q' to quit): " choice
            if [[ "$choice" == "q" || "$choice" == "Q" ]]; then
                echo "Exiting without changes."
                exit 0
            fi

            if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ $choice -lt 1 || $choice -gt $number_of_clients ]]; then
                echo "Error: Invalid selection. Must be a number between 1 and $number_of_clients."
                exit 1
            fi

            index=$((choice - 1))
            client_name=$(yq e ".remote_peer[$index].name" config.yaml)
            echo "Deleting client: $client_name..."

            server_conf="/etc/wireguard/${interface_name}.conf"

            cp config.yaml config.yaml.tmp
            yq e -i "del(.remote_peer[$index])" config.yaml.tmp
            mv config.yaml.tmp config.yaml
            echo "Removed $client_name from config.yaml."

            client_conf="$(dirname "$0")/wireguard-configs/${client_name}-${interface_name}.conf"
            if [[ -f "$client_conf" ]]; then
                rm -f "$client_conf"
                echo "Removed client config: $client_conf"
            fi

            qr_file="$(dirname "$0")/wireguard-configs/qr/${client_name}-${interface_name}.png"
            if [[ -f "$qr_file" ]]; then
                rm -f "$qr_file"
                echo "Removed QR code: $qr_file"
            fi

            cp config.yaml "$(dirname "$0")/config.yaml.backup"
            chmod 600 "$(dirname "$0")/config.yaml.backup"

            echo "Restarting WireGuard service to apply changes..."
            if systemctl restart wg-quick@"$interface_name"; then
                if ! wg show "$interface_name" >/dev/null 2>&1; then
                    echo "Warning: $interface_name failed to restart properly, attempting manual restart..."
                    wg-quick down "$interface_name" >/dev/null 2>&1
                    wg-quick up "$interface_name"
                    if wg show "$interface_name" >/dev/null 2>&1; then
                        echo "WireGuard interface $interface_name is now active after manual restart."
                    else
                        echo "Error: Failed to restart $interface_name even after manual restart."
                        exit 1
                    fi
                else
                    echo "WireGuard service restarted successfully."
                fi
            else
                echo "Error: Failed to restart $interface_name."
                exit 1
            fi

            echo "Client $client_name deleted successfully."
            ;;

        3)
            echo "Updating 'yq' to the latest version..."
            ARCH=$(uname -m)
            case "$ARCH" in
                x86_64)
                    wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq && \
                    chmod +x /usr/bin/yq
                    ;;
                aarch64)
                    wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_arm64 -O /usr/bin/yq && \
                    chmod +x /usr/bin/yq
                    ;;
                *)
                    echo "Error: Unsupported architecture '$ARCH'. Supported architectures are 'x86_64' (AMD64) and 'aarch64' (ARM64)."
                    echo "Please install 'yq' manually for your system."
                    exit 1
                    ;;
            esac
            if ! command -v yq &>/dev/null; then
                echo "Error: Failed to update 'yq'. Please install it manually."
                exit 1
            fi
            echo "Successfully updated 'yq' to version: $(yq --version)"
            ;;

        4)
            [[ "$interface_name" == "null" || -z "$interface_name" ]] && interface_name="wg0"
            systemctl disable --now wg-quick@"$interface_name"

            clear_firewall_rules

            if [[ -d "$(dirname "$0")/wireguard-configs" ]]; then
                rm -rf "$(dirname "$0")/wireguard-configs"
                echo "Removed client configuration directory (including QR codes): $(dirname "$0")/wireguard-configs"
            fi

            rm -rf /etc/wireguard
            apt remove -y wireguard wireguard-tools qrencode ipcalc --purge
            rm -f /usr/bin/yq
            ;;

        5)
            exit 0
            ;;
        *)
            echo "Invalid option."
            exit 1
            ;;
    esac
fi
