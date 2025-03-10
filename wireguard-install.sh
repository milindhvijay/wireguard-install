#!/bin/bash
#
# WireGuard Installer with YAML Configuration
# Requires yq (https://github.com/mikefarah/yq) for YAML parsing

CONFIG_FILE="wireguard-config.yml"

# Function to parse YAML config
parse_config() {
    if ! command -v yq &> /dev/null; then
        echo "yq is required to parse the YAML configuration. Please install it."
        exit 1
    fi

    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Configuration file $CONFIG_FILE not found."
        exit 1
    fi

    server_port=$(yq eval '.server.port' "$CONFIG_FILE")
    host_interface=$(yq eval '.server.host_interface' "$CONFIG_FILE")
    server_mtu=$(yq eval '.server.mtu' "$CONFIG_FILE")
    public_endpoint=$(yq eval '.server.public_endpoint' "$CONFIG_FILE")

    ipv4_enabled=$(yq eval '.server.ipv4.enabled' "$CONFIG_FILE")
    ipv4_address=$(yq eval '.server.ipv4.address' "$CONFIG_FILE")

    ipv6_enabled=$(yq eval '.server.ipv6.enabled' "$CONFIG_FILE")
    ipv6_address=$(yq eval '.server.ipv6.address' "$CONFIG_FILE")

    clients=()
    while IFS= read -r line; do
        clients+=("$line")
    done < <(yq eval -j '.clients[]' "$CONFIG_FILE" | jq -r '@base64')
}

# Function to generate server configuration
generate_server_config() {
    cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = $ipv4_address${ipv6_address:+, $ipv6_address}
ListenPort = $server_port
PrivateKey = $(wg genkey)
MTU = $server_mtu

EOF
}

# Function to generate client configuration
generate_client_config() {
    local client_data=$(echo "$1" | base64 --decode)
    local name=$(echo "$client_data" | jq -r '.name')
    local dns=$(echo "$client_data" | jq -r '.dns')
    local mtu=$(echo "$client_data" | jq -r '.mtu')
    local allowed_ips=$(echo "$client_data" | jq -r '.allowed_ips')
    local persistent_keepalive=$(echo "$client_data" | jq -r '.persistent_keepalive')

    # Generate keys
    local private_key=$(wg genkey)
    local public_key=$(wg pubkey <<< "$private_key")
    local psk=$(wg genpsk)

    # Add client to server config
    cat << EOF >> /etc/wireguard/wg0.conf
[Peer]
PublicKey = $public_key
PresharedKey = $psk
AllowedIPs = $(echo "$ipv4_address" | cut -d/ -f1 | cut -d. -f1-3).${client_id}/32
EOF

    # Create client config
    cat << EOF > ~/"$name.conf"
[Interface]
Address = $(echo "$ipv4_address" | cut -d/ -f1 | cut -d. -f1-3).${client_id}/24
DNS = $dns
MTU = $mtu
PrivateKey = $private_key

[Peer]
PublicKey = $(grep PrivateKey /etc/wireguard/wg0.conf | cut -d " " -f 3 | wg pubkey)
PresharedKey = $psk
AllowedIPs = $allowed_ips
Endpoint = ${public_endpoint:-$(curl -4 ifconfig.co)}:$server_port
PersistentKeepalive = $persistent_keepalive
EOF

    echo "Client $name configuration generated at ~/$name.conf"
}

# Main installation logic
install_wireguard() {
    # Parse YAML config
    parse_config

    # Check for root privileges
    if [[ "$EUID" -ne 0 ]]; then
        echo "This installer needs to be run with superuser privileges."
        exit 1
    fi

    # Install required packages
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get update
        apt-get install -y wireguard qrencode resolvconf
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        dnf install -y wireguard-tools qrencode
    fi

    # Generate server configuration
    generate_server_config

    # Generate client configurations
    local client_id=2
    for client_base64 in "${clients[@]}"; do
        generate_client_config "$client_base64" "$client_id"
        ((client_id++))
    done

    # Enable IP forwarding
    echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
    echo 1 > /proc/sys/net/ipv4/ip_forward

    if [[ "$ipv6_enabled" == "true" ]]; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
        echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
    fi

    # Start and enable WireGuard service
    systemctl enable --now wg-quick@wg0.service

    echo "WireGuard installation complete!"
}

# Uninstall WireGuard
uninstall_wireguard() {
    systemctl disable --now wg-quick@wg0.service
    rm -rf /etc/wireguard/
    rm -f /etc/sysctl.d/99-wireguard-forward.conf

    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get remove --purge -y wireguard wireguard-tools
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
        dnf remove -y wireguard-tools
    fi

    echo "WireGuard has been uninstalled."
}

# Main menu
main_menu() {
    echo "WireGuard Manager"
    echo "1) Install WireGuard"
    echo "2) Uninstall WireGuard"
    echo "3) Exit"
    read -p "Choose an option: " choice

    case "$choice" in
        1) install_wireguard ;;
        2) uninstall_wireguard ;;
        3) exit 0 ;;
        *) echo "Invalid option. Exiting." ;;
    esac
}

# Detect OS
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
elif [[ -e /etc/debian_version ]]; then
    os="debian"
elif [[ -e /etc/centos-release ]]; then
    os="centos"
elif [[ -e /etc/fedora-release ]]; then
    os="fedora"
else
    echo "Unsupported OS. Exiting."
    exit 1
fi

# Start the script
main_menu
