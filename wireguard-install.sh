#!/bin/bash

# Check if running as root
if [ "$(id -u)" -ne 0 ]; then
   echo "This script must be run as root"
   exit 1
fi

# Check dependencies
for cmd in wg yq; do
  if ! command -v $cmd &> /dev/null; then
    echo "Error: $cmd is required but not installed."
    exit 1
  fi
done

# Check for qrencode specifically
if ! command -v qrencode &> /dev/null; then
  echo "Error: qrencode is required but not installed."
  echo "Please install it with your package manager, e.g.:"
  echo "  apt install qrencode  # Debian/Ubuntu"
  echo "  yum install qrencode  # CentOS/RHEL"
  exit 1
fi

CONFIG_FILE="wireguard.yaml"
CLIENT_OUTPUT_DIR="wireguard-configs"
SERVER_CONFIG="/etc/wireguard/wg0.conf"
KEYS_DIR="${CLIENT_OUTPUT_DIR}/keys"
DEFAULT_MTU=1420
DEFAULT_PORT=51820

# Function to get IP address of an interface
get_interface_ip() {
  local interface=$1
  local ip_address

  # Try to get IPv4 address
  ip_address=$(ip -4 addr show dev "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)

  if [ -z "$ip_address" ]; then
    echo "Error: No IPv4 address found for interface $interface"
    return 1
  fi

  echo "$ip_address"
}

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Error: Config file $CONFIG_FILE not found."
  exit 1
fi

# Create output directories
mkdir -p "$CLIENT_OUTPUT_DIR"
mkdir -p "$KEYS_DIR"
mkdir -p "/etc/wireguard"

# Function to generate key pair if it doesn't exist
generate_keys() {
  local name=$1
  local private_key_file="${KEYS_DIR}/${name}.private"
  local public_key_file="${KEYS_DIR}/${name}.public"

  if [ ! -f "$private_key_file" ]; then
    echo "Generating new keys for $name..."
    wg genkey | tee "$private_key_file" | wg pubkey > "$public_key_file"
    chmod 600 "$private_key_file"
    return 0  # New keys generated
  fi

  return 1  # Existing keys used
}

# Generate server keys if they don't exist
generate_keys "server"
SERVER_PRIVATE_KEY=$(cat "${KEYS_DIR}/server.private")
SERVER_PUBLIC_KEY=$(cat "${KEYS_DIR}/server.public")

# Check if server config already exists
SERVER_EXISTS=false
if [ -f "$SERVER_CONFIG" ]; then
  echo "Existing server configuration found."
  SERVER_EXISTS=true
fi

# Extract server details from YAML
SERVER_ENDPOINT=$(yq '.server.endpoint' "$CONFIG_FILE")
SERVER_PORT=$(yq '.server.port' "$CONFIG_FILE")
SERVER_INTERNAL_IP=$(yq '.server.internal_ip' "$CONFIG_FILE")
SERVER_INTERFACE=$(yq '.server.interface_name' "$CONFIG_FILE" || echo "wg0")
SERVER_HOST_INTERFACE=$(yq '.server.host_interface' "$CONFIG_FILE")
SERVER_MTU=$(yq '.server.mtu' "$CONFIG_FILE")
SERVER_POST_UP=$(yq '.server.post_up' "$CONFIG_FILE")
SERVER_POST_DOWN=$(yq '.server.post_down' "$CONFIG_FILE")

# Set default port if not specified
if [ "$SERVER_PORT" == "null" ] || [ -z "$SERVER_PORT" ]; then
  SERVER_PORT=$DEFAULT_PORT
  echo "No port specified, using default: $SERVER_PORT"
fi

# Determine the host interface to use
if [ "$SERVER_HOST_INTERFACE" == "null" ] || [ -z "$SERVER_HOST_INTERFACE" ]; then
  # Default to the interface with the default route if not specified
  SERVER_HOST_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
  echo "No host interface specified, using: $SERVER_HOST_INTERFACE"
else
  # Verify the specified interface exists
  if ! ip link show dev "$SERVER_HOST_INTERFACE" &>/dev/null; then
    echo "Error: Specified host interface '$SERVER_HOST_INTERFACE' not found."
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print $2}'
    exit 1
  fi
fi

# Determine the endpoint IP address
if [ "$SERVER_ENDPOINT" == "null" ] || [ -z "$SERVER_ENDPOINT" ] || [ "$SERVER_ENDPOINT" == "auto" ]; then
  SERVER_ENDPOINT=$(get_interface_ip "$SERVER_HOST_INTERFACE")
  if [ $? -ne 0 ]; then
    echo "$SERVER_ENDPOINT" # This will contain the error message
    exit 1
  fi
  echo "Automatically detected endpoint IP: $SERVER_ENDPOINT"
fi

# Default PostUp/PostDown rules with placeholder for host interface
DEFAULT_POST_UP="iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o %h -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o %h -j MASQUERADE"
DEFAULT_POST_DOWN="iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o %h -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o %h -j MASQUERADE"

# Create server config only if it doesn't exist
if [ "$SERVER_EXISTS" = false ]; then
  echo "Creating new server configuration..."

  # Create server config
  cat > "$SERVER_CONFIG" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_INTERNAL_IP
ListenPort = $SERVER_PORT
EOF

  # Add optional server parameters
  if [ "$SERVER_MTU" != "null" ]; then
    echo "MTU = $SERVER_MTU" >> "$SERVER_CONFIG"
  else
    echo "MTU = $DEFAULT_MTU" >> "$SERVER_CONFIG"
  fi

  # Process PostUp rules
  if [ "$SERVER_POST_UP" != "null" ]; then
    # Replace %h with the actual host interface in custom rules
    PROCESSED_POST_UP="${SERVER_POST_UP//%h/$SERVER_HOST_INTERFACE}"
    echo "PostUp = $PROCESSED_POST_UP" >> "$SERVER_CONFIG"
  else
    # Use default rules with actual host interface
    PROCESSED_POST_UP="${DEFAULT_POST_UP//%h/$SERVER_HOST_INTERFACE}"
    echo "PostUp = $PROCESSED_POST_UP" >> "$SERVER_CONFIG"
  fi

  # Process PostDown rules
  if [ "$SERVER_POST_DOWN" != "null" ]; then
    # Replace %h with the actual host interface in custom rules
    PROCESSED_POST_DOWN="${SERVER_POST_DOWN//%h/$SERVER_HOST_INTERFACE}"
    echo "PostDown = $PROCESSED_POST_DOWN" >> "$SERVER_CONFIG"
  else
    # Use default rules with actual host interface
    PROCESSED_POST_DOWN="${DEFAULT_POST_DOWN//%h/$SERVER_HOST_INTERFACE}"
    echo "PostDown = $PROCESSED_POST_DOWN" >> "$SERVER_CONFIG"
  fi

  # Set secure permissions on server config
  chmod 600 "$SERVER_CONFIG"
else
  echo "Using existing server configuration."
  # We need to append new clients to the existing config - first create a backup
  cp "$SERVER_CONFIG" "${SERVER_CONFIG}.bak"
fi

# Get list of existing clients by parsing server config
EXISTING_CLIENTS=()
if [ -f "$SERVER_CONFIG" ]; then
  while read -r line; do
    if [[ "$line" =~ ^#\ (.+)$ ]]; then
      client_name="${BASH_REMATCH[1]}"
      EXISTING_CLIENTS+=("$client_name")
    fi
  done < <(grep -A 1 "\[Peer\]" "$SERVER_CONFIG" | grep "^#")
fi

echo "Existing clients: ${EXISTING_CLIENTS[*]}"

# Process each client from YAML
CLIENT_COUNT=$(yq '.clients | length' "$CONFIG_FILE")
ADDED_NEW_CLIENTS=false

for (( i=0; i<$CLIENT_COUNT; i++ )); do
  CLIENT_NAME=$(yq ".clients[$i].name" "$CONFIG_FILE")

  # Check if client already exists
  CLIENT_EXISTS=false
  for existing in "${EXISTING_CLIENTS[@]}"; do
    if [ "$existing" = "$CLIENT_NAME" ]; then
      CLIENT_EXISTS=true
      break
    fi
  done

  # Skip if client already exists
  if [ "$CLIENT_EXISTS" = true ]; then
    echo "Client '$CLIENT_NAME' already exists, skipping."
    continue
  fi

  echo "Adding new client: $CLIENT_NAME"
  ADDED_NEW_CLIENTS=true

  CLIENT_IP=$(yq ".clients[$i].internal_ip" "$CONFIG_FILE")
  CLIENT_DNS=$(yq ".clients[$i].dns" "$CONFIG_FILE")
  CLIENT_ALLOWED_IPS=$(yq ".clients[$i].allowed_ips" "$CONFIG_FILE")
  CLIENT_KEEPALIVE=$(yq ".clients[$i].persistent_keepalive" "$CONFIG_FILE")
  CLIENT_MTU=$(yq ".clients[$i].mtu" "$CONFIG_FILE")

  # Generate client keys
  generate_keys "$CLIENT_NAME"
  CLIENT_PRIVATE_KEY=$(cat "${KEYS_DIR}/${CLIENT_NAME}.private")
  CLIENT_PUBLIC_KEY=$(cat "${KEYS_DIR}/${CLIENT_NAME}.public")

  # Add client to server config
  cat >> "$SERVER_CONFIG" << EOF

[Peer]
# $CLIENT_NAME
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP
EOF

  # Create client config
  CLIENT_CONFIG="${CLIENT_OUTPUT_DIR}/${CLIENT_NAME}.conf"
  cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
EOF

  # Add MTU to client config (default 1420 if not specified)
  if [ "$CLIENT_MTU" != "null" ]; then
    echo "MTU = $CLIENT_MTU" >> "$CLIENT_CONFIG"
  else
    echo "MTU = $DEFAULT_MTU" >> "$CLIENT_CONFIG"
  fi

  # Add DNS if specified
  if [ "$CLIENT_DNS" != "null" ]; then
    echo "DNS = $CLIENT_DNS" >> "$CLIENT_CONFIG"
  fi

  # Add server as peer in client config
  cat >> "$CLIENT_CONFIG" << EOF

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = $CLIENT_ALLOWED_IPS
EOF

  # Add persistent keepalive if specified
  if [ "$CLIENT_KEEPALIVE" != "null" ]; then
    echo "PersistentKeepalive = $CLIENT_KEEPALIVE" >> "$CLIENT_CONFIG"
  fi

  # Generate and display QR code for this client
  echo "==============================================="
  echo "QR Code for client: $CLIENT_NAME"
  echo "==============================================="
  qrencode -t ansiutf8 < "${CLIENT_CONFIG}"
  echo "==============================================="

  # Also save QR code as image file
  qrencode -t png -o "${CLIENT_OUTPUT_DIR}/${CLIENT_NAME}.png" < "${CLIENT_CONFIG}"
  echo "QR code image saved as: ${CLIENT_OUTPUT_DIR}/${CLIENT_NAME}.png"
  echo ""
done

# Only restart services if we made changes
if [ "$SERVER_EXISTS" = false ] || [ "$ADDED_NEW_CLIENTS" = true ]; then
  # Enable IP forwarding
  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
  echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
  sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1

  # Setup WireGuard service
  systemctl enable wg-quick@wg0 >/dev/null 2>&1
  systemctl restart wg-quick@wg0 >/dev/null 2>&1

  # Open firewall port if ufw is installed
  if command -v ufw &> /dev/null && ufw status | grep -q "active"; then
    ufw allow $SERVER_PORT/udp >/dev/null 2>&1
    ufw reload >/dev/null 2>&1
  fi

  echo "WireGuard service restarted with updated configuration."
else
  echo "No changes made to WireGuard configuration."
fi

if [ "$ADDED_NEW_CLIENTS" = false ]; then
  echo "No new clients added."
fi

echo "WireGuard setup complete using host interface: $SERVER_HOST_INTERFACE with endpoint: $SERVER_ENDPOINT:$SERVER_PORT"
