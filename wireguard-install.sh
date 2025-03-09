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
YAML_MODIFIED=false

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

# Function to calculate next available IP in range
get_next_available_ip() {
  local network_base=$1
  local network_prefix=$2
  local used_ips=$3

  # Calculate network base and range
  IFS='.' read -r -a octets <<< "$network_base"
  local start_ip="${octets[0]}.${octets[1]}.${octets[2]}.2"  # Start from .2 as .1 is server
  local end_num=254  # Max for typical subnet

  # If prefix is small (e.g., /16), set appropriate range
  if [ "$network_prefix" -lt 24 ]; then
    # For now, we'll still use the same octet for simplicity
    # but could expand to full subnet range if needed
    end_num=254
  fi

  # Find next available IP
  for ((i=2; i<=end_num; i++)); do
    local candidate_ip="${octets[0]}.${octets[1]}.${octets[2]}.$i"
    if ! echo "$used_ips" | grep -q "$candidate_ip"; then
      echo "$candidate_ip"
      return 0
    fi
  done

  echo "Error: No available IPs in the subnet"
  return 1
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
SERVER_INTERNAL_IP=$(yq '.server.internal_ip' "$CONFIG_FILE" | tr -d '"')
SERVER_INTERFACE=$(yq '.server.interface_name' "$CONFIG_FILE" || echo "wg0")
SERVER_HOST_INTERFACE=$(yq '.server.host_interface' "$CONFIG_FILE" | tr -d '"')
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

# Parse server internal IP to get network
if ! [[ "$SERVER_INTERNAL_IP" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)/([0-9]+)$ ]]; then
  echo "Error: Invalid server internal IP format. Expected format: x.x.x.x/y"
  exit 1
fi

NETWORK_BASE="${BASH_REMATCH[1]}"
SERVER_IP_LAST_OCTET="${BASH_REMATCH[2]}"
NETWORK_PREFIX="${BASH_REMATCH[3]}"
NETWORK="${NETWORK_BASE}.0/${NETWORK_PREFIX}"

echo "Server network: $NETWORK (Base: $NETWORK_BASE, Prefix: $NETWORK_PREFIX)"

# Collect all used IPs
USED_IPS="$NETWORK_BASE.$SERVER_IP_LAST_OCTET"  # Server IP is used

# Get existing client IPs from YAML
CLIENT_COUNT=$(yq '.clients | length' "$CONFIG_FILE")
for (( i=0; i<$CLIENT_COUNT; i++ )); do
  CLIENT_IP=$(yq ".clients[$i].internal_ip" "$CONFIG_FILE")
  if [ "$CLIENT_IP" != "null" ] && [ -n "$CLIENT_IP" ]; then
    # Strip the CIDR notation if present
    CLIENT_IP=${CLIENT_IP%/*}
    USED_IPS="$USED_IPS
$CLIENT_IP"
  fi
done

# Collect IPs from existing WireGuard config if it exists
if [ -f "$SERVER_CONFIG" ]; then
  while read -r line; do
    if [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
      ip="${BASH_REMATCH[1]}"
      # Strip the CIDR notation if present
      ip=${ip%/*}
      USED_IPS="$USED_IPS
$ip"
    fi
  done < "$SERVER_CONFIG"
fi

echo "Used IPs in network: $(echo "$USED_IPS" | tr '\n' ' ')"

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

# Get list of YAML clients for comparison with existing clients
YAML_CLIENTS=()
for (( i=0; i<$CLIENT_COUNT; i++ )); do
  client_name=$(yq ".clients[$i].name" "$CONFIG_FILE")
  YAML_CLIENTS+=("$client_name")
done

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

# Identify clients to remove (exist in server config but not in YAML)
CLIENTS_TO_REMOVE=()
for existing in "${EXISTING_CLIENTS[@]}"; do
  client_in_yaml=false
  for yaml_client in "${YAML_CLIENTS[@]}"; do
    if [ "$existing" = "$yaml_client" ]; then
      client_in_yaml=true
      break
    fi
  done

  if [ "$client_in_yaml" = false ]; then
    CLIENTS_TO_REMOVE+=("$existing")
  fi
done

# Remove clients that are no longer in YAML
if [ ${#CLIENTS_TO_REMOVE[@]} -gt 0 ]; then
  echo "Removing ${#CLIENTS_TO_REMOVE[@]} clients that are no longer in YAML..."

  # Create a temporary file for the new config
  TEMP_SERVER_CONFIG=$(mktemp)

  # Process the server config line by line
  in_peer_to_remove=false
  client_name_to_remove=""

  while IFS= read -r line || [ -n "$line" ]; do
    # Check if we've hit a new peer section
    if [[ "$line" == "[Peer]" ]]; then
      # Write the current line to the temp file
      echo "$line" >> "$TEMP_SERVER_CONFIG"

      # Next line should be a comment with the client name
      # Get the next line to check if this is a peer to remove
      read -r next_line

      if [[ "$next_line" =~ ^#\ (.+)$ ]]; then
        client_name="${BASH_REMATCH[1]}"

        # Check if this client should be removed
        for remove_name in "${CLIENTS_TO_REMOVE[@]}"; do
          if [ "$client_name" = "$remove_name" ]; then
            in_peer_to_remove=true
            client_name_to_remove="$client_name"
            echo "Found client to remove: $client_name"
            break
          fi
        done

        # If not a client to remove, write the line to the temp file
        if [ "$in_peer_to_remove" = false ]; then
          echo "$next_line" >> "$TEMP_SERVER_CONFIG"
        fi
      else
        # No client name found, just write the line
        echo "$next_line" >> "$TEMP_SERVER_CONFIG"
      fi
    elif [ "$in_peer_to_remove" = true ]; then
      # We're in a peer section that should be removed
      # Skip this line if it's part of the current peer
      if [[ "$line" == "" ]] || [[ "$line" == "[Interface]" ]] || [[ "$line" == "[Peer]" ]]; then
        # Empty line or new section means we're done with this peer
        in_peer_to_remove=false
        echo "Removed client: $client_name_to_remove"

        # Write the line if it's a new section
        if [[ "$line" == "[Interface]" ]] || [[ "$line" == "[Peer]" ]]; then
          echo "$line" >> "$TEMP_SERVER_CONFIG"
        elif [[ "$line" == "" ]]; then
          # Only add one blank line
          echo "" >> "$TEMP_SERVER_CONFIG"
        fi
      fi
      # Otherwise, skip the line (part of the peer to remove)
    else
      # Write all other lines unchanged
      echo "$line" >> "$TEMP_SERVER_CONFIG"
    fi
  done < "$SERVER_CONFIG"

  # Replace the original file with our updated version
  mv "$TEMP_SERVER_CONFIG" "$SERVER_CONFIG"
  chmod 600 "$SERVER_CONFIG"

  # Clean up client configuration files
  for client_name in "${CLIENTS_TO_REMOVE[@]}"; do
    client_conf="${CLIENT_OUTPUT_DIR}/${client_name}.conf"
    client_png="${CLIENT_OUTPUT_DIR}/${client_name}.png"

    # Remove client configuration if it exists
    if [ -f "$client_conf" ]; then
      rm -f "$client_conf"
      echo "Removed client config file: $client_conf"
    fi

    # Remove QR code image if it exists
    if [ -f "$client_png" ]; then
      rm -f "$client_png"
      echo "Removed client QR code: $client_png"
    fi
  done

  # Flag that we need to restart the service
  CLIENTS_REMOVED=true
  echo "Removed ${#CLIENTS_TO_REMOVE[@]} clients: ${CLIENTS_TO_REMOVE[*]}"
else
  echo "No clients need to be removed."
  CLIENTS_REMOVED=false
fi

# Check for updates to existing clients
CLIENTS_UPDATED=false
UPDATED_CLIENT_NAMES=()
CLIENT_CHANGES=()

echo "Checking for updates to existing clients..."

# Loop through all clients that exist in both YAML and server config
for client_name in "${EXISTING_CLIENTS[@]}"; do
  # Find if client exists in YAML
  client_index=-1
  for ((i=0; i<${#YAML_CLIENTS[@]}; i++)); do
    if [ "${YAML_CLIENTS[i]}" = "$client_name" ]; then
      client_index=$i
      break
    fi
  done

  # Skip if client not in YAML (these were handled by removal process)
  if [ $client_index -eq -1 ]; then
    continue
  fi

  # Get client properties from YAML
  YAML_IP=$(yq ".clients[$client_index].internal_ip" "$CONFIG_FILE")
  YAML_DNS=$(yq ".clients[$client_index].dns" "$CONFIG_FILE")
  YAML_ALLOWED_IPS=$(yq ".clients[$client_index].allowed_ips" "$CONFIG_FILE")
  YAML_KEEPALIVE=$(yq ".clients[$client_index].persistent_keepalive" "$CONFIG_FILE")
  YAML_MTU=$(yq ".clients[$client_index].mtu" "$CONFIG_FILE")

  # Get current client properties from config file
  CLIENT_CONFIG="${CLIENT_OUTPUT_DIR}/${client_name}.conf"
  if [ ! -f "$CLIENT_CONFIG" ]; then
    echo "Warning: Config file for existing client '$client_name' not found, skipping update."
    continue
  fi

  # Extract current values from client config
  CURRENT_IP=$(grep "^Address = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_DNS=$(grep "^DNS = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_ALLOWED_IPS=$(grep "^AllowedIPs = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_KEEPALIVE=$(grep "^PersistentKeepalive = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_MTU=$(grep "^MTU = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)

  # Strip CIDR notation for comparison if present
  CURRENT_IP_STRIPPED=${CURRENT_IP%/*}
  YAML_IP_STRIPPED=${YAML_IP%/*}

  # Check for changes
  CHANGES=""

  # Special handling for null values from YAML
  [ "$YAML_MTU" = "null" ] && YAML_MTU=$DEFAULT_MTU

  # Compare values (handling null/unset cases)
  if [ "$YAML_IP" != "null" ] && [ "$YAML_IP_STRIPPED" != "$CURRENT_IP_STRIPPED" ]; then
    CHANGES="${CHANGES}IP ($CURRENT_IP → $YAML_IP), "
  fi
  if [ "$YAML_DNS" != "null" ] && [ "$YAML_DNS" != "$CURRENT_DNS" ]; then
    CHANGES="${CHANGES}DNS ($CURRENT_DNS → $YAML_DNS), "
  elif [ "$YAML_DNS" = "null" ] && [ -n "$CURRENT_DNS" ]; then
    CHANGES="${CHANGES}DNS (removed), "
  fi
  if [ "$YAML_ALLOWED_IPS" != "null" ] && [ "$YAML_ALLOWED_IPS" != "$CURRENT_ALLOWED_IPS" ]; then
    CHANGES="${CHANGES}AllowedIPs ($CURRENT_ALLOWED_IPS → $YAML_ALLOWED_IPS), "
  fi
  if [ "$YAML_KEEPALIVE" != "null" ] && [ "$YAML_KEEPALIVE" != "$CURRENT_KEEPALIVE" ]; then
    CHANGES="${CHANGES}Keepalive ($CURRENT_KEEPALIVE → $YAML_KEEPALIVE), "
  elif [ "$YAML_KEEPALIVE" = "null" ] && [ -n "$CURRENT_KEEPALIVE" ]; then
    CHANGES="${CHANGES}Keepalive (removed), "
  fi
  if [ "$YAML_MTU" != "$CURRENT_MTU" ]; then
    CHANGES="${CHANGES}MTU ($CURRENT_MTU → $YAML_MTU), "
  fi

  # If no changes detected, skip this client
  if [ -z "$CHANGES" ]; then
    continue
  fi

  echo "Updating client '$client_name' with changes: ${CHANGES%, }"
  CLIENTS_UPDATED=true
  UPDATED_CLIENT_NAMES+=("$client_name")
  CLIENT_CHANGES+=("${CHANGES%, }")

  # Backup client config
  cp "$CLIENT_CONFIG" "${CLIENT_CONFIG}.bak"

  # Generate updated client config
  cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $(grep "^PrivateKey = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
Address = $YAML_IP
EOF

  # Add MTU
  if [ "$YAML_MTU" != "null" ]; then
    echo "MTU = $YAML_MTU" >> "$CLIENT_CONFIG"
  else
    echo "MTU = $DEFAULT_MTU" >> "$CLIENT_CONFIG"
  fi

  # Add DNS if specified
  if [ "$YAML_DNS" != "null" ]; then
    echo "DNS = $YAML_DNS" >> "$CLIENT_CONFIG"
  fi

  # Add server as peer in client config
  cat >> "$CLIENT_CONFIG" << EOF

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = $YAML_ALLOWED_IPS
EOF

  # Add persistent keepalive if specified
  if [ "$YAML_KEEPALIVE" != "null" ]; then
    echo "PersistentKeepalive = $YAML_KEEPALIVE" >> "$CLIENT_CONFIG"
  fi

  # Update server config if IP changed
  if [ "$YAML_IP" != "null" ] && [ "$YAML_IP_STRIPPED" != "$CURRENT_IP_STRIPPED" ]; then
    # Use temporary file to rebuild server config with updated IP
    TEMP_SERVER_CONFIG=$(mktemp)

    # Flag to identify when we're in the peer section for this client
    in_target_peer=false

    # Process server config line by line
    while IFS= read -r line || [ -n "$line" ]; do
      # Check if we've found the peer section for this client
      if [[ "$line" == "[Peer]" ]]; then
        echo "$line" >> "$TEMP_SERVER_CONFIG"
        # Read the next line to get client name
        read -r next_line

        if [[ "$next_line" =~ ^#\ (.+)$ ]]; then
          peer_name="${BASH_REMATCH[1]}"

          # Check if this is the client we're updating
          if [ "$peer_name" = "$client_name" ]; then
            in_target_peer=true
          else
            in_target_peer=false
          fi
        fi
        # Write the name line no matter what
        echo "$next_line" >> "$TEMP_SERVER_CONFIG"
      elif [ "$in_target_peer" = true ] && [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
        # Replace the AllowedIPs line with the new IP
        echo "AllowedIPs = $YAML_IP" >> "$TEMP_SERVER_CONFIG"
      else
        # Write all other lines unchanged
        echo "$line" >> "$TEMP_SERVER_CONFIG"
      fi
    done < "$SERVER_CONFIG"

    # Replace the original file with the updated one
    mv "$TEMP_SERVER_CONFIG" "$SERVER_CONFIG"
    chmod 600 "$SERVER_CONFIG"
  fi

  # Generate updated QR code
  qrencode -t png -o "${CLIENT_OUTPUT_DIR}/${client_name}.png" < "${CLIENT_CONFIG}"
  echo "Updated QR code saved as: ${CLIENT_OUTPUT_DIR}/${client_name}.png"

  # Display QR code in terminal for the updated client
  echo "==============================================="
  echo "QR Code for updated client: $client_name"
  echo "==============================================="
  qrencode -t ansiutf8 < "${CLIENT_CONFIG}"
  echo "==============================================="
done

if [ "$CLIENTS_UPDATED" = true ]; then
  echo "Updated ${#UPDATED_CLIENT_NAMES[@]} clients:"
  for ((i=0; i<${#UPDATED_CLIENT_NAMES[@]}; i++)); do
    echo " - ${UPDATED_CLIENT_NAMES[i]}: ${CLIENT_CHANGES[i]}"
  done
else
  echo "No client updates needed."
fi

# Process each client from YAML
CLIENT_COUNT=$(yq '.clients | length' "$CONFIG_FILE")
ADDED_NEW_CLIENTS=false
UPDATED_CLIENTS=()
UPDATED_IPS=()

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

  # Assign IP if not specified
  if [ "$CLIENT_IP" == "null" ] || [ -z "$CLIENT_IP" ]; then
    # Get next available IP
    NEW_IP=$(get_next_available_ip "$NETWORK_BASE" "$NETWORK_PREFIX" "$USED_IPS")
    if [ $? -ne 0 ]; then
      echo "$NEW_IP"  # This contains the error message
      exit 1
    fi

    # Add CIDR notation for client
    CLIENT_IP="${NEW_IP}/32"
    echo "Assigned IP address $CLIENT_IP to client $CLIENT_NAME"

    # Add to used IPs
    USED_IPS="$USED_IPS
$NEW_IP"

    # Track for YAML update
    UPDATED_CLIENTS+=($i)
    UPDATED_IPS+=("$CLIENT_IP")
    YAML_MODIFIED=true
  fi

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

# Update YAML file with assigned IPs
if [ "$YAML_MODIFIED" = true ]; then
  echo "Updating YAML file with assigned IP addresses..."

  # Create a backup of the original YAML
  cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"

  # Update each client that got an auto-assigned IP
  for (( i=0; i<${#UPDATED_CLIENTS[@]}; i++ )); do
    client_index=${UPDATED_CLIENTS[$i]}
    client_ip=${UPDATED_IPS[$i]}

    # Use yq to update the YAML file
    yq -i ".clients[$client_index].internal_ip = \"$client_ip\"" "$CONFIG_FILE"
  done

  echo "YAML file updated."
fi

# Only restart services if we made changes
if [ "$SERVER_EXISTS" = false ] || [ "$ADDED_NEW_CLIENTS" = true ] || [ "$CLIENTS_REMOVED" = true ] || [ "$CLIENTS_UPDATED" = true ]; then
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

if [ "$ADDED_NEW_CLIENTS" = false ] && [ "$CLIENTS_REMOVED" = false ] && [ "$CLIENTS_UPDATED" = false ]; then
  echo "No clients added, removed, or updated."
fi

echo "WireGuard setup complete using host interface: $SERVER_HOST_INTERFACE with endpoint: $SERVER_ENDPOINT:$SERVER_PORT"
