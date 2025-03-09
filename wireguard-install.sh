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

# Function to get IPv6 address of an interface
get_interface_ipv6() {
  local interface=$1
  local ip_address

  # Try to get public IPv6 address (non link-local, non ULA)
  ip_address=$(ip -6 addr show dev "$interface" | grep -v "scope link" | grep "scope global" | grep -oP '(?<=inet6\s)[0-9a-fA-F:]+' | head -n 1)

  if [ -z "$ip_address" ]; then
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

# Function to get the next available IPv6 address
get_next_available_ipv6() {
  local ipv6_base=$1
  local ipv6_prefix=$2
  local used_ipv6s=$3
  local last_octet=$4  # For dual-stack, use the same last octet as IPv4

  # Check if we should use the same octet as IPv4
  if [ -n "$last_octet" ]; then
    local candidate_ipv6="${ipv6_base}::${last_octet}"
    if ! echo "$used_ipv6s" | grep -q "$candidate_ipv6"; then
      echo "$candidate_ipv6"
      return 0
    fi
  fi

  # If no last_octet specified or the address with that octet is taken,
  # find the next available starting from 2
  for ((i=2; i<=254; i++)); do
    local candidate_ipv6="${ipv6_base}::$i"
    if ! echo "$used_ipv6s" | grep -q "$candidate_ipv6"; then
      echo "$candidate_ipv6"
      return 0
    fi
  done

  echo "Error: No available IPv6 addresses in the subnet"
  return 1
}

# Function to extract the base of an IPv6 subnet
get_ipv6_base() {
  local subnet=$1

  # Extract the network part based on the prefix length
  if [[ "$subnet" =~ ^([0-9a-fA-F:]+)/([0-9]+)$ ]]; then
    local address="${BASH_REMATCH[1]}"
    local prefix="${BASH_REMATCH[2]}"

    # For standard /64 subnet, just return the network part
    if [ "$prefix" -eq 64 ]; then
      # Remove any trailing double colon
      address=${address%::}
      echo "$address"
      return 0
    else
      echo "Error: Only /64 IPv6 prefixes are supported"
      return 1
    fi
  else
    echo "Error: Invalid IPv6 subnet format"
    return 1
  fi
}

# Function to extract the last octet from an IPv4 address
get_ipv4_last_octet() {
  local ip=$1

  if [[ "$ip" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)(/[0-9]+)?$ ]]; then
    echo "${BASH_REMATCH[2]}"
    return 0
  else
    return 1
  fi
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
SERVER_INTERNAL_IPV6=$(yq '.server.internal_ipv6_subnet' "$CONFIG_FILE")
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

# Check for IPv6 availability
SERVER_IPV6_AVAILABLE=false
SERVER_IPV6_ENDPOINT=""
if [ "$SERVER_INTERNAL_IPV6" != "null" ] && [ -n "$SERVER_INTERNAL_IPV6" ]; then
  # Try to get the IPv6 address of the host interface
  SERVER_IPV6_ENDPOINT=$(get_interface_ipv6 "$SERVER_HOST_INTERFACE")
  if [ $? -eq 0 ] && [ -n "$SERVER_IPV6_ENDPOINT" ]; then
    SERVER_IPV6_AVAILABLE=true
    echo "IPv6 support enabled. Server IPv6: $SERVER_IPV6_ENDPOINT"

    # Parse the IPv6 subnet base
    IPV6_NETWORK_BASE=$(get_ipv6_base "$SERVER_INTERNAL_IPV6")
    if [ $? -ne 0 ]; then
      echo "$IPV6_NETWORK_BASE" # This contains the error message
      exit 1
    fi
    IPV6_NETWORK_PREFIX=$(echo "$SERVER_INTERNAL_IPV6" | cut -d '/' -f 2)
    echo "IPv6 network: $SERVER_INTERNAL_IPV6 (Base: $IPV6_NETWORK_BASE, Prefix: $IPV6_NETWORK_PREFIX)"
  else
    echo "Warning: IPv6 subnet specified in config but no public IPv6 address found on interface $SERVER_HOST_INTERFACE."
    echo "IPv6 support will be disabled."
  fi
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

# Collect all used IPv6 addresses if IPv6 is available
USED_IPV6S=""
if [ "$SERVER_IPV6_AVAILABLE" = true ]; then
  # Extract the last part of the server IPv6 (usually 1)
  SERVER_IPV6="${IPV6_NETWORK_BASE}::1"
  USED_IPV6S="$SERVER_IPV6"
fi

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

  # Get any existing IPv6 addresses
  if [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    CLIENT_IPV6=$(yq ".clients[$i].internal_ipv6" "$CONFIG_FILE")
    if [ "$CLIENT_IPV6" != "null" ] && [ -n "$CLIENT_IPV6" ]; then
      # Strip the CIDR notation if present
      CLIENT_IPV6=${CLIENT_IPV6%/*}
      USED_IPV6S="$USED_IPV6S
$CLIENT_IPV6"
    fi
  fi
done

# Collect IPs from existing WireGuard config if it exists
if [ -f "$SERVER_CONFIG" ]; then
  while read -r line; do
    if [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
      ips="${BASH_REMATCH[1]}"
      # Split by comma and process each IP
      IFS=',' read -ra IP_ARRAY <<< "$ips"
      for ip in "${IP_ARRAY[@]}"; do
        ip=$(echo "$ip" | xargs)  # Trim whitespace
        # Check if it's an IPv4 address
        if [[ "$ip" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(/[0-9]+)?$ ]]; then
          # Strip the CIDR notation if present
          ip=${ip%/*}
          USED_IPS="$USED_IPS
$ip"
        # Check if it's an IPv6 address
        elif [[ "$ip" =~ ^([0-9a-fA-F:]+)(/[0-9]+)?$ ]] && [ "$SERVER_IPV6_AVAILABLE" = true ]; then
          # Strip the CIDR notation if present
          ip=${ip%/*}
          USED_IPV6S="$USED_IPV6S
$ip"
        fi
      done
    fi
  done < "$SERVER_CONFIG"
fi

echo "Used IPs in network: $(echo "$USED_IPS" | tr '\n' ' ')"
if [ "$SERVER_IPV6_AVAILABLE" = true ]; then
  echo "Used IPv6 addresses: $(echo "$USED_IPV6S" | tr '\n' ' ')"
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
EOF

  # Add IPv6 address if available
  if [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    echo "Address = $SERVER_INTERNAL_IP, ${IPV6_NETWORK_BASE}::1/$IPV6_NETWORK_PREFIX" > "$SERVER_CONFIG.tmp"
    cat "$SERVER_CONFIG" | grep -v "^Address" >> "$SERVER_CONFIG.tmp"
    mv "$SERVER_CONFIG.tmp" "$SERVER_CONFIG"
  fi

  # Add port
  echo "ListenPort = $SERVER_PORT" >> "$SERVER_CONFIG"

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

  # Check if the server config already has IPv6 enabled
  if grep -q "Address.*::" "$SERVER_CONFIG" && [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    echo "Existing server configuration has IPv6 enabled."
  elif [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    echo "Adding IPv6 to existing server configuration."
    # Add IPv6 address to the server configuration
    SERVER_IPV6_ADDRESS="${IPV6_NETWORK_BASE}::1/${IPV6_NETWORK_PREFIX}"
    EXISTING_ADDRESS=$(grep "^Address" "$SERVER_CONFIG" | cut -d "=" -f 2 | xargs)
    NEW_ADDRESS="Address = $EXISTING_ADDRESS, $SERVER_IPV6_ADDRESS"
    sed -i "s|^Address.*|$NEW_ADDRESS|" "$SERVER_CONFIG"
  fi
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
  YAML_IPV6=$(yq ".clients[$client_index].internal_ipv6" "$CONFIG_FILE")
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
  CURRENT_IP=$(grep "^Address = " "$CLIENT_CONFIG" | cut -d ' ' -f 3- | grep -o "[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/[0-9]\+" | head -1)
  CURRENT_IPV6=$(grep "^Address = " "$CLIENT_CONFIG" | grep -o "[0-9a-fA-F:]\+/[0-9]\+")
  CURRENT_DNS=$(grep "^DNS = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_ALLOWED_IPS=$(grep "^AllowedIPs = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_KEEPALIVE=$(grep "^PersistentKeepalive = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_MTU=$(grep "^MTU = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)

  # Strip CIDR notation for comparison if present
  CURRENT_IP_STRIPPED=${CURRENT_IP%/*}
  YAML_IP_STRIPPED=${YAML_IP%/*}
  CURRENT_IPV6_STRIPPED=${CURRENT_IPV6%/*}
  YAML_IPV6_STRIPPED=${YAML_IPV6%/*}

  # Check for changes
  CHANGES=""

  # Special handling for null values from YAML
  [ "$YAML_MTU" = "null" ] && YAML_MTU=$DEFAULT_MTU

  # Compare values (handling null/unset cases)
  if [ "$YAML_IP" != "null" ] && [ "$YAML_IP_STRIPPED" != "$CURRENT_IP_STRIPPED" ]; then
    CHANGES="${CHANGES}IP ($CURRENT_IP → $YAML_IP), "
  fi

  # Handle IPv6 changes
  if [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    if [ "$YAML_IPV6" != "null" ] && [ "$YAML_IPV6_STRIPPED" != "$CURRENT_IPV6_STRIPPED" ]; then
      CHANGES="${CHANGES}IPv6 ($CURRENT_IPV6 → $YAML_IPV6), "
    elif [ -z "$CURRENT_IPV6" ] && [ "$YAML_IPV6" = "null" ]; then
      # If current config doesn't have IPv6 but server supports it, we'll add it
      # Get the IPv4 last octet to match with IPv6
      if [[ "$YAML_IP" =~ \.([0-9]+)(/[0-9]+)?$ ]]; then
        IPV4_LAST_OCTET="${BASH_REMATCH[1]}"
        YAML_IPV6="${IPV6_NETWORK_BASE}::$IPV4_LAST_OCTET/${IPV6_NETWORK_PREFIX}"
        CHANGES="${CHANGES}IPv6 (added: $YAML_IPV6), "
      fi
    fi
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
EOF

  # Add IPv4 and IPv6 addresses
  if [ "$SERVER_IPV6_AVAILABLE" = true ] && { [ "$YAML_IPV6" != "null" ] || [[ "$YAML_IP" =~ \.([0-9]+)(/[0-9]+)?$ ]]; }; then
    # If IPv6 is specified or we can derive it from IPv4
    if [ "$YAML_IPV6" != "null" ]; then
      IPV6_ADDRESS="$YAML_IPV6"
    else
      IPV4_LAST_OCTET="${BASH_REMATCH[1]}"
      IPV6_ADDRESS="${IPV6_NETWORK_BASE}::$IPV4_LAST_OCTET/${IPV6_NETWORK_PREFIX}"
    fi
    echo "Address = $YAML_IP, $IPV6_ADDRESS" >> "$CLIENT_CONFIG"
  else
    echo "Address = $YAML_IP" >> "$CLIENT_CONFIG"
  fi

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
EOF

  # Set AllowedIPs - If not explicitly specified in YAML, use default of 0.0.0.0/0 (all IPv4)
  # and ::/0 (all IPv6) if IPv6 is available
  if [ "$YAML_ALLOWED_IPS" != "null" ]; then
    echo "AllowedIPs = $YAML_ALLOWED_IPS" >> "$CLIENT_CONFIG"
  elif [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    echo "AllowedIPs = 0.0.0.0/0, ::/0" >> "$CLIENT_CONFIG"
  else
    echo "AllowedIPs = 0.0.0.0/0" >> "$CLIENT_CONFIG"
  fi

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
        # Parse existing allowed IPs
        allowed_ips="${BASH_REMATCH[1]}"

        # Split by comma to handle multiple IPs
        IFS=',' read -ra IP_ARRAY <<< "$allowed_ips"
        new_allowed_ips=""

        # Replace the IPv4 address, keep other addresses
        for ip in "${IP_ARRAY[@]}"; do
          ip=$(echo "$ip" | xargs)  # Trim whitespace

          # If it's an IPv4 address, replace it
          if [[ "$ip" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(/[0-9]+)?$ ]]; then
            new_allowed_ips="${new_allowed_ips}${YAML_IP}, "
          # If it's IPv6, keep it
          elif [[ "$ip" =~ ^([0-9a-fA-F:]+)(/[0-9]+)?$ ]]; then
            new_allowed_ips="${new_allowed_ips}${ip}, "
          fi
        done

        # Also handle the case where there was no IPv6 but we need to add it
        if [ "$SERVER_IPV6_AVAILABLE" = true ] && [ "$YAML_IPV6" != "null" ] &&
           ! echo "$allowed_ips" | grep -q ":"; then
          new_allowed_ips="${new_allowed_ips}${YAML_IPV6}, "
        fi

        # Remove trailing comma and space
        new_allowed_ips=${new_allowed_ips%, }

        # If we didn't find any IPs to keep or replace, use the new IP
        if [ -z "$new_allowed_ips" ]; then
          new_allowed_ips="$YAML_IP"
        fi

        echo "AllowedIPs = $new_allowed_ips" >> "$TEMP_SERVER_CONFIG"
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
UPDATED_IPV6S=()

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
  CLIENT_IPV6=$(yq ".clients[$i].internal_ipv6" "$CONFIG_FILE")
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
    CLIENT_IP="${NEW_IP}/${NETWORK_PREFIX}"
    echo "Assigned IP address $CLIENT_IP to client $CLIENT_NAME"

    # Add to used IPs
    USED_IPS="$USED_IPS
$NEW_IP"

    # Track for YAML update
    UPDATED_CLIENTS+=($i)
    UPDATED_IPS+=("$CLIENT_IP")
    YAML_MODIFIED=true

    # Extract the last octet for IPv6 matching
    IPV4_LAST_OCTET=$(get_ipv4_last_octet "$NEW_IP")
  else
    # Extract the last octet for IPv6 matching
    IPV4_LAST_OCTET=$(get_ipv4_last_octet "$CLIENT_IP")
  fi

  # Assign IPv6 if not specified but server supports it
  if [ "$SERVER_IPV6_AVAILABLE" = true ] && { [ "$CLIENT_IPV6" == "null" ] || [ -z "$CLIENT_IPV6" ]; }; then
    if [ -n "$IPV4_LAST_OCTET" ]; then
      # Try to use matching IPv6 with same last octet as IPv4
      NEW_IPV6=$(get_next_available_ipv6 "$IPV6_NETWORK_BASE" "$IPV6_NETWORK_PREFIX" "$USED_IPV6S" "$IPV4_LAST_OCTET")
    else
      # Fall back to any available IPv6
      NEW_IPV6=$(get_next_available_ipv6 "$IPV6_NETWORK_BASE" "$IPV6_NETWORK_PREFIX" "$USED_IPV6S")
    fi

    if [ $? -ne 0 ]; then
      echo "$NEW_IPV6"  # This contains the error message
      exit 1
    fi

    # Add CIDR notation for client
    CLIENT_IPV6="${NEW_IPV6}/${IPV6_NETWORK_PREFIX}"
    echo "Assigned IPv6 address $CLIENT_IPV6 to client $CLIENT_NAME"

    # Add to used IPv6s
    USED_IPV6S="$USED_IPV6S
$NEW_IPV6"

    # Track for YAML update
    if [[ " ${UPDATED_CLIENTS[@]} " =~ " $i " ]]; then
      # Client already in the update list, just add IPv6
      for idx in "${!UPDATED_CLIENTS[@]}"; do
        if [ "${UPDATED_CLIENTS[$idx]}" -eq "$i" ]; then
          UPDATED_IPV6S[$idx]="$CLIENT_IPV6"
          break
        fi
      done
    else
      UPDATED_CLIENTS+=($i)
      UPDATED_IPS+=("$CLIENT_IP")
      UPDATED_IPV6S+=("$CLIENT_IPV6")
    fi
    YAML_MODIFIED=true
  fi

  # Generate client keys
  generate_keys "$CLIENT_NAME"
  CLIENT_PRIVATE_KEY=$(cat "${KEYS_DIR}/${CLIENT_NAME}.private")
  CLIENT_PUBLIC_KEY=$(cat "${KEYS_DIR}/${CLIENT_NAME}.public")

  # Determine the AllowedIPs for server (client's tunnel IP)
  SERVER_ALLOWED_IPS="$CLIENT_IP"
  if [ "$SERVER_IPV6_AVAILABLE" = true ] && [ "$CLIENT_IPV6" != "null" ] && [ -n "$CLIENT_IPV6" ]; then
    SERVER_ALLOWED_IPS="$SERVER_ALLOWED_IPS, $CLIENT_IPV6"
  fi

  # Add client to server config
  cat >> "$SERVER_CONFIG" << EOF

[Peer]
# $CLIENT_NAME
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $SERVER_ALLOWED_IPS
EOF

  # Create client config
  CLIENT_CONFIG="${CLIENT_OUTPUT_DIR}/${CLIENT_NAME}.conf"
  cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
EOF

  # Add IPv4 and IPv6 addresses
  if [ "$SERVER_IPV6_AVAILABLE" = true ] && [ "$CLIENT_IPV6" != "null" ] && [ -n "$CLIENT_IPV6" ]; then
    echo "Address = $CLIENT_IP, $CLIENT_IPV6" >> "$CLIENT_CONFIG"
  else
    echo "Address = $CLIENT_IP" >> "$CLIENT_CONFIG"
  fi

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
EOF

  # Set AllowedIPs - If not explicitly specified in YAML, use default of 0.0.0.0/0 (all IPv4)
  # and ::/0 (all IPv6) if IPv6 is available
  if [ "$CLIENT_ALLOWED_IPS" != "null" ]; then
    echo "AllowedIPs = $CLIENT_ALLOWED_IPS" >> "$CLIENT_CONFIG"
  elif [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    echo "AllowedIPs = 0.0.0.0/0, ::/0" >> "$CLIENT_CONFIG"
  else
    echo "AllowedIPs = 0.0.0.0/0" >> "$CLIENT_CONFIG"
  fi

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
    client_ipv6=${UPDATED_IPV6S[$i]}

    # Use yq to update the YAML file
    yq -i ".clients[$client_index].internal_ip = \"$client_ip\"" "$CONFIG_FILE"

    # Update IPv6 if available
    if [ -n "$client_ipv6" ]; then
      yq -i ".clients[$client_index].internal_ipv6 = \"$client_ipv6\"" "$CONFIG_FILE"
    fi
  done

  echo "YAML file updated."
fi

# Only restart services if we made changes
if [ "$SERVER_EXISTS" = false ] || [ "$ADDED_NEW_CLIENTS" = true ] || [ "$CLIENTS_REMOVED" = true ] || [ "$CLIENTS_UPDATED" = true ]; then
  # Enable IP forwarding
  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf

  # Enable IPv6 forwarding if IPv6 is available
  if [ "$SERVER_IPV6_AVAILABLE" = true ]; then
    echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
  fi

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

if [ "$SERVER_IPV6_AVAILABLE" = true ]; then
  echo "WireGuard setup complete using host interface: $SERVER_HOST_INTERFACE with endpoint: $SERVER_ENDPOINT:$SERVER_PORT (IPv6: $SERVER_IPV6_ENDPOINT)"
else
  echo "WireGuard setup complete using host interface: $SERVER_HOST_INTERFACE with endpoint: $SERVER_ENDPOINT:$SERVER_PORT (IPv6 disabled)"
fi
