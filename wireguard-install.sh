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

# Function to get IPv4 address of an interface
get_interface_ip() {
  local interface=$1
  local ip_address
  ip_address=$(ip -4 addr show dev "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1)
  if [ -z "$ip_address" ]; then
    echo "Error: No IPv4 address found for interface $interface"
    return 1
  fi
  echo "$ip_address"
}

# Function to calculate next available IPv4 address in range
get_next_available_ip() {
  local network_base=$1
  local network_prefix=$2
  local used_ips=$3
  IFS='.' read -r -a octets <<< "$network_base"
  local start_ip="${octets[0]}.${octets[1]}.${octets[2]}.2"  # start at .2
  local end_num=254
  if [ "$network_prefix" -lt 24 ]; then
    end_num=254
  fi
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

# Function to calculate next available IPv6 address in range
# Assumes the server IPv6 is in the format "prefix::host/CIDR" (e.g. fddd:2c4:2c4:2c4::1/64)
get_next_available_ipv6() {
  local ipv6_prefix=$1
  local used_ipv6=$2
  # Loop from 2 up to 255 (sufficient for a few clients)
  for ((i=2; i<256; i++)); do
    candidate=$(printf "%s%x" "$ipv6_prefix" "$i")
    if ! echo "$used_ipv6" | grep -qw "$candidate"; then
      echo "$candidate"
      return 0
    fi
  done
  echo "Error: No available IPv6 addresses in the subnet"
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
    return 0
  fi
  return 1
}

# Generate server keys if needed
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
SERVER_INTERNAL_IPV6=$(yq '.server.internal_ipv6' "$CONFIG_FILE" | tr -d '"')
SERVER_INTERFACE=$(yq '.server.interface_name' "$CONFIG_FILE" || echo "wg0" | tr -d '"')
SERVER_HOST_INTERFACE=$(yq '.server.host_interface' "$CONFIG_FILE" | tr -d '"')
SERVER_MTU=$(yq '.server.mtu' "$CONFIG_FILE")
SERVER_POST_UP=$(yq '.server.post_up' "$CONFIG_FILE")
SERVER_POST_DOWN=$(yq '.server.post_down' "$CONFIG_FILE")

# Set default port if not specified
if [ "$SERVER_PORT" == "null" ] || [ -z "$SERVER_PORT" ]; then
  SERVER_PORT=$DEFAULT_PORT
  echo "No port specified, using default: $SERVER_PORT"
fi

# Determine host interface
if [ "$SERVER_HOST_INTERFACE" == "null" ] || [ -z "$SERVER_HOST_INTERFACE" ]; then
  SERVER_HOST_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n 1)
  echo "No host interface specified, using: $SERVER_HOST_INTERFACE"
else
  if ! ip link show dev "$SERVER_HOST_INTERFACE" &>/dev/null; then
    echo "Error: Specified host interface '$SERVER_HOST_INTERFACE' not found."
    echo "Available interfaces:"
    ip -o link show | awk -F': ' '{print $2}'
    exit 1
  fi
fi

# Determine endpoint IP address
if [ "$SERVER_ENDPOINT" == "null" ] || [ -z "$SERVER_ENDPOINT" ] || [ "$SERVER_ENDPOINT" == "auto" ]; then
  SERVER_ENDPOINT=$(get_interface_ip "$SERVER_HOST_INTERFACE")
  if [ $? -ne 0 ]; then
    echo "$SERVER_ENDPOINT"
    exit 1
  fi
  echo "Automatically detected endpoint IP: $SERVER_ENDPOINT"
fi

# Parse server internal IPv4 to get network
if ! [[ "$SERVER_INTERNAL_IP" =~ ^([0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)/([0-9]+)$ ]]; then
  echo "Error: Invalid server internal IP format. Expected format: x.x.x.x/y"
  exit 1
fi
NETWORK_BASE="${BASH_REMATCH[1]}"
SERVER_IP_LAST_OCTET="${BASH_REMATCH[2]}"
NETWORK_PREFIX="${BASH_REMATCH[3]}"
NETWORK="${NETWORK_BASE}.0/${NETWORK_PREFIX}"
echo "Server IPv4 network: $NETWORK (Base: $NETWORK_BASE, Prefix: $NETWORK_PREFIX)"

# Parse server internal IPv6 (if provided)
if [ "$SERVER_INTERNAL_IPV6" != "null" ] && [ -n "$SERVER_INTERNAL_IPV6" ]; then
  # Expect format like fddd:2c4:2c4:2c4::1/64
  if [[ "$SERVER_INTERNAL_IPV6" =~ ^(.+::)[0-9a-fA-F]+\/([0-9]+)$ ]]; then
    IPV6_PREFIX="${BASH_REMATCH[1]}"
    IPV6_CIDR="${BASH_REMATCH[2]}"
  else
    echo "Error: Invalid server internal IPv6 format. Expected format: x:x:x:x::x/y"
    exit 1
  fi
  echo "Server IPv6: $SERVER_INTERNAL_IPV6 (Prefix: $IPV6_PREFIX, CIDR: /$IPV6_CIDR)"
fi

# Collect used IPv4 addresses
USED_IPS="$NETWORK_BASE.$SERVER_IP_LAST_OCTET"
# Collect used IPv6 addresses (if IPv6 enabled)
USED_IPV6=""
if [ "$SERVER_INTERNAL_IPV6" != "null" ] && [ -n "$SERVER_INTERNAL_IPV6" ]; then
  SERVER_IPV6_ADDRESS=${SERVER_INTERNAL_IPV6%%/*}
  USED_IPV6="$SERVER_IPV6_ADDRESS"
fi

# Add already defined client addresses from YAML to used lists
CLIENT_COUNT=$(yq '.clients | length' "$CONFIG_FILE")
for (( i=0; i<$CLIENT_COUNT; i++ )); do
  CLIENT_IP=$(yq ".clients[$i].internal_ip" "$CONFIG_FILE")
  if [ "$CLIENT_IP" != "null" ] && [ -n "$CLIENT_IP" ]; then
    CLIENT_IP=${CLIENT_IP%/*}
    USED_IPS="$USED_IPS
$CLIENT_IP"
  fi
  if [ "$SERVER_INTERNAL_IPV6" != "null" ] && [ -n "$SERVER_INTERNAL_IPV6" ]; then
    CLIENT_IPV6=$(yq ".clients[$i].internal_ipv6" "$CONFIG_FILE")
    if [ "$CLIENT_IPV6" != "null" ] && [ -n "$CLIENT_IPV6" ]; then
      CLIENT_IPV6=${CLIENT_IPV6%%/*}
      USED_IPV6="$USED_IPV6
$CLIENT_IPV6"
    fi
  fi
done

# Also collect addresses already in the server config
if [ -f "$SERVER_CONFIG" ]; then
  while read -r line; do
    if [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
      ip="${BASH_REMATCH[1]}"
      # For IPv4
      if echo "$ip" | grep -qE '^[0-9]+\.'; then
        ip=${ip%%/*}
        USED_IPS="$USED_IPS
$ip"
      fi
      # For IPv6
      if echo "$ip" | grep -q ":"; then
        ip=${ip%%/*}
        USED_IPV6="$USED_IPV6
$ip"
      fi
    fi
  done < "$SERVER_CONFIG"
fi

echo "Used IPv4 addresses: $(echo "$USED_IPS" | tr '\n' ' ')"
if [ -n "$USED_IPV6" ]; then
  echo "Used IPv6 addresses: $(echo "$USED_IPV6" | tr '\n' ' ')"
fi

# Default PostUp/PostDown rules (including ip6tables)
DEFAULT_POST_UP="iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o %h -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o %h -j MASQUERADE"
DEFAULT_POST_DOWN="iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o %h -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o %h -j MASQUERADE"

# Create server config if not exists
if [ "$SERVER_EXISTS" = false ]; then
  echo "Creating new server configuration..."
  cat > "$SERVER_CONFIG" << EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_INTERNAL_IP$( [ "$SERVER_INTERNAL_IPV6" != "null" ] && echo ", $SERVER_INTERNAL_IPV6" )
ListenPort = $SERVER_PORT
EOF
  if [ "$SERVER_MTU" != "null" ]; then
    echo "MTU = $SERVER_MTU" >> "$SERVER_CONFIG"
  else
    echo "MTU = $DEFAULT_MTU" >> "$SERVER_CONFIG"
  fi
  if [ "$SERVER_POST_UP" != "null" ]; then
    PROCESSED_POST_UP="${SERVER_POST_UP//%h/$SERVER_HOST_INTERFACE}"
    echo "PostUp = $PROCESSED_POST_UP" >> "$SERVER_CONFIG"
  else
    PROCESSED_POST_UP="${DEFAULT_POST_UP//%h/$SERVER_HOST_INTERFACE}"
    echo "PostUp = $PROCESSED_POST_UP" >> "$SERVER_CONFIG"
  fi
  if [ "$SERVER_POST_DOWN" != "null" ]; then
    PROCESSED_POST_DOWN="${SERVER_POST_DOWN//%h/$SERVER_HOST_INTERFACE}"
    echo "PostDown = $PROCESSED_POST_DOWN" >> "$SERVER_CONFIG"
  else
    PROCESSED_POST_DOWN="${DEFAULT_POST_DOWN//%h/$SERVER_HOST_INTERFACE}"
    echo "PostDown = $PROCESSED_POST_DOWN" >> "$SERVER_CONFIG"
  fi
  chmod 600 "$SERVER_CONFIG"
else
  echo "Using existing server configuration."
  cp "$SERVER_CONFIG" "${SERVER_CONFIG}.bak"
fi

# Get list of YAML client names for comparison
YAML_CLIENTS=()
for (( i=0; i<$CLIENT_COUNT; i++ )); do
  client_name=$(yq ".clients[$i].name" "$CONFIG_FILE")
  YAML_CLIENTS+=("$client_name")
done

# Get list of existing clients (by parsing server config comments)
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

# Identify clients to remove (present in server config but not in YAML)
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

if [ ${#CLIENTS_TO_REMOVE[@]} -gt 0 ]; then
  echo "Removing ${#CLIENTS_TO_REMOVE[@]} clients that are no longer in YAML..."
  TEMP_SERVER_CONFIG=$(mktemp)
  in_peer_to_remove=false
  client_name_to_remove=""
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" == "[Peer]" ]]; then
      echo "$line" >> "$TEMP_SERVER_CONFIG"
      read -r next_line
      if [[ "$next_line" =~ ^#\ (.+)$ ]]; then
        client_name="${BASH_REMATCH[1]}"
        for remove_name in "${CLIENTS_TO_REMOVE[@]}"; do
          if [ "$client_name" = "$remove_name" ]; then
            in_peer_to_remove=true
            client_name_to_remove="$client_name"
            echo "Found client to remove: $client_name"
            break
          fi
        done
        if [ "$in_peer_to_remove" = false ]; then
          echo "$next_line" >> "$TEMP_SERVER_CONFIG"
        fi
      else
        echo "$next_line" >> "$TEMP_SERVER_CONFIG"
      fi
    elif [ "$in_peer_to_remove" = true ]; then
      if [[ "$line" == "" ]] || [[ "$line" == "[Interface]" ]] || [[ "$line" == "[Peer]" ]]; then
        in_peer_to_remove=false
        echo "Removed client: $client_name_to_remove"
        if [[ "$line" == "[Interface]" ]] || [[ "$line" == "[Peer]" ]]; then
          echo "$line" >> "$TEMP_SERVER_CONFIG"
        elif [[ "$line" == "" ]]; then
          echo "" >> "$TEMP_SERVER_CONFIG"
        fi
      fi
    else
      echo "$line" >> "$TEMP_SERVER_CONFIG"
    fi
  done < "$SERVER_CONFIG"
  mv "$TEMP_SERVER_CONFIG" "$SERVER_CONFIG"
  chmod 600 "$SERVER_CONFIG"
  for client_name in "${CLIENTS_TO_REMOVE[@]}"; do
    client_conf="${CLIENT_OUTPUT_DIR}/${client_name}.conf"
    client_png="${CLIENT_OUTPUT_DIR}/${client_name}.png"
    [ -f "$client_conf" ] && rm -f "$client_conf" && echo "Removed client config file: $client_conf"
    [ -f "$client_png" ] && rm -f "$client_png" && echo "Removed client QR code: $client_png"
  done
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
for client_name in "${EXISTING_CLIENTS[@]}"; do
  client_index=-1
  for ((i=0; i<${#YAML_CLIENTS[@]}; i++)); do
    if [ "${YAML_CLIENTS[i]}" = "$client_name" ]; then
      client_index=$i
      break
    fi
  done
  if [ $client_index -eq -1 ]; then
    continue
  fi

  YAML_IP=$(yq ".clients[$client_index].internal_ip" "$CONFIG_FILE")
  YAML_IPV6=$(yq ".clients[$client_index].internal_ipv6" "$CONFIG_FILE")
  YAML_DNS=$(yq ".clients[$client_index].dns" "$CONFIG_FILE")
  YAML_ALLOWED_IPS=$(yq ".clients[$client_index].allowed_ips" "$CONFIG_FILE")
  YAML_KEEPALIVE=$(yq ".clients[$client_index].persistent_keepalive" "$CONFIG_FILE")
  YAML_MTU=$(yq ".clients[$client_index].mtu" "$CONFIG_FILE")

  CLIENT_CONFIG="${CLIENT_OUTPUT_DIR}/${client_name}.conf"
  if [ ! -f "$CLIENT_CONFIG" ]; then
    echo "Warning: Config file for existing client '$client_name' not found, skipping update."
    continue
  fi

  # Extract current settings
  CURRENT_ADDRESS=$(grep "^Address = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_IP=$(echo "$CURRENT_ADDRESS" | cut -d ',' -f 1 | xargs)
  CURRENT_IPV6=$(echo "$CURRENT_ADDRESS" | cut -d ',' -f 2 | xargs)
  CURRENT_DNS=$(grep "^DNS = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_ALLOWED_IPS=$(grep "^AllowedIPs = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_KEEPALIVE=$(grep "^PersistentKeepalive = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
  CURRENT_MTU=$(grep "^MTU = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)

  CURRENT_IP_STRIPPED=${CURRENT_IP%/*}
  YAML_IP_STRIPPED=${YAML_IP%/*}

  CHANGES=""
  [ "$YAML_MTU" = "null" ] && YAML_MTU=$DEFAULT_MTU

  if [ "$YAML_IP" != "null" ] && [ "$YAML_IP_STRIPPED" != "$CURRENT_IP_STRIPPED" ]; then
    CHANGES="${CHANGES}IP ($CURRENT_IP → $YAML_IP), "
  fi
  if [ "$SERVER_INTERNAL_IPV6" != "null" ] && [ "$YAML_IPV6" != "null" ]; then
    if [ "$YAML_IPV6" != "$CURRENT_IPV6" ]; then
      CHANGES="${CHANGES}IPv6 ($CURRENT_IPV6 → $YAML_IPV6), "
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

  if [ -z "$CHANGES" ]; then
    continue
  fi

  echo "Updating client '$client_name' with changes: ${CHANGES%, }"
  CLIENTS_UPDATED=true
  UPDATED_CLIENT_NAMES+=("$client_name")
  CLIENT_CHANGES+=("${CHANGES%, }")
  cp "$CLIENT_CONFIG" "${CLIENT_CONFIG}.bak"

  # For client config, convert auto-assigned IPv6 (/128) to /64 for interface address
  client_ipv6_client=""
  if [ "$YAML_IPV6" != "null" ] && [ -n "$YAML_IPV6" ]; then
    if [[ "$YAML_IPV6" == */128 ]]; then
      client_ipv6_client="${YAML_IPV6%/*}/64"
    else
      client_ipv6_client="$YAML_IPV6"
    fi
  fi

  cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $(grep "^PrivateKey = " "$CLIENT_CONFIG" | cut -d ' ' -f 3)
Address = $YAML_IP$( [ "$client_ipv6_client" != "" ] && echo ", $client_ipv6_client" )
EOF
  if [ "$YAML_MTU" != "null" ]; then
    echo "MTU = $YAML_MTU" >> "$CLIENT_CONFIG"
  else
    echo "MTU = $DEFAULT_MTU" >> "$CLIENT_CONFIG"
  fi
  if [ "$YAML_DNS" != "null" ]; then
    echo "DNS = $YAML_DNS" >> "$CLIENT_CONFIG"
  fi
  cat >> "$CLIENT_CONFIG" << EOF

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = $YAML_IP$( [ "$YAML_IPV6" != "null" ] && echo ", $YAML_IPV6" )
EOF
  if [ "$YAML_KEEPALIVE" != "null" ]; then
    echo "PersistentKeepalive = $YAML_KEEPALIVE" >> "$CLIENT_CONFIG"
  fi

  if [ "$YAML_IP" != "null" ] && [ "$YAML_IP_STRIPPED" != "$CURRENT_IP_STRIPPED" ]; then
    TEMP_SERVER_CONFIG=$(mktemp)
    in_target_peer=false
    while IFS= read -r line || [ -n "$line" ]; do
      if [[ "$line" == "[Peer]" ]]; then
        echo "$line" >> "$TEMP_SERVER_CONFIG"
        read -r next_line
        if [[ "$next_line" =~ ^#\ (.+)$ ]]; then
          peer_name="${BASH_REMATCH[1]}"
          if [ "$peer_name" = "$client_name" ]; then
            in_target_peer=true
          else
            in_target_peer=false
          fi
        fi
        echo "$next_line" >> "$TEMP_SERVER_CONFIG"
      elif [ "$in_target_peer" = true ] && [[ "$line" =~ ^AllowedIPs\ =\ (.+)$ ]]; then
        echo "AllowedIPs = $YAML_IP$( [ "$YAML_IPV6" != "null" ] && echo ", $YAML_IPV6" )" >> "$TEMP_SERVER_CONFIG"
      else
        echo "$line" >> "$TEMP_SERVER_CONFIG"
      fi
    done < "$SERVER_CONFIG"
    mv "$TEMP_SERVER_CONFIG" "$SERVER_CONFIG"
    chmod 600 "$SERVER_CONFIG"
  fi

  qrencode -t png -o "${CLIENT_OUTPUT_DIR}/${client_name}.png" < "${CLIENT_CONFIG}"
  echo "Updated QR code saved as: ${CLIENT_OUTPUT_DIR}/${client_name}.png"
  echo "==============================================="
  echo "QR Code for updated client: $client_name"
  echo "==============================================="
  qrencode -t ansiutf8 < "${CLIENT_CONFIG}"
  echo "==============================================="
done

# Arrays to track auto-assigned addresses for YAML update
UPDATED_CLIENTS+=()        # for IPv4
UPDATED_IPS=()
UPDATED_CLIENTS_IPV6=()
UPDATED_IPV6S=()

ADDED_NEW_CLIENTS=false
for (( i=0; i<$CLIENT_COUNT; i++ )); do
  CLIENT_NAME=$(yq ".clients[$i].name" "$CONFIG_FILE")
  CLIENT_EXISTS=false
  for existing in "${EXISTING_CLIENTS[@]}"; do
    if [ "$existing" = "$CLIENT_NAME" ]; then
      CLIENT_EXISTS=true
      break
    fi
  done
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

  if [ "$CLIENT_IP" == "null" ] || [ -z "$CLIENT_IP" ]; then
    NEW_IP=$(get_next_available_ip "$NETWORK_BASE" "$NETWORK_PREFIX" "$USED_IPS")
    if [ $? -ne 0 ]; then
      echo "$NEW_IP"
      exit 1
    fi
    CLIENT_IP="${NEW_IP}/32"
    echo "Assigned IPv4 address $CLIENT_IP to client $CLIENT_NAME"
    USED_IPS="$USED_IPS
$NEW_IP"
    UPDATED_CLIENTS+=($i)
    UPDATED_IPS+=("$CLIENT_IP")
    YAML_MODIFIED=true
  fi

  if [ "$SERVER_INTERNAL_IPV6" != "null" ] && [ -n "$SERVER_INTERNAL_IPV6" ]; then
    if [ "$CLIENT_IPV6" == "null" ] || [ -z "$CLIENT_IPV6" ]; then
      NEW_IPV6=$(get_next_available_ipv6 "$IPV6_PREFIX" "$USED_IPV6")
      if [ $? -ne 0 ]; then
        echo "$NEW_IPV6"
        exit 1
      fi
      # Use /128 for server AllowedIPs; client interface will later use /64
      CLIENT_IPV6="$NEW_IPV6/128"
      echo "Assigned IPv6 address $CLIENT_IPV6 to client $CLIENT_NAME"
      USED_IPV6="$USED_IPV6
$NEW_IPV6"
      UPDATED_CLIENTS_IPV6+=($i)
      UPDATED_IPV6S+=("$CLIENT_IPV6")
      YAML_MODIFIED=true
    fi
  fi

  generate_keys "$CLIENT_NAME"
  CLIENT_PRIVATE_KEY=$(cat "${KEYS_DIR}/${CLIENT_NAME}.private")
  CLIENT_PUBLIC_KEY=$(cat "${KEYS_DIR}/${CLIENT_NAME}.public")

  cat >> "$SERVER_CONFIG" << EOF

[Peer]
# $CLIENT_NAME
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP$( [ "$CLIENT_IPV6" != "null" ] && echo ", $CLIENT_IPV6" )
EOF

  CLIENT_CONFIG="${CLIENT_OUTPUT_DIR}/${CLIENT_NAME}.conf"
  client_ipv6_client=""
  if [ "$CLIENT_IPV6" != "null" ] && [ -n "$CLIENT_IPV6" ]; then
    if [[ "$CLIENT_IPV6" == */128 ]]; then
      client_ipv6_client="${CLIENT_IPV6%/*}/64"
    else
      client_ipv6_client="$CLIENT_IPV6"
    fi
  fi

  cat > "$CLIENT_CONFIG" << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP$( [ "$client_ipv6_client" != "" ] && echo ", $client_ipv6_client" )
EOF
  if [ "$CLIENT_MTU" != "null" ]; then
    echo "MTU = $CLIENT_MTU" >> "$CLIENT_CONFIG"
  else
    echo "MTU = $DEFAULT_MTU" >> "$CLIENT_CONFIG"
  fi
  if [ "$CLIENT_DNS" != "null" ]; then
    echo "DNS = $CLIENT_DNS" >> "$CLIENT_CONFIG"
  fi
  cat >> "$CLIENT_CONFIG" << EOF

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = ${SERVER_ENDPOINT}:${SERVER_PORT}
AllowedIPs = $CLIENT_IP$( [ "$CLIENT_IPV6" != "null" ] && echo ", $CLIENT_IPV6" )
EOF
  if [ "$CLIENT_KEEPALIVE" != "null" ]; then
    echo "PersistentKeepalive = $CLIENT_KEEPALIVE" >> "$CLIENT_CONFIG"
  fi
  echo "==============================================="
  echo "QR Code for client: $CLIENT_NAME"
  echo "==============================================="
  qrencode -t ansiutf8 < "${CLIENT_CONFIG}"
  echo "==============================================="
  qrencode -t png -o "${CLIENT_OUTPUT_DIR}/${CLIENT_NAME}.png" < "${CLIENT_CONFIG}"
  echo "QR code image saved as: ${CLIENT_OUTPUT_DIR}/${CLIENT_NAME}.png"
  echo ""
done

# Update YAML file with auto-assigned addresses (IPv4 and IPv6)
if [ "$YAML_MODIFIED" = true ]; then
  echo "Updating YAML file with assigned IP addresses..."
  cp "$CONFIG_FILE" "${CONFIG_FILE}.bak"
  for (( i=0; i<${#UPDATED_CLIENTS[@]}; i++ )); do
    client_index=${UPDATED_CLIENTS[$i]}
    client_ip=${UPDATED_IPS[$i]}
    yq -i ".clients[$client_index].internal_ip = \"$client_ip\"" "$CONFIG_FILE"
  done
  for (( i=0; i<${#UPDATED_CLIENTS_IPV6[@]}; i++ )); do
    client_index=${UPDATED_CLIENTS_IPV6[$i]}
    client_ipv6=${UPDATED_IPV6S[$i]}
    yq -i ".clients[$client_index].internal_ipv6 = \"$client_ipv6\"" "$CONFIG_FILE"
  done
  echo "YAML file updated."
fi

# Restart services if changes were made
if [ "$SERVER_EXISTS" = false ] || [ "$ADDED_NEW_CLIENTS" = true ] || [ "$CLIENTS_REMOVED" = true ] || [ "$CLIENTS_UPDATED" = true ]; then
  echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-wireguard.conf
  echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/99-wireguard.conf
  sysctl -p /etc/sysctl.d/99-wireguard.conf >/dev/null 2>&1
  systemctl enable wg-quick@wg0 >/dev/null 2>&1
  systemctl restart wg-quick@wg0 >/dev/null 2>&1
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
