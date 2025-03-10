#!/bin/bash
#
# WireGuard Installer with YAML-based Server and Client Configuration
#
# This script is a modified version of the original installer where
# only the server and client parts are defined via YAML (/etc/wireguard/config.yaml).
# The rest of the logic (OS detection, firewall/iptables rules, etc.) remains.
#
# Make sure yq is installed for YAML parsing.

# --- Preliminary Checks ---

# Ensure the script is run with bash (not dash)
if readlink /proc/$$/exe | grep -q "dash"; then
  echo 'This installer needs to be run with "bash", not "sh".'
  exit 1
fi

# Discard any extraneous input (helpful when running one-liners)
read -N 999999 -t 0.001

# --- OS Detection ---
if grep -qs "ubuntu" /etc/os-release; then
  os="ubuntu"
  os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f2 | tr -d '.')
elif [[ -e /etc/debian_version ]]; then
  os="debian"
  os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)
elif [[ -e /etc/almalinux-release || -e /etc/rocky-release || -e /etc/centos-release ]]; then
  os="centos"
  os_version=$(grep -shoE '[0-9]+' /etc/almalinux-release /etc/rocky-release /etc/centos-release | head -1)
elif [[ -e /etc/fedora-release ]]; then
  os="fedora"
  os_version=$(grep -oE '[0-9]+' /etc/fedora-release | head -1)
else
  echo "This installer seems to be running on an unsupported distribution.
Supported distros are Ubuntu, Debian, AlmaLinux, Rocky Linux, CentOS and Fedora."
  exit 1
fi

if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
  echo "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
  exit 1
fi

if [[ "$os" == "debian" ]]; then
  if grep -q '/sid' /etc/debian_version; then
    echo "Debian Testing and Debian Unstable are unsupported by this installer."
    exit 1
  fi
  if [[ "$os_version" -lt 11 ]]; then
    echo "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
    exit 1
  fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
  os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release \
    2>/dev/null | head -1)
  echo "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
  exit 1
fi

# Ensure PATH contains sbin directories
if ! grep -q sbin <<< "$PATH"; then
  echo '$PATH does not include sbin. Try using "su -" instead of "su".'
  exit 1
fi

# --- Container & TUN Device Check ---

if ! systemd-detect-virt -cq; then
  # Not running inside a container: use kernel module
  use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
  # Running in a container but kernel module available
  use_boringtun="0"
else
  # In container without kernel module: use userspace BoringTun
  use_boringtun="1"
fi

if [[ "$EUID" -ne 0 ]]; then
  echo "This installer needs to be run as root."
  exit 1
fi

# --- Main Installation Section ---
# If /etc/wireguard/wg0.conf does not exist, we assume WireGuard is not installed.
# The server and client configuration details are read from a YAML file.
YAML_CONFIG="/etc/wireguard/config.yaml"

if [[ ! -e /etc/wireguard/wg0.conf ]]; then
  echo "WireGuard is not installed. Starting installation process."

  # Ensure yq is installed
  if ! command -v yq &>/dev/null; then
    echo "yq not found, installing yq..."
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
      apt-get update && apt-get install -y yq
    elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
      dnf install -y yq
    fi
  fi

  if [[ ! -f "$YAML_CONFIG" ]]; then
    echo "Error: YAML configuration file $YAML_CONFIG not found!"
    exit 1
  fi

  echo "Loading configuration from $YAML_CONFIG ..."

  # --- Extract Server Config from YAML ---
  SERVER_PORT=$(yq e '.server.port' "$YAML_CONFIG")
  HOST_INTERFACE=$(yq e '.server.host_interface' "$YAML_CONFIG")
  SERVER_MTU=$(yq e '.server.mtu' "$YAML_CONFIG")
  PUBLIC_ENDPOINT=$(yq e '.server.public_endpoint' "$YAML_CONFIG")
  IPV4_ENABLED=$(yq e '.server.ipv4.enabled' "$YAML_CONFIG")
  IPV4_ADDRESS=$(yq e '.server.ipv4.address' "$YAML_CONFIG")
  IPV6_ENABLED=$(yq e '.server.ipv6.enabled' "$YAML_CONFIG")
  IPV6_ADDRESS=$(yq e '.server.ipv6.address' "$YAML_CONFIG")

  # Generate server keys
  SERVER_PRIVATE_KEY=$(wg genkey)
  SERVER_PUBLIC_KEY=$(echo "$SERVER_PRIVATE_KEY" | wg pubkey)

  echo "Generating server configuration file at /etc/wireguard/wg0.conf ..."
  cat << EOF > /etc/wireguard/wg0.conf
[Interface]
Address = $(if [ "$IPV4_ENABLED" = "true" ]; then echo "$IPV4_ADDRESS"; fi)$(if [ "$IPV6_ENABLED" = "true" ]; then
  echo ", $IPV6_ADDRESS"
fi)
ListenPort = $SERVER_PORT
MTU = $SERVER_MTU
PrivateKey = $SERVER_PRIVATE_KEY
EOF

  # --- Process Client Configurations from YAML ---
  CLIENT_COUNT=$(yq e '.clients | length' "$YAML_CONFIG")
  # Assume the server IPv4 is of the form X.Y.Z.1 with a /24 mask.
  SERVER_IPV4=$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)
  IFS=. read -r A B C D <<< "$SERVER_IPV4"
  CLIENT_OCTET=2

  for (( i=0; i<CLIENT_COUNT; i++ )); do
    CLIENT_NAME=$(yq e ".clients[${i}].name" "$YAML_CONFIG")
    CLIENT_DNS=$(yq e ".clients[${i}].dns" "$YAML_CONFIG")
    CLIENT_MTU=$(yq e ".clients[${i}].mtu" "$YAML_CONFIG")
    CLIENT_ALLOWED_IPS=$(yq e ".clients[${i}].allowed_ips" "$YAML_CONFIG")
    CLIENT_KEEPALIVE=$(yq e ".clients[${i}].persistent_keepalive" "$YAML_CONFIG")

    # Generate client keys and pre-shared key
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
    CLIENT_PSK=$(wg genpsk)

    CLIENT_IP="${A}.${B}.${C}.${CLIENT_OCTET}"
    (( CLIENT_OCTET++ ))

    # Append the peer configuration to the server's config file
    cat << EOF >> /etc/wireguard/wg0.conf

# BEGIN_PEER $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
PresharedKey = $CLIENT_PSK
AllowedIPs = ${CLIENT_IP}/32
EOF
    if [ "$IPV6_ENABLED" = "true" ]; then
      # A simple IPv6 allocation: append the client number to the server IPv6 prefix.
      IPV6_PREFIX=$(echo "$IPV6_ADDRESS" | cut -d'/' -f1)
      CLIENT_IPV6="${IPV6_PREFIX}:${CLIENT_OCTET}"
      cat << EOF >> /etc/wireguard/wg0.conf
, ${CLIENT_IPV6}/128
EOF
    fi
    echo "# END_PEER $CLIENT_NAME" >> /etc/wireguard/wg0.conf

    # Create individual client configuration file
    cat << EOF > ~/"${CLIENT_NAME}.conf"
[Interface]
Address = ${CLIENT_IP}/24$(if [ "$IPV6_ENABLED" = "true" ]; then
  echo ", ${CLIENT_IPV6}/64"
fi)
DNS = $CLIENT_DNS
MTU = $CLIENT_MTU
PrivateKey = $CLIENT_PRIVATE_KEY

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $CLIENT_PSK
AllowedIPs = $CLIENT_ALLOWED_IPS
Endpoint = $(if [ -n "$PUBLIC_ENDPOINT" ]; then echo "$PUBLIC_ENDPOINT"; else
  curl -s ifconfig.me
fi):$SERVER_PORT
PersistentKeepalive = $CLIENT_KEEPALIVE
EOF
    echo "Client '$CLIENT_NAME' configuration generated at ~/${CLIENT_NAME}.conf"
  done

  chmod 600 /etc/wireguard/wg0.conf

  # --- Enable IP Forwarding ---
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-wireguard-forward.conf
  echo 1 > /proc/sys/net/ipv4/ip_forward
  if [ "$IPV6_ENABLED" = "true" ]; then
    echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.d/99-wireguard-forward.conf
    echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
  fi

  # --- Install WireGuard and Dependencies ---
  echo "Installing WireGuard and dependencies..."
  if [[ "$use_boringtun" -eq 0 ]]; then
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
      apt-get update
      apt-get install -y wireguard qrencode
    elif [[ "$os" == "centos" ]]; then
      dnf install -y epel-release
      dnf install -y wireguard-tools qrencode
    elif [[ "$os" == "fedora" ]]; then
      dnf install -y wireguard-tools qrencode
    fi
  else
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
      apt-get update
      apt-get install -y qrencode ca-certificates
      apt-get install -y wireguard-tools --no-install-recommends
    elif [[ "$os" == "centos" ]]; then
      dnf install -y epel-release
      dnf install -y wireguard-tools qrencode ca-certificates tar
    elif [[ "$os" == "fedora" ]]; then
      dnf install -y wireguard-tools qrencode ca-certificates tar
      mkdir -p /etc/wireguard/
    fi

    { wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || \
      curl -sL https://wg.nyr.be/1/latest/download; } | \
      tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' \
      --strip-components 1

    mkdir -p /etc/systemd/system/wg-quick@wg0.service.d/
    cat << EOF > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1
EOF
  fi

  # --- Firewall / NAT Setup ---
  if systemctl is-active --quiet firewalld.service; then
    firewall="firewalld"
    # Open the WireGuard UDP port
    firewall-cmd --add-port="${SERVER_PORT}"/udp
    firewall-cmd --permanent --add-port="${SERVER_PORT}"/udp

    # Add the VPN subnet as a trusted zone.
    IPV4_SUBNET="$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)/24"
    firewall-cmd --zone=trusted --add-source="${IPV4_SUBNET}"
    firewall-cmd --permanent --zone=trusted --add-source="${IPV4_SUBNET}"

    # Set NAT for the VPN subnet using direct rules
    NAT_IP=$(ip route get 1.1.1.1 | awk '{print $NF; exit}')
    firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -s "${IPV4_SUBNET}" ! -d "${IPV4_SUBNET}" -j SNAT --to "${NAT_IP}"
    firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -s "${IPV4_SUBNET}" ! -d "${IPV4_SUBNET}" -j SNAT --to "${NAT_IP}"
    if [ "$IPV6_ENABLED" = "true" ]; then
      IPV6_PREFIX=$(echo "$IPV6_ADDRESS" | cut -d'/' -f1)
      firewall-cmd --zone=trusted --add-source="${IPV6_PREFIX}/64"
      firewall-cmd --permanent --zone=trusted --add-source="${IPV6_PREFIX}/64"
      # (IPv6 NAT is not always used; adjust if needed.)
    fi
  else
    iptables_path=$(command -v iptables)
    ip6tables_path=$(command -v ip6tables)
    cat << EOF > /etc/systemd/system/wg-iptables.service
[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s "$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)/24" ! -d "$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)/24" -j SNAT --to $(ip route get 1.1.1.1 | awk '{print $NF; exit}')
ExecStart=$iptables_path -I INPUT -p udp --dport $SERVER_PORT -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s "$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)/24" -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s "$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)/24" ! -d "$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)/24" -j SNAT --to $(ip route get 1.1.1.1 | awk '{print $NF; exit}')
ExecStop=$iptables_path -D INPUT -p udp --dport $SERVER_PORT -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s "$(echo "$IPV4_ADDRESS" | cut -d'/' -f1)/24" -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
    systemctl enable --now wg-iptables.service
  fi

  # --- Enable the WireGuard Service ---
  systemctl enable --now wg-quick@wg0.service

  # --- Display Client QR Codes ---
  echo "Displaying QR codes for client configurations..."
  for (( i=0; i<CLIENT_COUNT; i++ )); do
    CLIENT_NAME=$(yq e ".clients[${i}].name" "$YAML_CONFIG")
    qrencode -t ANSI256UTF8 < ~/"${CLIENT_NAME}.conf"
    echo -e "\nQR code for ${CLIENT_NAME} above."
  done

  echo "WireGuard installation completed!"
  echo "Server configuration: /etc/wireguard/wg0.conf"
  echo "Client configurations saved in your home directory."
  exit 0

else
  # --- Interactive Management Menu ---
  clear
  echo "WireGuard is already installed."
  echo
  echo "Select an option:"
  echo "   1) Add a new client"
  echo "   2) Remove an existing client"
  echo "   3) Remove WireGuard"
  echo "   4) Exit"
  read -p "Option: " option
  until [[ "$option" =~ ^[1-4]$ ]]; do
    echo "$option: invalid selection."
    read -p "Option: " option
  done
  case "$option" in
    1)
      echo
      echo "Enter a name for the new client:"
      read -p "Name: " unsanitized_client
      client=$(sed 's/[^0-9a-zA-Z_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
      while [[ -z "$client" ]] || grep -q "^# BEGIN_PEER $client\$" /etc/wireguard/wg0.conf; do
        echo "Invalid or duplicate client name. Please try again."
        read -p "Name: " unsanitized_client
        client=$(sed 's/[^0-9a-zA-Z_-]/_/g' <<< "$unsanitized_client" | cut -c-15)
      done
      echo
      echo "Enter DNS for the client (e.g., 1.1.1.1, 1.0.0.1):"
      read -p "DNS [1.1.1.1, 1.0.0.1]: " dns
      dns=${dns:-"1.1.1.1, 1.0.0.1"}

      # Determine an available IPv4 address (assumes server is .1 with /24)
      octet=2
      while grep AllowedIPs /etc/wireguard/wg0.conf | cut -d "." -f4 | cut -d"/" -f1 | grep -q "^$octet\$"; do
        (( octet++ ))
      done
      if [[ "$octet" -ge 255 ]]; then
        echo "No available IP addresses."
        exit 1
      fi
      SERVER_IPV4=$(grep "Address =" /etc/wireguard/wg0.conf | head -1 | awk '{print $3}' | cut -d',' -f1 | cut -d'/' -f1)
      IFS=. read -r A B C D <<< "$SERVER_IPV4"
      client_ip="${A}.${B}.${C}.${octet}"

      key=$(wg genkey)
      psk=$(wg genpsk)

      # Append new client (peer) configuration into the server config
      cat << EOF >> /etc/wireguard/wg0.conf

# BEGIN_PEER $client
[Peer]
PublicKey = $(echo "$key" | wg pubkey)
PresharedKey = $psk
AllowedIPs = ${client_ip}/32
# END_PEER $client
EOF

      SERVER_PUBLIC_KEY=$(grep "PrivateKey" /etc/wireguard/wg0.conf | head -1 | awk '{print $3}' | wg pubkey)
      SERVER_PORT=$(grep "ListenPort" /etc/wireguard/wg0.conf | head -1 | awk '{print $3}')
      PUBLIC_IP=$(grep '^# ENDPOINT' /etc/wireguard/wg0.conf | awk '{print $3}')
      [ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(curl -s ifconfig.me)

      cat << EOF > ~/"${client}.conf"
[Interface]
Address = ${client_ip}/24
DNS = $dns
PrivateKey = $key

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
PresharedKey = $psk
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = ${PUBLIC_IP}:${SERVER_PORT}
PersistentKeepalive = 25
EOF

      wg addconf wg0 <(sed -n "/^# BEGIN_PEER $client\$/,/^# END_PEER $client\$/p" /etc/wireguard/wg0.conf)
      qrencode -t ANSI256UTF8 < ~/"${client}.conf"
      echo "Client '$client' added. Configuration available at ~/${client}.conf"
      exit 0
      ;;
    2)
      echo
      echo "Existing clients:"
      grep "^# BEGIN_PEER" /etc/wireguard/wg0.conf | cut -d " " -f3 | nl -s ') '
      read -p "Select client number to remove: " client_number
      client=$(grep "^# BEGIN_PEER" /etc/wireguard/wg0.conf | cut -d " " -f3 | sed -n "${client_number}p")
      if [ -z "$client" ]; then
        echo "Invalid selection."
        exit 1
      fi
      read -p "Confirm removal of client $client? [y/N]: " remove
      if [[ "$remove" =~ ^[yY]$ ]]; then
        PUBKEY=$(sed -n "/^# BEGIN_PEER $client\$/,/^# END_PEER $client\$/p" /etc/wireguard/wg0.conf | grep PublicKey | awk '{print $3}')
        wg set wg0 peer "$PUBKEY" remove
        sed -i "/^# BEGIN_PEER $client\$/,/^# END_PEER $client\$/d" /etc/wireguard/wg0.conf
        echo "Client $client removed."
      else
        echo "Aborted removal."
      fi
      exit 0
      ;;
    3)
      echo
      read -p "Confirm WireGuard removal? [y/N]: " remove
      if [[ "$remove" =~ ^[yY]$ ]]; then
        systemctl disable --now wg-quick@wg0.service
        if systemctl is-active --quiet firewalld.service; then
          firewall-cmd --remove-port="$(grep ListenPort /etc/wireguard/wg0.conf | awk '{print $3}')/udp"
        else
          systemctl disable --now wg-iptables.service
          rm -f /etc/systemd/system/wg-iptables.service
        fi
        rm -rf /etc/wireguard/
        if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
          apt-get remove --purge -y wireguard wireguard-tools
        elif [[ "$os" == "centos" ]]; then
          dnf remove -y wireguard-tools
        elif [[ "$os" == "fedora" ]]; then
          dnf remove -y wireguard-tools
        fi
        echo "WireGuard removed."
      else
        echo "Aborted removal."
      fi
      exit 0
      ;;
    4)
      exit 0
      ;;
  esac
fi
