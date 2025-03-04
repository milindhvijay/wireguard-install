#!/bin/bash
#
# https://github.com/Nyr/wireguard-install
#
# Copyright (c) 2020 Nyr. Released under the MIT License.

# Detect Debian users running the script with "sh" instead of bash
if readlink /proc/$$/exe | grep -q "dash"; then
    echo 'This installer needs to be run with "bash", not "sh".'
    exit
fi

# Discard stdin. Needed when running from an one-liner which includes a newline
read -N 999999 -t 0.001

# Detect OS
# $os_version variables aren't always in use, but are kept here for convenience
if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')
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
    exit
fi

# Validate OS version
if [[ "$os" == "ubuntu" && "$os_version" -lt 2204 ]]; then
    echo "Ubuntu 22.04 or higher is required to use this installer.
This version of Ubuntu is too old and unsupported."
    exit
fi

if [[ "$os" == "debian" ]]; then
    if grep -q '/sid' /etc/debian_version; then
        echo "Debian Testing and Debian Unstable are unsupported by this installer."
        exit
    fi
    if [[ "$os_version" -lt 11 ]]; then
        echo "Debian 11 or higher is required to use this installer.
This version of Debian is too old and unsupported."
        exit
    fi
fi

if [[ "$os" == "centos" && "$os_version" -lt 9 ]]; then
    os_name=$(sed 's/ release.*//' /etc/almalinux-release /etc/rocky-release /etc/centos-release 2>/dev/null | head -1)
    echo "$os_name 9 or higher is required to use this installer.
This version of $os_name is too old and unsupported."
    exit
fi

# Detect environments where $PATH does not include the sbin directories
if ! grep -q sbin <<< "$PATH"; then
    echo '$PATH does not include sbin. Try using "su -" instead of "su".'
    exit
fi

# Detect if BoringTun (userspace WireGuard) needs to be used
if ! systemd-detect-virt -cq; then
    # Not running inside a container
    use_boringtun="0"
elif grep -q '^wireguard ' /proc/modules; then
    # Running inside a container, but the wireguard kernel module is available
    use_boringtun="0"
else
    # Running inside a container and the wireguard kernel module is not available
    use_boringtun="1"
fi

# Check privileges
if [[ "$EUID" -ne 0 ]]; then
    echo "This installer needs to be run with superuser privileges."
    exit
fi

# Check BoringTun requirements
if [[ "$use_boringtun" -eq 1 ]]; then
    if [ "$(uname -m)" != "x86_64" ]; then
        echo "In containerized systems without the wireguard kernel module, this installer
supports only the x86_64 architecture.
The system runs on $(uname -m) and is unsupported."
        exit
    fi
    # TUN device is required to use BoringTun
    if [[ ! -e /dev/net/tun ]] || ! ( exec 7<>/dev/net/tun ) 2>/dev/null; then
        echo "The system does not have the TUN device available.
TUN needs to be enabled before running this installer."
        exit
    fi
fi

# Check and install yq for YAML parsing
if ! hash yq 2>/dev/null; then
    echo "yq is required to parse YAML configuration files."
    read -n1 -r -p "Press any key to install yq and continue..."
    if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
        apt-get update
        apt-get install -y yq
    elif [[ "$os" == "centos" ]]; then
        dnf install -y epel-release
        dnf install -y yq
    elif [[ "$os" == "fedora" ]]; then
        dnf install -y yq
    fi
fi

# Read YAML configuration file
CONFIG_FILE="/etc/wireguard/wg-config.yaml"
if [[ -f "$CONFIG_FILE" ]]; then
    SERVER_IP=$(yq e '.server.ip' "$CONFIG_FILE")
    SERVER_PORT=$(yq e '.server.port' "$CONFIG_FILE")
    if [[ "$SERVER_IP" == "null" || -z "$SERVER_IP" ]]; then
        echo "Server IP not specified in YAML."
    fi
    if [[ "$SERVER_PORT" == "null" || -z "$SERVER_PORT" ]]; then
        echo "Server port not specified in YAML, using default 51820."
        SERVER_PORT="51820"
    fi
else
    echo "YAML config file ($CONFIG_FILE) not found."
fi

# Install required tools
if [[ ! -e /etc/wireguard/wg0.conf ]]; then
    # Detect some Debian minimal setups where neither wget nor curl are installed
    if ! hash wget 2>/dev/null && ! hash curl 2>/dev/null; then
        echo "Wget is required to use this installer."
        read -n1 -r -p "Press any key to install Wget and continue..."
        apt-get update
        apt-get install -y wget
    fi

    # Install WireGuard tools based on OS and BoringTun requirement
    if [[ "$use_boringtun" -eq 0 ]]; then
        if [[ "$os" == "ubuntu" ]]; then
            apt-get update
            apt-get install -y wireguard qrencode
        elif [[ "$os" == "debian" ]]; then
            apt-get update
            apt-get install -y wireguard qrencode
        elif [[ "$os" == "centos" ]]; then
            dnf install -y epel-release
            dnf install -y wireguard-tools qrencode
        elif [[ "$os" == "fedora" ]]; then
            dnf install -y wireguard-tools qrencode
            mkdir -p /etc/wireguard/
        fi
    else
        if [[ "$os" == "ubuntu" ]]; then
            apt-get update
            apt-get install -y qrencode ca-certificates
            apt-get install -y wireguard-tools --no-install-recommends
        elif [[ "$os" == "debian" ]]; then
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
        # Install BoringTun
        { wget -qO- https://wg.nyr.be/1/latest/download 2>/dev/null || curl -sL https://wg.nyr.be/1/latest/download ; } | tar xz -C /usr/local/sbin/ --wildcards 'boringtun-*/boringtun' --strip-components 1
        # Configure wg-quick for BoringTun
        mkdir /etc/systemd/system/wg-quick@wg0.service.d/ 2>/dev/null
        echo "[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=boringtun
Environment=WG_SUDO=1" > /etc/systemd/system/wg-quick@wg0.service.d/boringtun.conf
    fi
fi

echo "Setup complete: OS detected ($os $os_version), BoringTun set to $use_boringtun, tools installed."
echo "Server IP = ${SERVER_IP:-not set}, Server Port = ${SERVER_PORT:-not set}"
