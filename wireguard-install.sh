#!/bin/bash

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

if [[ "$EUID" -ne 0 ]]; then
	echo "This installer needs to be run with superuser privileges."
	exit
fi

# Install WireGuard
# If BoringTun is not required, set up with the WireGuard kernel module
if [[ "$use_boringtun" -eq 0 ]]; then
	if [[ "$os" == "ubuntu" ]]; then
		# Ubuntu
		apt-get update
		apt-get install -y wireguard qrencode $firewall
	elif [[ "$os" == "debian" ]]; then
		# Debian
		apt-get update
		apt-get install -y wireguard qrencode $firewall
	elif [[ "$os" == "centos" ]]; then
		# CentOS
		dnf install -y epel-release
		dnf install -y wireguard-tools qrencode $firewall
	elif [[ "$os" == "fedora" ]]; then
		# Fedora
		dnf install -y wireguard-tools qrencode $firewall
		mkdir -p /etc/wireguard/
	fi
# Else, BoringTun needs to be used
else
	# Install required packages
	if [[ "$os" == "ubuntu" ]]; then
		# Ubuntu
		apt-get update
		apt-get install -y qrencode ca-certificates $cron $firewall
		apt-get install -y wireguard-tools --no-install-recommends
	elif [[ "$os" == "debian" ]]; then
		# Debian
		apt-get update
		apt-get install -y qrencode ca-certificates $cron $firewall
		apt-get install -y wireguard-tools --no-install-recommends
	elif [[ "$os" == "centos" ]]; then
		# CentOS
		dnf install -y epel-release
		dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
	elif [[ "$os" == "fedora" ]]; then
		# Fedora
		dnf install -y wireguard-tools qrencode ca-certificates tar $cron $firewall
		mkdir -p /etc/wireguard/
	fi
fi

# Ensure yq is installed
install_yq() {
    if ! command -v yq &> /dev/null; then
        echo "yq not found. Installing..."
        if [[ "$os" == "ubuntu" || "$os" == "debian" ]]; then
            wget https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -O /usr/bin/yq
            chmod +x /usr/bin/yq
        elif [[ "$os" == "centos" || "$os" == "fedora" ]]; then
            dnf install -y yq
        else
            echo "Unsupported OS for automatic yq installation"
            exit 1
        fi
    fi
}

# Default config file locations (in order of precedence)
CONFIG_LOCATIONS=(
    "./wireguard.yaml"
    "/etc/wireguard/config.yaml"
    "$HOME/.config/wireguard/config.yaml"
    "/usr/local/etc/wireguard/config.yaml"
)

find_config_file() {
    for config in "${CONFIG_LOCATIONS[@]}"; do
        if [[ -f "$config" ]]; then
            echo "$config"
            return 0
        fi
    done

    echo "No configuration file found. Checked locations:"
    printf '%s\n' "${CONFIG_LOCATIONS[@]}"
    exit 1
}

# Parse config from YAML
parse_config() {
    local config_file="$1"

    # Validate config file exists
    if [[ ! -f "$config_file" ]]; then
        echo "Config file not found: $config_file"
        exit 1
    fi

    # Extract configuration values
    SERVER_IPV4=$(yq '.server.ipv4' "$config_file")
    SERVER_PORT=$(yq '.server.port' "$config_file")
    CLIENT_NAME=$(yq '.client.name' "$config_file")
    DNS_SERVER=$(yq '.client.dns' "$config_file")

    # Validate extracted values
    [[ -z "$SERVER_IPV4" ]] && { echo "No IPv4 address specified in config"; exit 1; }
    [[ -z "$SERVER_PORT" ]] && SERVER_PORT="51820"
    [[ -z "$CLIENT_NAME" ]] && CLIENT_NAME="client"
    [[ -z "$DNS_SERVER" ]] && DNS_SERVER="1"
}
