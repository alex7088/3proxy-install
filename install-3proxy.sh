#!/usr/bin/env bash
set -euo pipefail

#================= Paths / Settings =================
PREFIX_BIN="/usr/local/bin"
CFG_DIR="/etc/3proxy"
CFG_FILE="${CFG_DIR}/3proxy.cfg"
USERS_FILE="${CFG_DIR}/.users"
UNIT_FILE="/etc/systemd/system/3proxy.service"
BUILD_DIR="/tmp/3proxy-build"
REPO_URL="https://github.com/3proxy/3proxy.git"
BRANCH="master"

#================= Helpers =================
need_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0" >&2; exit 1
  fi
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

detect_pkg() {
  if have_cmd apt-get; then PKG="apt-get"; else
    echo "apt-get not found (Debian/Ubuntu required)"; exit 1
  fi
}

detect_fw() {
  # Check if iptables rules already exist (prefer consistency)
  if have_cmd iptables && iptables -L INPUT -n 2>/dev/null | grep -q "ACCEPT\|DROP\|REJECT"; then 
    FW="iptables"
  elif have_cmd nft; then 
    FW="nft"
  elif have_cmd iptables; then 
    FW="iptables"
  else 
    FW="none"
  fi
}

valid_port() {
  local p="$1"; [[ "$p" =~ ^[0-9]+$ ]] && (( p>0 && p<65536 ))
}

is_port_busy() {
  if have_cmd ss; then
    ss -tuln 2>/dev/null | grep -q ":$1 "
  elif have_cmd netstat; then
    netstat -tuln 2>/dev/null | grep -q ":$1 "
  else
    return 1  # we cant check
  fi
}

get_server_ip() {
  local ip
  ip=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
  echo "$ip"
}

#================= Installation Check =================
check_existing_installation() {
  if [[ -f "${PREFIX_BIN}/3proxy" ]]; then
    if [[ -f "${CFG_FILE}" ]] && grep -q "# Installed by 3proxy-installer.sh script" "${CFG_FILE}"; then
      echo "Found existing installation by this script. Proceeding with reinstallation..."
      return 0
    else
      echo "WARNING: 3proxy is already installed (possibly manually)."
      echo "To avoid damaging your configuration, the script has stopped."
      echo ""
      echo "If you want to use this script:"
      echo "1. Remove 3proxy manually"
      echo "2. Run this script again"
      echo ""
      echo "For manual removal, try:"
      echo "  sudo systemctl stop 3proxy"
      echo "  sudo systemctl disable 3proxy"
      echo "  sudo rm -f /usr/local/bin/3proxy"
      echo "  sudo rm -rf /etc/3proxy"
      echo "  sudo rm -f /etc/systemd/system/3proxy.service"
      echo ""
      return 1
    fi
  fi
  return 0
}

#================= Port Input with Validation =================
get_port_input() {
  local prompt="$1"
  local default="$2"
  local port
  
  while true; do
    read -rp "${prompt} [${default}]: " port
    port="${port:-$default}"
    
    if ! valid_port "$port"; then
      echo "Invalid port number. Please enter a port between 1-65535." >&2
      continue
    fi
    
    if is_port_busy "$port"; then
      echo "Port $port is busy. Please try another port." >&2
      continue
    fi
    
    echo "Port $port is available." >&2
    echo "$port"
    return 0
  done
}

#================= Firewall =================
add_fw_rules() {
  local http_port="$1" socks_port="$2"
  detect_fw
  echo "Configuring firewall: ${FW}"
  case "$FW" in
    nft)
      nft list table inet filter >/dev/null 2>&1 || nft add table inet filter
      nft list chain inet filter INPUT >/dev/null 2>&1 || nft add chain inet filter INPUT '{ type filter hook input priority 0; policy accept; }'
      nft add rule inet filter INPUT tcp dport ${http_port} counter accept 2>/dev/null || true
      nft add rule inet filter INPUT tcp dport ${socks_port} counter accept 2>/dev/null || true
      nft add rule inet filter INPUT udp dport ${socks_port} counter accept 2>/dev/null || true
      ;;
    iptables)
      iptables -C INPUT -p tcp --dport "$http_port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$http_port" -j ACCEPT
      iptables -C INPUT -p tcp --dport "$socks_port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$socks_port" -j ACCEPT
      iptables -C INPUT -p udp --dport "$socks_port" -j ACCEPT 2>/dev/null || iptables -I INPUT -p udp --dport "$socks_port" -j ACCEPT
      if have_cmd ip6tables; then
        ip6tables -C INPUT -p tcp --dport "$http_port" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport "$http_port" -j ACCEPT
        ip6tables -C INPUT -p tcp --dport "$socks_port" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p tcp --dport "$socks_port" -j ACCEPT
        ip6tables -C INPUT -p udp --dport "$socks_port" -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p udp --dport "$socks_port" -j ACCEPT
      fi
      ;;
    *) echo "No firewall detected - skipped";;
  esac
}

remove_fw_rules() {
  local http_port="$1" socks_port="$2"
  detect_fw
  case "$FW" in
    nft)
      nft delete rule inet filter INPUT tcp dport ${http_port} counter accept 2>/dev/null || true
      nft delete rule inet filter INPUT tcp dport ${socks_port} counter accept 2>/dev/null || true
      nft delete rule inet filter INPUT udp dport ${socks_port} counter accept 2>/dev/null || true
      ;;
    iptables)
      while iptables -C INPUT -p tcp --dport "$http_port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport "$http_port" -j ACCEPT; done
      while iptables -C INPUT -p tcp --dport "$socks_port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p tcp --dport "$socks_port" -j ACCEPT; done
      while iptables -C INPUT -p udp --dport "$socks_port" -j ACCEPT 2>/dev/null; do iptables -D INPUT -p udp --dport "$socks_port" -j ACCEPT; done
      if have_cmd ip6tables; then
        while ip6tables -C INPUT -p tcp --dport "$http_port" -j ACCEPT 2>/dev/null; do ip6tables -D INPUT -p tcp --dport "$http_port" -j ACCEPT; done
        while ip6tables -C INPUT -p tcp --dport "$socks_port" -j ACCEPT 2>/dev/null; do ip6tables -D INPUT -p tcp --dport "$socks_port" -j ACCEPT; done
        while ip6tables -C INPUT -p udp --dport "$socks_port" -j ACCEPT 2>/dev/null; do ip6tables -D INPUT -p udp --dport "$socks_port" -j ACCEPT; done
      fi
      ;;
    *) ;;
  esac
}

#================= Config / Service =================
write_config() {
  local http_port="$1" socks_port="$2"
  install -d -m 0755 "${CFG_DIR}"
  
  # Preserve existing users if this is a reinstall by this script
  if [[ -f "${USERS_FILE}" ]] && [[ -f "${CFG_FILE}" ]] && grep -q "# Installed by 3proxy-installer.sh script" "${CFG_FILE}"; then
    cp "${USERS_FILE}" "${USERS_FILE}.backup"
    echo "Created backup of existing users: ${USERS_FILE}.backup"
  else
    touch "${USERS_FILE}"; chmod 640 "${USERS_FILE}"
  fi

  cat > "${CFG_FILE}" <<EOF
# Installed by 3proxy-installer.sh script
# Installation date: $(date)
# Ports: HTTP ${http_port}, SOCKS5 ${socks_port}

maxconn 400
nscache 65536
timeouts 1 5 30 60 180 1800 15 60

auth strong
users $/etc/3proxy/.users

flush
allow *

# SOCKS5 (with UDP associate support)
socks -p${socks_port}

# HTTP proxy
proxy -p${http_port}

# Logging is disabled by default for privacy.
# To enable, add lines like:
# log /var/log/3proxy/3proxy-%y%m%d.log D
# logformat "L%Y-%m-%d %H:%M:%S %E %U %C:%c %R:%r %O %I %T"
# rotate 30
EOF
  chmod 644 "${CFG_FILE}"
}

ensure_unit() {
  cat > "${UNIT_FILE}" <<EOF
[Unit]
Description=3proxy tiny proxy server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${PREFIX_BIN}/3proxy ${CFG_FILE}
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable 3proxy.service >/dev/null 2>&1 || true
}

restart_3proxy() {
  systemctl restart 3proxy.service
  systemctl --no-pager --full status 3proxy.service || true
}

#================= Users =================
validate_username() {
  local username="$1"
  [[ "$username" =~ ^[a-zA-Z0-9_-]+$ ]]
}

add_user() {
  local u p p_confirm
  
  while true; do
    read -rp "Username: " u
    [[ -z "$u" ]] && { echo "Empty username"; continue; }
    
    if ! validate_username "$u"; then
      echo "Invalid username. Only English letters, numbers, dash (-) and underscore (_) allowed."
      continue
    fi
    
    if [[ -f "${USERS_FILE}" ]] && grep -E "^${u}:" "${USERS_FILE}" >/dev/null 2>&1; then
      echo "User already exists"; continue
    fi
    
    break
  done
  
  while true; do
    read -rp "Password: " p
    [[ -z "$p" ]] && { echo "Empty password"; continue; }
    read -rp "Confirm password: " p_confirm
    if [[ "$p" = "$p_confirm" ]]; then
      break
    else
      echo "Passwords don't match. Please try again."
    fi
  done
  
  echo "${u}:CL:${p}" >> "${USERS_FILE}"
  chmod 640 "${USERS_FILE}"
  echo "User added: ${u}"
  restart_3proxy
}

del_user() {
  if [[ ! -s "${USERS_FILE}" ]]; then 
    echo "No users to remove"; 
    return; 
  fi
  
  echo "Current users:"
  local users_array=()
  local i=1
  
  # Read users into array and display with numbers
  while IFS=':' read -r username rest; do
    users_array+=("$username")
    echo "$i) $username"
    ((i++))
  done < "${USERS_FILE}"
  
  echo "0) Cancel"
  echo
  
  local choice
  read -rp "Enter user number to remove: " choice
  
  if [[ "$choice" = "0" ]]; then
    echo "Canceled"
    return
  fi
  
  if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#users_array[@]} )); then
    echo "Invalid choice"
    return
  fi
  
  local username_to_remove="${users_array[$((choice-1))]}"
  
  # Use line number deletion instead of pattern matching to handle special characters
  sed -i.bak "${choice}d" "${USERS_FILE}"
  echo "User removed: ${username_to_remove}"
  restart_3proxy
}

list_users() {
  if [[ ! -s "${USERS_FILE}" ]]; then 
    echo "No users yet"; 
    return; 
  fi
  
  echo "Users:"
  local i=1
  while IFS=':' read -r username rest; do
    echo " $i) $username"
    ((i++))
  done < "${USERS_FILE}"
}

#================= BadVPN =================
install_badvpn() {
  echo "Installing BadVPN UDP Gateway..."
  local badvpn_dir="/tmp/badvpn-build"
  
  apt-get install -y --no-install-recommends cmake
  
  echo "Cloning BadVPN..."
  rm -rf "${badvpn_dir}"
  git clone --depth 1 https://github.com/ambrop72/badvpn.git "${badvpn_dir}"
  
  echo "Building BadVPN..."
  cd "${badvpn_dir}"
  mkdir build && cd build
  cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
  make 2> >(grep -v "warning:")
  
  echo "Installing BadVPN binary..."
  install -m 0755 udpgw/badvpn-udpgw "${PREFIX_BIN}/badvpn-udpgw"
  
  echo "Cleaning up..."
  rm -rf "${badvpn_dir}"
  cd /
}

ensure_badvpn_unit() {
  cat > /etc/systemd/system/udpgw.service <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
Type=simple
User=root
ExecStart=${PREFIX_BIN}/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable udpgw.service >/dev/null 2>&1 || true
  systemctl start udpgw.service
}

#================= Build / Install / Uninstall =================
install_build() {
  need_root; detect_pkg
  echo "Installing build dependencies..."
  apt-get update -y >/dev/null 2>&1
  apt-get install -y --no-install-recommends git build-essential make gcc libc6-dev >/dev/null 2>&1

  echo "Cloning 3proxy..."
  rm -rf "${BUILD_DIR}"
  git clone --quiet --depth 1 -b "${BRANCH}" "${REPO_URL}" "${BUILD_DIR}"

  echo "Building 3proxy..."
  if ! make -C "${BUILD_DIR}" -f Makefile.Linux \
	> >(grep -v "warning:") \
	2> >(grep -v "warning:"); then
    echo "ERROR: 3proxy build failed" >&2
    exit 1
  fi

  echo "Installing 3proxy binary..."
  install -m 0755 "${BUILD_DIR}/bin/3proxy" "${PREFIX_BIN}/3proxy"

  echo "Cleaning up..."
  rm -rf "${BUILD_DIR}"
  
  # Install BadVPN
  install_badvpn
}

uninstall_all() {
  need_root
  local http_ports socks_ports
  
  # Extract ports from config if it exists and is readable
  if [[ -f "${CFG_FILE}" ]]; then
    http_ports=$(grep -E '^proxy -p[0-9]+' "${CFG_FILE}" 2>/dev/null | sed -E 's/.*-p([0-9]+).*/\1/' || true)
    socks_ports=$(grep -E '^socks -p[0-9]+' "${CFG_FILE}" 2>/dev/null | sed -E 's/.*-p([0-9]+).*/\1/' || true)
  fi

  echo "Stopping services..."
  systemctl stop 3proxy.service 2>/dev/null || true
  systemctl disable 3proxy.service 2>/dev/null || true
  systemctl stop udpgw.service 2>/dev/null || true  
  systemctl disable udpgw.service 2>/dev/null || true
  
  rm -f "${UNIT_FILE}"
  rm -f /etc/systemd/system/udpgw.service
  systemctl daemon-reload || true

  # Remove firewall rules - try both extracted ports and common defaults
  echo "Removing firewall rules..."
  local all_ports="$http_ports $socks_ports 3128 8080 8888 1080 1081 9050"
  
  detect_fw
  case "$FW" in
    iptables)
      # Remove common proxy ports
      for port in $all_ports; do
        [[ -n "$port" ]] || continue
        iptables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
        iptables -D INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
        if have_cmd ip6tables; then
          ip6tables -D INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || true
          ip6tables -D INPUT -p udp --dport "$port" -j ACCEPT 2>/dev/null || true
        fi
      done
      ;;
    nft)
      # Try to remove the entire inet filter table created by this script
      nft delete table inet filter 2>/dev/null || true
      ;;
  esac

  echo "Removing files..."
  rm -f "${PREFIX_BIN}/3proxy"
  rm -f "${PREFIX_BIN}/badvpn-udpgw"
  rm -rf "${CFG_DIR}"
  echo "3proxy and BadVPN uninstalled successfully."
  echo "Note: Some firewall rules may remain if ports couldn't be detected from config."
}

#================= Setup =================
initial_setup() {
  need_root
  
  # Check for existing installation
  if ! check_existing_installation; then
    return 1
  fi
  
  echo "=== 3proxy Installation ==="
  local HTTP_PORT SOCKS_PORT
  
  HTTP_PORT=$(get_port_input "HTTP proxy port" "3128")
  SOCKS_PORT=$(get_port_input "SOCKS5 proxy port" "1080")
  
  if [[ "$HTTP_PORT" = "$SOCKS_PORT" ]]; then
    echo "HTTP and SOCKS5 ports must be different. Please start over."
    return
  fi

  echo "Installing 3proxy..."
  install_build
  write_config "$HTTP_PORT" "$SOCKS_PORT"
  ensure_unit
  ensure_badvpn_unit
  add_fw_rules "$HTTP_PORT" "$SOCKS_PORT"

  read -rp "Create first user now? [y/N]: " ans
  [[ "${ans:-n}" =~ ^[Yy]$ ]] && add_user

  restart_3proxy
  
  local server_ip
  server_ip=$(get_server_ip)
  
  echo ""
  echo "=== Installation Complete ==="
  echo "HTTP proxy: ${server_ip}:${HTTP_PORT}"
  echo "SOCKS5 proxy: ${server_ip}:${SOCKS_PORT} (with UDP Associate)"
  echo "BadVPN UDP Gateway: 127.0.0.1:7300 (for mobile clients)"
  echo "Config file: ${CFG_FILE}"
  echo "Users file: ${USERS_FILE}"
  echo ""
  echo "Services installed:"
  echo "  ✓ 3proxy (HTTP/SOCKS5 proxy server)"
  echo "  ✓ udpgw port 7300 (BadVPN UDP Gateway for mobile compatibility)"
  echo ""
  echo "Test your proxy:"
  echo "  curl -x http://user:pass@${server_ip}:${HTTP_PORT} http://ifconfig.me"
  echo "  curl --socks5 user:pass@${server_ip}:${SOCKS_PORT} http://ifconfig.me"
}

show_connection_info() {
  if [[ ! -f "${CFG_FILE}" ]]; then
    echo "3proxy is not installed or config file not found"
    return
  fi
  
  echo "=== Connection Information ==="
  
  # Extract ports from config
  local http_port socks_port server_ip
  http_port=$(grep -E '^proxy -p[0-9]+' "${CFG_FILE}" 2>/dev/null | sed -E 's/.*-p([0-9]+)/\1/' | head -n1)
  socks_port=$(grep -E '^socks -p[0-9]+' "${CFG_FILE}" 2>/dev/null | sed -E 's/.*-p([0-9]+)/\1/' | head -n1)
  server_ip=$(get_server_ip)
  
  echo "Server IP: ${server_ip}"
  [[ -n "$http_port" ]] && echo "HTTP Proxy: ${server_ip}:${http_port}"
  [[ -n "$socks_port" ]] && echo "SOCKS5 Proxy: ${server_ip}:${socks_port}"
  echo ""
  echo "Test commands:"
  [[ -n "$http_port" ]] && echo "  curl -x http://user:pass@${server_ip}:${http_port} http://ifconfig.me"
  [[ -n "$socks_port" ]] && echo "  curl --socks5 user:pass@${server_ip}:${socks_port} http://ifconfig.me"
  echo ""
  echo "Browser extensions: FoxyProxy, Proxy SwitchyOmega"
}

#================= Menu =================
menu() {
  while true; do
    echo
    echo "==== 3proxy Management Menu ===="
    echo "1) Install / Reinstall 3proxy"
    echo "2) Add user"
    echo "3) Remove user"
    echo "4) List users"
    echo "5) Show connection info"
    echo "6) Restart service"
    echo "7) Uninstall 3proxy"
    echo "0) Exit"
    read -rp "Choose option: " ch
    case "$ch" in
      1) initial_setup ;;
      2) add_user ;;
      3) del_user ;;
      4) list_users ;;
      5) show_connection_info ;;
      6) restart_3proxy ;;
      7) read -rp "Are you sure you want to uninstall 3proxy? [y/N]: " c; [[ "${c:-n}" =~ ^[Yy]$ ]] && uninstall_all || echo "Canceled." ;;
      0) exit 0 ;;
      *) echo "Invalid option" ;;
    esac
  done
}

# Show banner
echo "3proxy Installer Script"
echo "======================="
echo "Interactive installation script for 3proxy proxy server"
echo "Supports HTTP proxy + SOCKS5 with user management"
echo ""

menu