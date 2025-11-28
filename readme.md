# 3proxy Installer

Automated installer for [3proxy](https://3proxy.org/) with BadVPN support for Debian/Ubuntu systems.

Sets up a fully functional proxy server with HTTP/HTTPS and SOCKS5 support, user management, and automatic firewall configuration.

---

## Features

- **HTTP/HTTPS Proxy** (default port 3128)
- **SOCKS5 Proxy** with UDP Associate support (default port 1080)
- **BadVPN UDP Gateway** (port 7300) for mobile VPN clients (SocksDroid, HTTP Injector, etc.)
- **No logging by default** — maximum privacy, no traffic records
- **Authentication** — username/password protection
- **Auto firewall setup** (iptables/nftables)
- **Interactive management** — add/remove users, reinstall, uninstall
- **Port validation** — checks if ports are already in use

---

## Quick Install
```bash
curl -fsSL https://raw.githubusercontent.com/alex7088/3proxy-install/main/install-3proxy.sh -o install-3proxy.sh
sudo bash install-3proxy.sh
```

Follow the prompts to select ports and create your first user.

---

## Requirements

- **OS**: Debian 8+ or Ubuntu 16.04+
- **Access**: root/sudo
- **RAM**: 256MB minimum
- **Disk**: ~50MB

---

## Usage

### Management Menu
```
==== 3proxy Management Menu ====
1) Install / Reinstall 3proxy
2) Add user
3) Remove user
4) List users
5) Show connection info
6) Restart service
7) Uninstall 3proxy
0) Exit
```

### Testing Your Proxy

**HTTP Proxy:**
```bash
curl -x http://username:password@SERVER_IP:3128 http://ifconfig.me
```

**SOCKS5 Proxy:**
```bash
curl --socks5 username:password@SERVER_IP:1080 http://ifconfig.me
```

---

## Client Setup

### Browsers

Use extensions like [FoxyProxy](https://getfoxyproxy.org/) or [Proxy SwitchyOmega](https://github.com/FelisCatus/SwitchyOmega):
```
Type: SOCKS5 (or HTTP)
Server: YOUR_SERVER_IP
Port: 1080 (SOCKS5) or 3128 (HTTP)
Username: your_username
Password: your_password
```

### Telegram
```
Settings → Advanced → Connection type → Use custom proxy
Type: SOCKS5
Server: YOUR_SERVER_IP
Port: 1080
Username: your_username
Password: your_password
```

### Android

Use [SocksDroid](https://play.google.com/store/apps/details?id=net.typeblog.socks):
```
Server: YOUR_SERVER_IP
Port: 1080
Username: your_username
Password: your_password
```

BadVPN UDP Gateway (127.0.0.1:7300) enables UDP support for mobile apps automatically.

---

## Privacy & Security

### No Logging by Default

The script does **NOT** save any logs by default:
- ❌ No client IP addresses recorded
- ❌ No visited websites tracked
- ❌ No traffic information stored

### Enable Logging (Optional)

If you need logs for debugging, edit the config:
```bash
sudo nano /etc/3proxy/3proxy.cfg
```

Uncomment these lines:
```
log /var/log/3proxy/3proxy-%y%m%d.log D
logformat "L%Y-%m-%d %H:%M:%S %E %U %C:%c %R:%r %O %I %T"
rotate 30
```

Then restart:
```bash
sudo mkdir -p /var/log/3proxy
sudo systemctl restart 3proxy
```

---

## File Locations
```
/usr/local/bin/3proxy              # 3proxy binary
/usr/local/bin/badvpn-udpgw        # BadVPN binary
/etc/3proxy/3proxy.cfg             # Configuration
/etc/3proxy/.users                 # User database (640 permissions)
/etc/systemd/system/3proxy.service # 3proxy systemd service
/etc/systemd/system/udpgw.service  # BadVPN systemd service
```

---

## Troubleshooting

**Service not starting:**
```bash
sudo systemctl status 3proxy
sudo journalctl -u 3proxy -n 50
```

**Port already in use:**
```bash
sudo ss -ltnp | grep :3128
```

**Check firewall rules:**
```bash
sudo iptables -L INPUT -v -n
# or
sudo nft list ruleset
```

---

## FAQ

**HTTP vs SOCKS5?**
- HTTP: Web traffic only (browsers, curl)
- SOCKS5: All TCP/UDP traffic (games, Telegram, torrents)

**Why BadVPN?**
Enables UDP support for mobile SOCKS5 clients. Runs internally on `127.0.0.1:7300`.

**Change ports after installation?**
Reinstall (option 1) — keeps all users and settings.

---

## Uninstall
```bash
sudo bash install-3proxy.sh
# Choose option 7
```

Removes all binaries, configs, services, and firewall rules.

---

## License

MIT License

---

## Tested On

✅ Debian 8-12, Ubuntu 16.04-24.04  
✅ DigitalOcean, Vultr, Hetzner, AWS, OVH

---

**⭐ Star this repo if you find it useful!**