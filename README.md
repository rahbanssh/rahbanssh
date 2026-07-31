# Rahban SSH · راه‌بان

Rahban SSH is a self-hosted, Persian-first SSH account and reseller panel. It
runs customer SSH accounts inside an isolated Docker container and provides a
responsive HTTPS administration panel with traffic accounting, expiry,
connection limits, multi-level reseller credit, service plans, paste-ready NPV
Tunnel configurations, and optional Telegram sales bots.

## Install on a clean VPS

Run as `root` on a public Debian, Ubuntu, Fedora, or other `apt`/`dnf` VPS:

```bash
curl -fsSL https://raw.githubusercontent.com/rahbanssh/rahbanssh/main/install.sh | sudo bash
```

The installer automatically:

- detects the VPS public IPv4 address;
- creates `ssh-panel-IP-WITH-DASHES.sslip.io`;
- installs Docker when it is absent;
- starts Traefik on ports 80/443;
- requests and renews a Let's Encrypt TLS certificate;
- builds the isolated SSH/panel container;
- creates an empty SQLite database and new SSH host keys;
- generates a random administrator master password;
- prints the HTTPS URL, username, password, customer endpoint, and rollback
  command;
- saves the same summary root-only at
  `/opt/ssh-vpn-panel/install-summary.txt`.

No database, password, bot token, user account, SSH key, server address, or
operator identity is bundled in this repository.

### Default ports

- `80/tcp` and `443/tcp`: HTTPS and certificate issuance.
- `2222/tcp`: customer SSH.
- Host `22/tcp`: left untouched for safe VPS administration.
- `127.0.0.1:19080`: emergency loopback access to the panel.

The safe default is customer port 2222 because most VPS hosts already use port
22 for administration. Do not move host SSH or claim port 22 remotely unless
you have tested a second management connection and have console recovery.

Open inbound TCP ports 80, 443, and 2222 in the VPS provider firewall.

### Installation options

Environment variables can customize the installation:

```bash
curl -fsSL https://raw.githubusercontent.com/rahbanssh/rahbanssh/main/install.sh |
  sudo CUSTOMER_SSH_PORT=2022 PANEL_PUBLIC_HOST=panel.example.com bash
```

Supported options:

- `INSTALL_DIR` — default `/opt/ssh-vpn-panel`
- `CUSTOMER_SSH_PORT` — default `2222`
- `PANEL_HOST_PORT` — default `19080`, bound only to loopback
- `PANEL_ADMIN_USERNAME` — default `admin`
- `PANEL_TITLE` — default `Rahban · راه‌بان`
- `CUSTOMER_PUBLIC_HOST` — auto-detected when omitted
- `PANEL_PUBLIC_HOST` — automatic `sslip.io` hostname when omitted

A custom hostname must already resolve to the VPS before installation so
Let's Encrypt can validate it.

## Main features

- Owner, reseller, and nested child-reseller roles.
- Delegated traffic credit with overselling and parent-expiry protection.
- Per-user traffic, exact expiry, active/disabled state, and 1–100 concurrent
  connection limits.
- Quick administration buttons for adding time, quota, and connection slots.
- Persian/Jalali expiry display.
- Custom sales plans with arbitrary name, duration, quota, connection count,
  displayed price, and description.
- Safe plan deletion: removed plans disappear from sales while historical
  orders remain available.
- Live usage and last-IP reporting.
- Copyable host, port, username, password, plain SSH details, and `npvt-ssh://`
  configuration.
- Optional Telegram bot per reseller, numeric Telegram-ID SSH usernames,
  customer self-service password changes, trials, account status, client links,
  purchase requests, permanent agent assignment, and reseller applications.
- Immediate purchase notification to the responsible reseller's configured
  numeric Telegram ID.
- Audit log and root-only application backups.

There is no commission, backdoor, credential reporting, creator account, or
remote access mechanism.

## Reseller accounting

The Owner allocates traffic credit and an expiry date to a reseller. Customer
quotas and credit allocated to child resellers are reserved from that balance.
A branch cannot allocate more traffic than it owns or create service past its
parent's expiry. Each reseller sees only its own branch, users, plans, requests,
usage, audit records, bot settings, and remaining credit.

## Telegram setup

Create a bot with BotFather and paste only its token into **Settings → Telegram**.
Tokens are encrypted at rest using a root-only application secret. Configure a
numeric Telegram ID for order notifications; that Telegram account must start
the bot at least once before the bot can send it a private message.

New bot customers use their immutable numeric Telegram ID as their SSH
username. `/password` changes the VPN password in a private chat and disconnects
old sessions. Phone sharing is optional and used only when a reseller applicant
explicitly presses Telegram's contact-sharing button.

## Security model

- Customer users exist only inside the SSH container.
- The panel container does not mount host `/etc`, host users, the host network,
  or the Docker socket.
- The Traefik proxy mounts the Docker socket read-only for service discovery.
- The panel is published through HTTPS; its direct port is loopback-only.
- Runtime state lives under `/opt/ssh-vpn-panel` with restrictive permissions.
- The generated bootstrap password is a permanent recovery master. A separate
  secondary administrator password can be changed in Settings.
- Customer passwords are stored as Linux password hashes plus authenticated
  encrypted credentials only when configuration redisplay is required.
- The installer refuses occupied ports and does not alter the host SSH daemon,
  firewall, users, or existing Docker projects.

## Manual development start

Copy `.env.example` to `.env`, replace the documentation IP with the server's
real public IP, create the protected directories and password, then run:

```bash
mkdir -p data/backups data/ssh secrets letsencrypt
chmod 700 data data/backups data/ssh secrets
openssl rand -base64 36 > secrets/admin_password
chmod 600 secrets/admin_password
touch letsencrypt/acme.json
chmod 600 letsencrypt/acme.json
docker compose up -d --build
```

## Operations

Show the original installation summary:

```bash
sudo cat /opt/ssh-vpn-panel/install-summary.txt
```

Stop Rahban while preserving all persistent data:

```bash
sudo /opt/ssh-vpn-panel/rollback.sh
```

Start it again:

```bash
cd /opt/ssh-vpn-panel && sudo docker compose up -d
```

Before production use, review [DEPLOYMENT.md](DEPLOYMENT.md) and
[SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
