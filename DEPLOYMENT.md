# Deployment and recovery

## Requirements

- A clean public Linux VPS with root or sudo access.
- An `apt`- or `dnf`-based distribution.
- Docker-compatible CPU architecture.
- Free inbound ports 80 and 443.
- A free customer SSH port; the installer defaults to 2222.
- Provider firewall rules allowing TCP 80, 443, and the customer SSH port.

## One-line deployment

```bash
curl -fsSL https://raw.githubusercontent.com/rahbanssh/rahbanssh/main/install.sh | sudo bash
```

For stronger supply-chain control, download a tagged release, review
`install.sh`, and execute the local copy instead of piping directly to Bash.

The installer is intentionally zero-state. It creates a new database, session
secret, credential-encryption key, administrator password, container-local SSH
host keys, and Let's Encrypt state on every new installation.

## Filesystem layout

The default installation directory is `/opt/ssh-vpn-panel`:

- `panel.py`, `Dockerfile`, `sshd_config`, `docker-compose.yml`: installed app
- `.env`: generated server-specific values
- `data/panel.db`: SQLite application database
- `data/ssh/`: persistent container SSH host keys
- `data/backups/`: protected application backups
- `secrets/admin_password`: permanent recovery master password
- `letsencrypt/acme.json`: TLS account and certificate state
- `install-summary.txt`: root-only credentials and endpoints
- `rollback.sh`: stops only this Compose project and preserves data

## Port strategy

Rahban deliberately does not reconfigure the host SSH daemon. Customer SSH is
published on port 2222 by default so administrative SSH can remain on port 22.
Changing host SSH remotely can lock out the VPS and is outside the installer.

If you explicitly want customer SSH on port 22, first move and test host
administration using your provider console and a separate SSH session. Then run
the installer with `CUSTOMER_SSH_PORT=22` only after port 22 is demonstrably
free.

## TLS and hostname

Without `PANEL_PUBLIC_HOST`, the installer derives a hostname such as
`ssh-panel-203-0-113-10.sslip.io`. The `sslip.io` service resolves the embedded
address to the VPS. Traefik uses the HTTP-01 challenge on port 80 and publishes
the panel on HTTPS port 443.

For a custom domain, create its A record first and pass:

```bash
sudo PANEL_PUBLIC_HOST=panel.example.com bash install.sh
```

## Backup and restore

Use **Settings → Create backup** for a root-only archive containing the SQLite
database, application secrets, and container SSH identity. Treat backup files
as credentials.

For a server-level backup, stop the project and copy the complete installation
directory using a root-only encrypted destination:

```bash
cd /opt/ssh-vpn-panel
sudo docker compose down
sudo tar -czf /root/rahban-backup.tar.gz /opt/ssh-vpn-panel
sudo docker compose up -d
```

To stop the deployment without deleting state:

```bash
sudo /opt/ssh-vpn-panel/rollback.sh
```

Do not run `docker compose down -v` unless permanent data removal is intended.

## Upgrade

Back up the installation first. Replace the four application files with a
reviewed release (`panel.py`, `Dockerfile`, `sshd_config`, and
`docker-compose.yml`) and rebuild:

```bash
cd /opt/ssh-vpn-panel
sudo docker compose up -d --build
```

Database migrations are additive and run during panel startup.
