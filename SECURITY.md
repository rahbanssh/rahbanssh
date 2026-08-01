# Security policy

## Reporting a vulnerability

Do not publish exploit details, credentials, tokens, IP addresses, database
copies, or user records in a public issue. Send a minimal report to
[rahbanssh@gmail.com](mailto:rahbanssh@gmail.com) without including live
credentials or personal customer data.

## Operator responsibilities

- Review the installer before executing it.
- Keep the VPS, Docker Engine, and images patched.
- Restrict the provider firewall to required ports.
- Keep `/opt/ssh-vpn-panel`, backups, `.env`, and `secrets/` root-only.
- Use a unique secondary administrator password and protect the recovery master.
- Revoke Telegram tokens and rotate passwords after suspected compromise.
- Never publish `panel.db`, `session_secret`, `admin_password`, SSH host keys,
  backup archives, or installation summaries.
- Test restores and management access before changing any SSH listener.
- Allow and verify TCP 2222 through the provider firewall before installing;
  retain emergency console access while moving host SSH.

## Trust boundaries

The SSH/panel container manages only its container-local users. Traefik mounts
the Docker socket read-only for routing discovery; anyone who can modify the
Compose project or Docker daemon is therefore a trusted host administrator.

Traffic accounting uses Linux TCP connection counters and includes encrypted
transport overhead. It is suitable for enforcing service quotas, not for
financial-grade byte metering.
