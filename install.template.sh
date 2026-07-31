#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/ssh-vpn-panel}"
CUSTOMER_SSH_PORT="${CUSTOMER_SSH_PORT:-2222}"
PANEL_HOST_PORT="${PANEL_HOST_PORT:-19080}"
PANEL_ADMIN_USERNAME="${PANEL_ADMIN_USERNAME:-admin}"
PANEL_TITLE="${PANEL_TITLE:-Rahban · راه‌بان}"
started=0

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

on_error() {
  printf '\nInstallation failed. Files were kept in %s for inspection.\n' "$INSTALL_DIR" >&2
  if [[ "$started" == "1" ]]; then
    (cd "$INSTALL_DIR" && docker compose down) >/dev/null 2>&1 || true
  fi
}
trap on_error ERR

[[ "${EUID}" -eq 0 ]] || fail "Run this installer as root or with sudo."
[[ "$CUSTOMER_SSH_PORT" =~ ^[0-9]+$ ]] || fail "CUSTOMER_SSH_PORT must be numeric."
[[ "$PANEL_HOST_PORT" =~ ^[0-9]+$ ]] || fail "PANEL_HOST_PORT must be numeric."
[[ "$PANEL_ADMIN_USERNAME" =~ ^[a-z][a-z0-9_-]{2,31}$ ]] || fail "Invalid panel administrator username."
[[ "$PANEL_TITLE" != *$'\n'* ]] || fail "PANEL_TITLE cannot contain a newline."
(( CUSTOMER_SSH_PORT >= 1 && CUSTOMER_SSH_PORT <= 65535 )) || fail "Invalid customer SSH port."
(( PANEL_HOST_PORT >= 1 && PANEL_HOST_PORT <= 65535 )) || fail "Invalid emergency panel port."
[[ "$CUSTOMER_SSH_PORT" != "22" ]] || fail "Port 22 is reserved for safe VPS administration. Choose another port."

if [[ -f "$INSTALL_DIR/.installed" ]]; then
  printf 'SSH VPN Manager is already installed.\n'
  [[ -f "$INSTALL_DIR/install-summary.txt" ]] && cat "$INSTALL_DIR/install-summary.txt"
  exit 0
fi
if [[ -e "$INSTALL_DIR" ]] && [[ -n "$(find "$INSTALL_DIR" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]]; then
  fail "$INSTALL_DIR already exists and is not an initialized installation."
fi

if command -v apt-get >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl openssl iproute2
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y ca-certificates curl openssl iproute
else
  fail "This installer supports apt- and dnf-based Linux distributions."
fi

if ! command -v docker >/dev/null 2>&1; then
  docker_installer="$(mktemp)"
  curl -fsSL https://get.docker.com -o "$docker_installer"
  sh "$docker_installer"
  rm -f "$docker_installer"
fi
docker info >/dev/null
docker compose version >/dev/null
if docker container inspect ssh-vpn-panel >/dev/null 2>&1; then
  fail "A Docker container named ssh-vpn-panel already exists."
fi
if docker container inspect ssh-vpn-traefik >/dev/null 2>&1; then
  fail "A Docker container named ssh-vpn-traefik already exists."
fi

port_in_use() {
  ss -H -ltn | awk '{print $4}' | grep -Eq ":${1}$"
}
port_in_use 80 && fail "Port 80 is already in use."
port_in_use 443 && fail "Port 443 is already in use."
port_in_use "$CUSTOMER_SSH_PORT" && fail "Customer SSH port $CUSTOMER_SSH_PORT is already in use."
port_in_use "$PANEL_HOST_PORT" && fail "Emergency panel port $PANEL_HOST_PORT is already in use."

public_ip="${CUSTOMER_PUBLIC_HOST:-$(curl -4fsS --max-time 15 https://api.ipify.org)}"
[[ "$public_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "Could not determine a public IPv4 address."
ip_slug="${public_ip//./-}"
panel_host="${PANEL_PUBLIC_HOST:-ssh-panel-${ip_slug}.sslip.io}"
[[ "$panel_host" =~ ^[A-Za-z0-9.-]+$ ]] || fail "PANEL_PUBLIC_HOST is not a valid hostname."

umask 077
mkdir -p "$INSTALL_DIR/data/backups" "$INSTALL_DIR/data/ssh" "$INSTALL_DIR/secrets" "$INSTALL_DIR/letsencrypt"
chmod 700 "$INSTALL_DIR/data" "$INSTALL_DIR/data/backups" "$INSTALL_DIR/data/ssh" "$INSTALL_DIR/secrets"
touch "$INSTALL_DIR/letsencrypt/acme.json"
chmod 600 "$INSTALL_DIR/letsencrypt/acme.json"

PANEL_PY_B64='__PANEL_PY_B64__'
DOCKERFILE_B64='__DOCKERFILE_B64__'
SSHD_CONFIG_B64='__SSHD_CONFIG_B64__'
COMPOSE_B64='__COMPOSE_B64__'

printf '%s' "$PANEL_PY_B64" | base64 -d > "$INSTALL_DIR/panel.py"
printf '%s' "$DOCKERFILE_B64" | base64 -d > "$INSTALL_DIR/Dockerfile"
printf '%s' "$SSHD_CONFIG_B64" | base64 -d > "$INSTALL_DIR/sshd_config"
printf '%s' "$COMPOSE_B64" | base64 -d > "$INSTALL_DIR/docker-compose.yml"
chmod 600 "$INSTALL_DIR/panel.py" "$INSTALL_DIR/Dockerfile" "$INSTALL_DIR/sshd_config" "$INSTALL_DIR/docker-compose.yml"

admin_password="$(openssl rand -base64 36 | tr -d '\n')"
printf '%s\n' "$admin_password" > "$INSTALL_DIR/secrets/admin_password"
chmod 600 "$INSTALL_DIR/secrets/admin_password"

{
  printf 'CUSTOMER_SSH_BIND=0.0.0.0\n'
  printf 'CUSTOMER_SSH_PORT=%s\n' "$CUSTOMER_SSH_PORT"
  printf 'PANEL_HOST_PORT=%s\n' "$PANEL_HOST_PORT"
  printf 'PANEL_ADMIN_USERNAME=%s\n' "$PANEL_ADMIN_USERNAME"
  printf 'PANEL_TITLE=%s\n' "$PANEL_TITLE"
  printf 'PANEL_PUBLIC_HOST=%s\n' "$panel_host"
  printf 'CUSTOMER_PUBLIC_HOST=%s\n' "$public_ip"
} > "$INSTALL_DIR/.env"
chmod 600 "$INSTALL_DIR/.env"

cat > "$INSTALL_DIR/rollback.sh" <<'ROLLBACK'
#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
docker compose down
printf 'SSH VPN Manager stopped. Persistent data was preserved in %s/data.\n' "$SCRIPT_DIR"
ROLLBACK
chmod 700 "$INSTALL_DIR/rollback.sh"

cd "$INSTALL_DIR"
docker compose config --quiet
docker compose up -d --build
started=1

healthy=0
for _ in {1..30}; do
  state="$(docker inspect ssh-vpn-panel --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' 2>/dev/null || true)"
  if [[ "$state" == "healthy" ]]; then
    healthy=1
    break
  fi
  sleep 2
done
[[ "$healthy" == "1" ]] || fail "The panel container did not become healthy."

panel_url="https://${panel_host}"
{
  printf 'Panel URL: %s\n' "$panel_url"
  printf 'Admin username: %s\n' "$PANEL_ADMIN_USERNAME"
  printf 'Admin password: %s\n' "$admin_password"
  printf 'Customer SSH endpoint: %s:%s\n' "$public_ip" "$CUSTOMER_SSH_PORT"
  printf 'Rollback command: %s/rollback.sh\n' "$INSTALL_DIR"
} > "$INSTALL_DIR/install-summary.txt"
chmod 600 "$INSTALL_DIR/install-summary.txt"
touch "$INSTALL_DIR/.installed"
chmod 600 "$INSTALL_DIR/.installed"
trap - ERR

printf '\nSSH VPN Manager installed successfully.\n\n'
cat "$INSTALL_DIR/install-summary.txt"
printf '\nAllow inbound TCP ports 80, 443, and %s in your VPS provider firewall.\n' "$CUSTOMER_SSH_PORT"
printf 'The TLS certificate may take a minute to become available.\n'
