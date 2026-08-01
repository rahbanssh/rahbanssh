#!/usr/bin/env bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/ssh-vpn-panel}"
CUSTOMER_SSH_PORT="${CUSTOMER_SSH_PORT:-22}"
MANAGEMENT_SSH_PORT="${MANAGEMENT_SSH_PORT:-2222}"
MANAGEMENT_SSH_USER="${MANAGEMENT_SSH_USER:-${SUDO_USER:-root}}"
RAHBAN_MOVE_HOST_SSH="${RAHBAN_MOVE_HOST_SSH:-}"
PANEL_HOST_PORT="${PANEL_HOST_PORT:-19080}"
PANEL_ADMIN_USERNAME="${PANEL_ADMIN_USERNAME:-admin}"
PANEL_TITLE="${PANEL_TITLE:-Rahban · راه‌بان}"
started=0
host_ssh_moved=0

print_management_access_box() {
  local red="" reset=""
  if [[ -t 1 ]]; then
    red=$'\033[1;31m'
    reset=$'\033[0m'
  fi
  printf '\n%s' "$red"
  printf '######################################################################\n'
  printf '# 🔴 IMPORTANT: SAVE THIS COMMAND                                    #\n'
  printf '# Your VPS management SSH has moved away from customer port 22.      #\n'
  printf '# From now on, manage this VPS with:                                 #\n'
  printf '#                                                                    #\n'
  printf '  ssh -p %s %s@%s\n' "$MANAGEMENT_SSH_PORT" "$MANAGEMENT_SSH_USER" "$public_ip"
  printf '#                                                                    #\n'
  printf '# Keep this terminal open until the command works in a second one.   #\n'
  printf '######################################################################%s\n\n' "$reset"
}

restore_host_ssh() {
  [[ "$host_ssh_moved" == "1" ]] || return 0
  docker compose -f "$INSTALL_DIR/docker-compose.yml" --env-file "$INSTALL_DIR/.env" down >/dev/null 2>&1 || true
  systemctl stop rahban-management-sshd.service >/dev/null 2>&1 || true
  systemctl disable rahban-management-sshd.service >/dev/null 2>&1 || true
  rm -f /etc/systemd/system/rahban-management-sshd.service
  systemctl daemon-reload >/dev/null 2>&1 || true
  if [[ -f "$INSTALL_DIR/host-ssh-enabled-units" ]]; then
    while IFS= read -r unit; do
      [[ -n "$unit" ]] && systemctl enable "$unit" >/dev/null 2>&1 || true
    done < "$INSTALL_DIR/host-ssh-enabled-units"
  fi
  if [[ -f "$INSTALL_DIR/host-ssh-active-units" ]]; then
    while IFS= read -r unit; do
      [[ -n "$unit" ]] && systemctl start "$unit" >/dev/null 2>&1 || true
    done < "$INSTALL_DIR/host-ssh-active-units"
  fi
  host_ssh_moved=0
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  if [[ "$started" == "1" ]]; then
    (cd "$INSTALL_DIR" && docker compose down) >/dev/null 2>&1 || true
    started=0
  fi
  restore_host_ssh
  exit 1
}

on_error() {
  printf '\nInstallation failed. Files were kept in %s for inspection.\n' "$INSTALL_DIR" >&2
  if [[ "$started" == "1" ]]; then
    (cd "$INSTALL_DIR" && docker compose down) >/dev/null 2>&1 || true
  fi
  restore_host_ssh
}
trap on_error ERR

[[ "${EUID}" -eq 0 ]] || fail "Run this installer as root or with sudo."
[[ "$CUSTOMER_SSH_PORT" =~ ^[0-9]+$ ]] || fail "CUSTOMER_SSH_PORT must be numeric."
[[ "$MANAGEMENT_SSH_PORT" =~ ^[0-9]+$ ]] || fail "MANAGEMENT_SSH_PORT must be numeric."
[[ "$MANAGEMENT_SSH_USER" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || fail "Invalid management SSH username."
[[ "$PANEL_HOST_PORT" =~ ^[0-9]+$ ]] || fail "PANEL_HOST_PORT must be numeric."
[[ "$PANEL_ADMIN_USERNAME" =~ ^[a-z][a-z0-9_-]{2,31}$ ]] || fail "Invalid panel administrator username."
[[ "$PANEL_TITLE" != *$'\n'* ]] || fail "PANEL_TITLE cannot contain a newline."
(( CUSTOMER_SSH_PORT >= 1 && CUSTOMER_SSH_PORT <= 65535 )) || fail "Invalid customer SSH port."
(( MANAGEMENT_SSH_PORT >= 1 && MANAGEMENT_SSH_PORT <= 65535 )) || fail "Invalid management SSH port."
(( PANEL_HOST_PORT >= 1 && PANEL_HOST_PORT <= 65535 )) || fail "Invalid emergency panel port."
[[ "$CUSTOMER_SSH_PORT" != "$MANAGEMENT_SSH_PORT" ]] || fail "Customer and management SSH ports must be different."
if [[ "$CUSTOMER_SSH_PORT" == "22" && "$RAHBAN_MOVE_HOST_SSH" != "1" ]]; then
  fail "Customer SSH uses port 22. First allow TCP ${MANAGEMENT_SSH_PORT} in the provider firewall, verify console recovery, then rerun with RAHBAN_MOVE_HOST_SSH=1."
fi

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
if [[ "$CUSTOMER_SSH_PORT" != "22" ]]; then
  port_in_use "$CUSTOMER_SSH_PORT" && fail "Customer SSH port $CUSTOMER_SSH_PORT is already in use."
fi
if [[ "$CUSTOMER_SSH_PORT" == "22" ]]; then
  port_in_use "$MANAGEMENT_SSH_PORT" && fail "Management SSH port $MANAGEMENT_SSH_PORT is already in use."
fi
port_in_use "$PANEL_HOST_PORT" && fail "Emergency panel port $PANEL_HOST_PORT is already in use."

public_ip="${CUSTOMER_PUBLIC_HOST:-$(curl -4fsS --max-time 15 https://api.ipify.org)}"
[[ "$public_ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || fail "Could not determine a public IPv4 address."
ip_slug="${public_ip//./-}"
panel_host="${PANEL_PUBLIC_HOST:-ssh-panel-${ip_slug}.sslip.io}"
[[ "$panel_host" =~ ^[A-Za-z0-9.-]+$ ]] || fail "PANEL_PUBLIC_HOST is not a valid hostname."

if [[ "$CUSTOMER_SSH_PORT" == "22" ]]; then
  print_management_access_box
fi

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

if [[ "$CUSTOMER_SSH_PORT" == "22" ]]; then
  command -v systemctl >/dev/null 2>&1 || fail "Moving host SSH requires systemd."
  sshd_binary="$(command -v sshd || true)"
  [[ -n "$sshd_binary" ]] || fail "OpenSSH server was not found."
  "$sshd_binary" -t

  : > "$INSTALL_DIR/host-ssh-enabled-units"
  : > "$INSTALL_DIR/host-ssh-active-units"
  for unit in ssh.socket sshd.socket ssh.service sshd.service; do
    canonical_unit="$(systemctl show "$unit" --property=Id --value 2>/dev/null || true)"
    [[ -n "$canonical_unit" ]] || continue
    if systemctl is-enabled "$canonical_unit" >/dev/null 2>&1 \
       && ! grep -qxF "$canonical_unit" "$INSTALL_DIR/host-ssh-enabled-units"; then
      printf '%s\n' "$canonical_unit" >> "$INSTALL_DIR/host-ssh-enabled-units"
    fi
    if systemctl is-active "$canonical_unit" >/dev/null 2>&1 \
       && ! grep -qxF "$canonical_unit" "$INSTALL_DIR/host-ssh-active-units"; then
      printf '%s\n' "$canonical_unit" >> "$INSTALL_DIR/host-ssh-active-units"
    fi
  done
  chmod 600 "$INSTALL_DIR/host-ssh-enabled-units" "$INSTALL_DIR/host-ssh-active-units"
  host_ssh_moved=1

  cat > /etc/systemd/system/rahban-management-sshd.service <<EOF
[Unit]
Description=Rahban dedicated management SSH
After=network.target

[Service]
Type=simple
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755
RuntimeDirectoryPreserve=yes
ExecStartPre=/usr/bin/install -d -m 0755 /run/sshd
ExecStart=${sshd_binary} -D -e -p ${MANAGEMENT_SSH_PORT} -o PidFile=/run/rahban-management-sshd.pid
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 /etc/systemd/system/rahban-management-sshd.service
  systemctl daemon-reload
  systemctl enable --now rahban-management-sshd.service
  for _ in {1..10}; do
    port_in_use "$MANAGEMENT_SSH_PORT" && break
    sleep 1
  done
  port_in_use "$MANAGEMENT_SSH_PORT" || fail "The dedicated management SSH service did not open port $MANAGEMENT_SSH_PORT."

  systemctl stop ssh.socket sshd.socket >/dev/null 2>&1 || true
  systemctl stop ssh.service sshd.service >/dev/null 2>&1 || true
  systemctl disable ssh.socket sshd.socket ssh.service sshd.service >/dev/null 2>&1 || true
  install -d -m 0755 /run/sshd
  for _ in {1..10}; do
    port_in_use 22 || break
    sleep 1
  done
  if port_in_use 22; then
    restore_host_ssh
    fail "Host SSH did not release port 22; the original SSH service was restored."
  fi
fi

cat > "$INSTALL_DIR/rollback.sh" <<'ROLLBACK'
#!/usr/bin/env bash
set -Eeuo pipefail
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
docker compose down
if systemctl list-unit-files rahban-management-sshd.service >/dev/null 2>&1; then
  systemctl stop rahban-management-sshd.service || true
  systemctl disable rahban-management-sshd.service || true
  rm -f /etc/systemd/system/rahban-management-sshd.service
  systemctl daemon-reload
  if [[ -f "$SCRIPT_DIR/host-ssh-enabled-units" ]]; then
    while IFS= read -r unit; do
      [[ -n "$unit" ]] && systemctl enable "$unit" || true
    done < "$SCRIPT_DIR/host-ssh-enabled-units"
  fi
  if [[ -f "$SCRIPT_DIR/host-ssh-active-units" ]]; then
    while IFS= read -r unit; do
      [[ -n "$unit" ]] && systemctl start "$unit" || true
    done < "$SCRIPT_DIR/host-ssh-active-units"
  fi
fi
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
  if [[ "$CUSTOMER_SSH_PORT" == "22" ]]; then
    printf 'VPS management SSH command: ssh -p %s %s@%s\n' "$MANAGEMENT_SSH_PORT" "$MANAGEMENT_SSH_USER" "$public_ip"
  else
    printf 'VPS management SSH: unchanged by Rahban\n'
  fi
  printf 'Rollback command: %s/rollback.sh\n' "$INSTALL_DIR"
} > "$INSTALL_DIR/install-summary.txt"
chmod 600 "$INSTALL_DIR/install-summary.txt"
touch "$INSTALL_DIR/.installed"
chmod 600 "$INSTALL_DIR/.installed"
trap - ERR

printf '\nSSH VPN Manager installed successfully.\n\n'
cat "$INSTALL_DIR/install-summary.txt"
if [[ "$CUSTOMER_SSH_PORT" == "22" ]]; then
  printf '\nAllow inbound TCP ports 80, 443, %s (customers), and %s (VPS management) in your provider firewall.\n' "$CUSTOMER_SSH_PORT" "$MANAGEMENT_SSH_PORT"
  print_management_access_box
else
  printf '\nAllow inbound TCP ports 80, 443, and %s (customers) in your provider firewall.\n' "$CUSTOMER_SSH_PORT"
fi
printf 'The TLS certificate may take a minute to become available.\n'
