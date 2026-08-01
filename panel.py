#!/usr/bin/env python3
"""Small, dependency-free SSH account manager for an isolated container."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import html
import http.cookies
import ipaddress
import json
import os
import pwd
import re
import secrets
import signal
import sqlite3
import subprocess
import tarfile
import threading
import time
import traceback
import urllib.parse
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


DATA = Path("/data")
DB_PATH = DATA / "panel.db"
SSH_DIR = DATA / "ssh"
BACKUP_DIR = DATA / "backups"
TITLE = os.environ.get("PANEL_TITLE", "Rahban · راه‌بان")
CUSTOMER_PUBLIC_HOST = os.environ.get("CUSTOMER_PUBLIC_HOST", "127.0.0.1")
CUSTOMER_PUBLIC_PORT = int(os.environ.get("CUSTOMER_PUBLIC_PORT", "22"))
PANEL_PUBLIC_URL = os.environ.get(
    "PANEL_PUBLIC_URL",
    "http://127.0.0.1:8080",
).rstrip("/")
ADMIN_USERNAME = os.environ.get("PANEL_ADMIN_USERNAME", "admin")
REQUIRE_TOTP = os.environ.get("PANEL_REQUIRE_TOTP", "true").lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ADMIN_PASSWORD_FILE = Path(
    os.environ.get("PANEL_ADMIN_PASSWORD_FILE", "/run/secrets/admin_password")
)
INTERVAL = max(1, int(os.environ.get("ACCOUNTING_INTERVAL_SECONDS", "2")))
MAX_CONNECTIONS_PER_USER = 100
USERNAME_RE = re.compile(r"^[a-z][a-z0-9_-]{2,31}$")
SSH_USERNAME_RE = re.compile(r"^(?:[a-z][a-z0-9_-]{2,31}|[0-9]{5,20})$")
STATE_LOCK = threading.RLock()
STOP = threading.Event()
LOGIN_ATTEMPTS: dict[str, list[float]] = {}
SSHD_PROCESS: subprocess.Popen[str] | None = None


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_now() -> str:
    return utcnow().replace(microsecond=0).isoformat()


def run(
    args: list[str],
    *,
    input_text: str | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        input=input_text,
        text=True,
        capture_output=True,
        check=check,
        timeout=20,
    )


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=15000")
    return conn


def initialize_filesystem() -> None:
    Path("/run/sshd").mkdir(parents=True, exist_ok=True, mode=0o755)
    SSH_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(DATA, 0o700)

    if not (SSH_DIR / "ssh_host_ed25519_key").exists():
        run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(SSH_DIR / "ssh_host_ed25519_key"),
            ]
        )
    if not (SSH_DIR / "ssh_host_rsa_key").exists():
        run(
            [
                "ssh-keygen",
                "-q",
                "-t",
                "rsa",
                "-b",
                "3072",
                "-N",
                "",
                "-f",
                str(SSH_DIR / "ssh_host_rsa_key"),
            ]
        )

    group_check = run(["getent", "group", "vpnusers"], check=False)
    if group_check.returncode != 0:
        run(["groupadd", "--system", "vpnusers"])


def initialize_database() -> None:
    with db() as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS admins (
                username TEXT PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash BLOB NOT NULL,
                totp_secret TEXT NOT NULL DEFAULT '',
                role TEXT NOT NULL DEFAULT 'reseller',
                parent_username TEXT NOT NULL DEFAULT '',
                traffic_credit INTEGER NOT NULL DEFAULT 0,
                expires_on TEXT,
                enabled INTEGER NOT NULL DEFAULT 1,
                note TEXT NOT NULL DEFAULT '',
                telegram_token TEXT NOT NULL DEFAULT '',
                telegram_bot_username TEXT NOT NULL DEFAULT '',
                contact_text TEXT NOT NULL DEFAULT '',
                trial_enabled INTEGER NOT NULL DEFAULT 0,
                public_sales_enabled INTEGER NOT NULL DEFAULT 0,
                public_name TEXT NOT NULL DEFAULT '',
                can_create_resellers INTEGER NOT NULL DEFAULT 0,
                telegram_channel TEXT NOT NULL DEFAULT '',
                notification_telegram_id TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                traffic_limit INTEGER NOT NULL DEFAULT 0,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                last_counter INTEGER NOT NULL DEFAULT 0,
                expires_on TEXT,
                max_connections INTEGER NOT NULL DEFAULT 100,
                enabled INTEGER NOT NULL DEFAULT 1,
                note TEXT NOT NULL DEFAULT '',
                last_ip TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL DEFAULT '',
                credential_token TEXT NOT NULL DEFAULT '',
                owner_username TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT 'panel',
                telegram_id TEXT NOT NULL DEFAULT '',
                expires_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT '',
                source_ip TEXT NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS live_sessions (
                endpoint TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                last_total INTEGER NOT NULL DEFAULT 0,
                last_seen TEXT NOT NULL,
                connected_at TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS audit_created_idx
                ON audit_log(created_at DESC);

            CREATE TABLE IF NOT EXISTS telegram_trials (
                owner_username TEXT NOT NULL,
                telegram_id TEXT NOT NULL,
                ssh_username TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(owner_username, telegram_id)
            );

            CREATE TABLE IF NOT EXISTS telegram_bot_state (
                owner_username TEXT PRIMARY KEY,
                update_offset INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS telegram_pending_actions (
                bot_owner TEXT NOT NULL,
                telegram_id TEXT NOT NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL,
                PRIMARY KEY(bot_owner, telegram_id)
            );

            CREATE TABLE IF NOT EXISTS panel_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS telegram_customers (
                bot_owner TEXT NOT NULL,
                telegram_id TEXT NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                telegram_username TEXT NOT NULL DEFAULT '',
                display_name TEXT NOT NULL DEFAULT '',
                assigned_reseller TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY(bot_owner, telegram_id)
            );

            CREATE TABLE IF NOT EXISTS reseller_applications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_owner TEXT NOT NULL,
                telegram_id TEXT NOT NULL,
                phone TEXT NOT NULL DEFAULT '',
                telegram_username TEXT NOT NULL DEFAULT '',
                requested_parent TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                handled_by TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS service_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_username TEXT NOT NULL,
                name TEXT NOT NULL,
                duration_minutes INTEGER NOT NULL,
                traffic_bytes INTEGER NOT NULL,
                max_connections INTEGER NOT NULL DEFAULT 1,
                price_label TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                deleted_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS purchase_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bot_owner TEXT NOT NULL,
                telegram_id TEXT NOT NULL,
                assigned_reseller TEXT NOT NULL,
                plan_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS admins_parent_idx ON admins(parent_username);
            CREATE INDEX IF NOT EXISTS telegram_customer_agent_idx
                ON telegram_customers(assigned_reseller);
            CREATE INDEX IF NOT EXISTS reseller_applications_status_idx
                ON reseller_applications(status, created_at DESC);
            CREATE INDEX IF NOT EXISTS service_plans_owner_idx
                ON service_plans(owner_username, enabled);
            CREATE INDEX IF NOT EXISTS purchase_requests_agent_idx
                ON purchase_requests(assigned_reseller, status, created_at DESC);
            """
        )
        columns = {
            str(row["name"]) for row in conn.execute("PRAGMA table_info(users)")
        }
        if "password_hash" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN password_hash TEXT NOT NULL DEFAULT ''"
            )
        if "credential_token" not in columns:
            conn.execute(
                "ALTER TABLE users ADD COLUMN credential_token TEXT NOT NULL DEFAULT ''"
            )
        if "owner_username" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN owner_username TEXT NOT NULL DEFAULT ''")
        if "source" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN source TEXT NOT NULL DEFAULT 'panel'")
        if "telegram_id" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN telegram_id TEXT NOT NULL DEFAULT ''")
        if "expires_at" not in columns:
            conn.execute("ALTER TABLE users ADD COLUMN expires_at TEXT NOT NULL DEFAULT ''")
        admin_columns = {
            str(row["name"]) for row in conn.execute("PRAGMA table_info(admins)")
        }
        if "totp_secret" not in admin_columns:
            conn.execute(
                "ALTER TABLE admins ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''"
            )
        admin_migrations = {
            "role": "TEXT NOT NULL DEFAULT 'reseller'",
            "parent_username": "TEXT NOT NULL DEFAULT ''",
            "traffic_credit": "INTEGER NOT NULL DEFAULT 0",
            "expires_on": "TEXT",
            "enabled": "INTEGER NOT NULL DEFAULT 1",
            "note": "TEXT NOT NULL DEFAULT ''",
            "telegram_token": "TEXT NOT NULL DEFAULT ''",
            "telegram_bot_username": "TEXT NOT NULL DEFAULT ''",
            "contact_text": "TEXT NOT NULL DEFAULT ''",
            "trial_enabled": "INTEGER NOT NULL DEFAULT 0",
            "public_sales_enabled": "INTEGER NOT NULL DEFAULT 0",
            "public_name": "TEXT NOT NULL DEFAULT ''",
            "can_create_resellers": "INTEGER NOT NULL DEFAULT 0",
            "telegram_channel": "TEXT NOT NULL DEFAULT ''",
            "notification_telegram_id": "TEXT NOT NULL DEFAULT ''",
        }
        for column, declaration in admin_migrations.items():
            if column not in admin_columns:
                conn.execute(f"ALTER TABLE admins ADD COLUMN {column} {declaration}")
        plan_columns = {
            str(row["name"]) for row in conn.execute("PRAGMA table_info(service_plans)")
        }
        if "description" not in plan_columns:
            conn.execute(
                "ALTER TABLE service_plans ADD COLUMN description TEXT NOT NULL DEFAULT ''"
            )
        if "deleted_at" not in plan_columns:
            conn.execute(
                "ALTER TABLE service_plans ADD COLUMN deleted_at TEXT NOT NULL DEFAULT ''"
            )

        existing = conn.execute(
            "SELECT 1 FROM admins WHERE username=?", (ADMIN_USERNAME,)
        ).fetchone()
        if not existing:
            raw = ADMIN_PASSWORD_FILE.read_text(encoding="utf-8").strip()
            if len(raw) < 16:
                raise RuntimeError("Bootstrap administrator password must be 16+ characters")
            salt, digest = hash_password(raw)
            now = iso_now()
            conn.execute(
                """
                INSERT INTO admins(
                  username, salt, password_hash, totp_secret, role,
                  created_at, updated_at)
                VALUES (?, ?, ?, ?, 'owner', ?, ?)
                """,
                (ADMIN_USERNAME, salt, digest, new_totp_secret(), now, now),
            )
        conn.execute(
            "UPDATE admins SET role='owner', enabled=1, parent_username='', can_create_resellers=1 WHERE username=?",
            (ADMIN_USERNAME,),
        )
        conn.execute(
            "UPDATE users SET owner_username=? WHERE owner_username=''",
            (ADMIN_USERNAME,),
        )
        hierarchy_migration = conn.execute(
            "SELECT 1 FROM panel_settings WHERE key='hierarchy_v1_migrated'"
        ).fetchone()
        if not hierarchy_migration:
            conn.execute("UPDATE admins SET can_create_resellers=1 WHERE role='reseller'")
            conn.execute("INSERT INTO panel_settings(key,value) VALUES('hierarchy_v1_migrated','1')")
        row = conn.execute(
            "SELECT totp_secret FROM admins WHERE username=?", (ADMIN_USERNAME,)
        ).fetchone()
        if row and not row["totp_secret"]:
            conn.execute(
                "UPDATE admins SET totp_secret=?, updated_at=? WHERE username=?",
                (new_totp_secret(), iso_now(), ADMIN_USERNAME),
            )
        row = conn.execute(
            "SELECT totp_secret FROM admins WHERE username=?", (ADMIN_USERNAME,)
        ).fetchone()
        if row:
            totp_path = DATA / f"totp_secret_{ADMIN_USERNAME}.txt"
            totp_path.write_text(str(row["totp_secret"]) + "\n", encoding="ascii")
            os.chmod(totp_path, 0o600)
        seeded = conn.execute(
            "SELECT 1 FROM panel_settings WHERE key='default_sales_plans_v1_seeded'"
        ).fetchone()
        if not seeded:
            now = iso_now()
            default_plans = (
                ("روزانه ۱ گیگ", 1440, 1, 1, "۵۰٬۰۰۰ تومان"),
                ("سه‌روزه ۳ گیگ", 4320, 3, 1, "۱۴۲٬۵۰۰ تومان · ۵٪ تخفیف"),
                ("هفتگی ۷ گیگ", 10080, 7, 1, "۳۱۵٬۰۰۰ تومان · ۱۰٪ تخفیف"),
                ("ماهانه ۳۰ گیگ", 43200, 30, 2, "۱٬۲۰۰٬۰۰۰ تومان · ۲۰٪ تخفیف"),
                ("سه‌ماهه ۹۰ گیگ", 129600, 90, 2, "۳٬۱۵۰٬۰۰۰ تومان · ۳۰٪ تخفیف"),
                ("سالانه ۳۶۵ گیگ", 525600, 365, 3, "۹٬۰۰۰٬۰۰۰ تومان · ۵۰٪ تخفیف"),
            )
            for name, minutes, gib, maximum, price in default_plans:
                exists = conn.execute(
                    "SELECT 1 FROM service_plans WHERE owner_username=? AND name=?",
                    (ADMIN_USERNAME, name),
                ).fetchone()
                if not exists:
                    conn.execute(
                        """INSERT INTO service_plans(owner_username,name,duration_minutes,
                        traffic_bytes,max_connections,price_label,enabled,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,1,?,?)""",
                        (ADMIN_USERNAME, name, minutes, gib * 1024**3, maximum, price, now, now),
                    )
            conn.execute(
                "INSERT INTO panel_settings(key,value) VALUES('default_sales_plans_v1_seeded','1')"
            )


def secret_key() -> bytes:
    path = DATA / "session_secret"
    if not path.exists():
        path.write_bytes(secrets.token_bytes(32))
        os.chmod(path, 0o600)
    return path.read_bytes()


def credential_keys() -> tuple[bytes, bytes]:
    master = secret_key()
    encryption_key = hmac.new(
        master, b"ssh-vpn-credential-encryption-v1", hashlib.sha256
    ).digest()
    authentication_key = hmac.new(
        master, b"ssh-vpn-credential-authentication-v1", hashlib.sha256
    ).digest()
    return encryption_key, authentication_key


def credential_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(
            hmac.new(
                key, nonce + counter.to_bytes(8, "big"), hashlib.sha256
            ).digest()
        )
        counter += 1
    return bytes(output[:length])


def encrypt_credential(password: str) -> str:
    plaintext = password.encode("utf-8")
    encryption_key, authentication_key = credential_keys()
    nonce = secrets.token_bytes(16)
    stream = credential_keystream(encryption_key, nonce, len(plaintext))
    ciphertext = bytes(left ^ right for left, right in zip(plaintext, stream))
    tag = hmac.new(
        authentication_key, nonce + ciphertext, hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(nonce + ciphertext + tag).decode("ascii")


def decrypt_credential(token: str) -> str:
    try:
        raw = base64.urlsafe_b64decode(token)
    except (ValueError, TypeError) as exc:
        raise ValueError("Stored credential is invalid") from exc
    if len(raw) < 49:
        raise ValueError("Stored credential is invalid")
    nonce, ciphertext, supplied_tag = raw[:16], raw[16:-32], raw[-32:]
    encryption_key, authentication_key = credential_keys()
    expected_tag = hmac.new(
        authentication_key, nonce + ciphertext, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(expected_tag, supplied_tag):
        raise ValueError("Stored credential authentication failed")
    stream = credential_keystream(encryption_key, nonce, len(ciphertext))
    try:
        return bytes(
            left ^ right for left, right in zip(ciphertext, stream)
        ).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Stored credential is invalid") from exc


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_at(secret: str, timestamp: float | None = None) -> str:
    timestamp = time.time() if timestamp is None else timestamp
    padded = secret.upper() + "=" * (-len(secret) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int(timestamp // 30).to_bytes(8, "big")
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def verify_totp(secret: str, supplied: str) -> bool:
    if not re.fullmatch(r"\d{6}", supplied):
        return False
    now = time.time()
    return any(
        hmac.compare_digest(totp_at(secret, now + drift), supplied)
        for drift in (-30, 0, 30)
    )


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=2**15,
        r=8,
        p=1,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )
    return salt, digest


def check_admin_password(username: str, password: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT salt, password_hash FROM admins WHERE username=?", (username,)
        ).fetchone()
    if not row:
        hash_password(password)
        return False
    _, digest = hash_password(password, bytes(row["salt"]))
    secondary_ok = hmac.compare_digest(digest, bytes(row["password_hash"]))
    master_ok = False
    if username == ADMIN_USERNAME:
        try:
            master = ADMIN_PASSWORD_FILE.read_text(encoding="utf-8").strip()
            master_ok = hmac.compare_digest(master, password)
        except OSError:
            pass
    return secondary_ok or master_ok


def admin_record(username: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM admins WHERE username=?", (username,)
        ).fetchone()


def get_setting(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM panel_settings WHERE key=?", (key,)).fetchone()
    return str(row["value"]) if row else default


def set_setting(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO panel_settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def panel_title() -> str:
    return get_setting("panel_name", TITLE)


def admin_can_login(username: str) -> bool:
    row = admin_record(username)
    return bool(
        row
        and bool(row["enabled"])
        and not expiration_passed(row["expires_on"])
    )


def is_owner(session: dict[str, object]) -> bool:
    return str(session.get("role", "")) == "owner"


def can_create_resellers(session: dict[str, object]) -> bool:
    if is_owner(session):
        return True
    row = admin_record(str(session.get("u", "")))
    return bool(row and row["can_create_resellers"])


def admin_descendants(username: str, include_self: bool = False) -> list[str]:
    with db() as conn:
        rows = conn.execute(
            """
            WITH RECURSIVE tree(username) AS (
              SELECT username FROM admins WHERE parent_username=?
              UNION ALL
              SELECT a.username FROM admins a JOIN tree t ON a.parent_username=t.username
            ) SELECT username FROM tree
            """,
            (username,),
        ).fetchall()
    result = [str(row["username"]) for row in rows]
    return ([username] + result) if include_self else result


def admin_ancestors(username: str, include_self: bool = True) -> list[str]:
    result = [username] if include_self else []
    seen = {username}
    current = username
    while current:
        row = admin_record(current)
        parent = str(row["parent_username"] or "") if row else ""
        if not parent or parent in seen:
            break
        result.append(parent)
        seen.add(parent)
        current = parent
    return result


def plans_for_agent(username: str) -> list[sqlite3.Row]:
    owners = admin_ancestors(username)
    placeholders = ",".join("?" for _ in owners)
    with db() as conn:
        return conn.execute(
            f"SELECT * FROM service_plans WHERE enabled=1 AND deleted_at='' AND owner_username IN ({placeholders}) ORDER BY CASE WHEN owner_username=? THEN 0 ELSE 1 END,id DESC LIMIT 20",
            tuple(owners) + (username,),
        ).fetchall()


def can_manage_reseller(session: dict[str, object], username: str) -> bool:
    if is_owner(session):
        return username != ADMIN_USERNAME
    return username in admin_descendants(str(session["u"]))


def direct_resellers(username: str) -> list[sqlite3.Row]:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM admins WHERE role='reseller' AND parent_username=? ORDER BY username",
            (username,),
        ).fetchall()


def reseller_allocation(
    username: str,
    exclude_user: str = "",
    exclude_child: str = "",
) -> tuple[int, int, int]:
    with db() as conn:
        admin = conn.execute(
            "SELECT traffic_credit,role FROM admins WHERE username=?", (username,)
        ).fetchone()
        if not admin:
            raise ValueError("Reseller not found")
        user_allocated = conn.execute(
            """
            SELECT COALESCE(SUM(traffic_limit),0) FROM users
            WHERE owner_username=? AND username<>?
            """,
            (username, exclude_user),
        ).fetchone()[0]
        child_allocated = conn.execute(
            "SELECT COALESCE(SUM(traffic_credit),0) FROM admins WHERE parent_username=? AND username<>?",
            (username, exclude_child),
        ).fetchone()[0]
    credit = int(admin["traffic_credit"])
    allocated = int(user_allocated) + int(child_allocated)
    if admin["role"] == "owner":
        return credit, allocated, 2**63 - 1
    return credit, allocated, max(0, credit - allocated)


def validate_child_allocation(
    parent_username: str,
    credit: int,
    expires_on: str,
    exclude_child: str = "",
) -> None:
    parent = admin_record(parent_username)
    if not parent or not bool(parent["enabled"]) or expiration_passed(parent["expires_on"]):
        raise ValueError("Parent reseller is disabled, expired or missing")
    if credit <= 0:
        raise ValueError("Reseller credit must be greater than zero")
    if parent["role"] != "owner":
        _, _, remaining = reseller_allocation(parent_username, exclude_child=exclude_child)
        if credit > remaining:
            raise ValueError(f"Not enough parent credit; remaining is {human_bytes(remaining)}")
        if parent["expires_on"] and expires_on > str(parent["expires_on"]):
            raise ValueError("Child reseller expiry cannot exceed parent expiry")


def validate_reseller_allocation(
    owner_username: str, traffic_limit: int, expires_on: str | None,
    exclude_user: str = "",
) -> None:
    row = admin_record(owner_username)
    if not row:
        raise ValueError("Reseller not found")
    if row["role"] == "owner":
        return
    if not bool(row["enabled"]) or expiration_passed(row["expires_on"]):
        raise ValueError("Reseller is disabled or expired")
    if traffic_limit <= 0:
        raise ValueError("Reseller customers must have a traffic limit")
    _, _, remaining = reseller_allocation(owner_username, exclude_user)
    if traffic_limit > remaining:
        raise ValueError(
            f"Not enough reseller credit; remaining credit is {human_bytes(remaining)}"
        )
    if row["expires_on"] and (
        not expires_on or expires_on > str(row["expires_on"])
    ):
        raise ValueError("Customer expiry cannot exceed reseller expiry")


def visible_user(session: dict[str, object], username: str) -> sqlite3.Row | None:
    with db() as conn:
        if is_owner(session):
            return conn.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            ).fetchone()
        return conn.execute(
            "SELECT * FROM users WHERE username=? AND owner_username=?",
            (username, str(session["u"])),
        ).fetchone()


def check_admin_totp(username: str, supplied: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT totp_secret FROM admins WHERE username=?", (username,)
        ).fetchone()
    return bool(row and row["totp_secret"] and verify_totp(row["totp_secret"], supplied))


def audit(
    actor: str,
    action: str,
    target: str = "",
    detail: str = "",
    source_ip: str = "",
) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO audit_log(created_at, actor, action, target, detail, source_ip)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (iso_now(), actor, action, target, detail[:1000], source_ip),
        )


def sign_session(username: str) -> str:
    payload = {
        "u": username,
        "exp": int(time.time()) + 8 * 3600,
        "csrf": secrets.token_urlsafe(24),
        "n": secrets.token_urlsafe(12),
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=")
    signature = hmac.new(secret_key(), encoded, hashlib.sha256).digest()
    return (
        encoded.decode()
        + "."
        + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    )


def verify_session(token: str) -> dict[str, object] | None:
    try:
        encoded, supplied = token.split(".", 1)
        encoded_b = encoded.encode()
        supplied_b = base64.urlsafe_b64decode(supplied + "=" * (-len(supplied) % 4))
        expected = hmac.new(secret_key(), encoded_b, hashlib.sha256).digest()
        if not hmac.compare_digest(expected, supplied_b):
            return None
        raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
        payload = json.loads(raw)
        if int(payload["exp"]) < int(time.time()):
            return None
        if not isinstance(payload.get("u"), str) or not isinstance(
            payload.get("csrf"), str
        ):
            return None
        return payload
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return None


def human_bytes(value: int) -> str:
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024 or unit == "TiB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{value} B"


def gregorian_to_jalali(year: int, month: int, day: int) -> tuple[int, int, int]:
    month_days = (0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)
    adjusted_year = year + 1 if month > 2 else year
    days = (
        355666
        + 365 * year
        + (adjusted_year + 3) // 4
        - (adjusted_year + 99) // 100
        + (adjusted_year + 399) // 400
        + day
        + month_days[month - 1]
    )
    jalali_year = -1595 + 33 * (days // 12053)
    days %= 12053
    jalali_year += 4 * (days // 1461)
    days %= 1461
    if days > 365:
        jalali_year += (days - 1) // 365
        days = (days - 1) % 365
    if days < 186:
        jalali_month = 1 + days // 31
        jalali_day = 1 + days % 31
    else:
        jalali_month = 7 + (days - 186) // 30
        jalali_day = 1 + (days - 186) % 30
    return jalali_year, jalali_month, jalali_day


def jalali_datetime(value: str | None, *, include_time: bool = True) -> str:
    if not value:
        return "بدون انقضا"
    raw = str(value)
    try:
        parsed: dt.datetime | dt.date
        if "T" in raw or " " in raw:
            parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        else:
            parsed = dt.date.fromisoformat(raw)
        jy, jm, jd = gregorian_to_jalali(parsed.year, parsed.month, parsed.day)
        result = f"{jy:04d}/{jm:02d}/{jd:02d}"
        if include_time and isinstance(parsed, dt.datetime):
            result += f" · {parsed.hour:02d}:{parsed.minute:02d} UTC"
        return result
    except ValueError:
        return raw


def human_duration(minutes: int) -> str:
    if minutes % 525600 == 0:
        return f"{minutes // 525600} سال"
    if minutes % 43200 == 0:
        return f"{minutes // 43200} ماه"
    if minutes % 10080 == 0:
        return f"{minutes // 10080} هفته"
    if minutes % 1440 == 0:
        return f"{minutes // 1440} روز"
    if minutes % 60 == 0:
        return f"{minutes // 60} ساعت"
    return f"{minutes} دقیقه"


def parse_limit_gb(value: str) -> int:
    value = value.strip()
    if not value:
        return 0
    amount = float(value)
    if amount < 0 or amount > 100000:
        raise ValueError("Traffic limit must be between 0 and 100000 GiB")
    return int(amount * 1024**3)


def expiration_passed(expires_on: str | None) -> bool:
    if not expires_on:
        return False
    try:
        return dt.date.fromisoformat(expires_on) < utcnow().date()
    except ValueError:
        return True


def timestamp_expired(expires_at: str | None) -> bool:
    if not expires_at:
        return False
    try:
        parsed = dt.datetime.fromisoformat(str(expires_at).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        return parsed <= utcnow()
    except ValueError:
        return True


def account_should_work(row: sqlite3.Row) -> tuple[bool, str]:
    owner = str(row["owner_username"] or ADMIN_USERNAME)
    seen: set[str] = set()
    while owner and owner not in seen:
        seen.add(owner)
        owner_row = admin_record(owner)
        if not owner_row or not bool(owner_row["enabled"]):
            return False, "group disabled"
        if expiration_passed(owner_row["expires_on"]):
            return False, "group expired"
        owner = str(owner_row["parent_username"] or "")
    if not bool(row["enabled"]):
        return False, "disabled"
    if row["expires_at"] and timestamp_expired(str(row["expires_at"])):
        return False, "expired"
    if expiration_passed(row["expires_on"]):
        return False, "expired"
    limit = int(row["traffic_limit"])
    if limit and int(row["used_bytes"]) >= limit:
        return False, "quota reached"
    return True, "active"


def passwd_status(username: str) -> str:
    result = run(["passwd", "-S", username], check=False)
    if result.returncode != 0:
        return "missing"
    fields = result.stdout.split()
    return fields[1] if len(fields) > 1 else "unknown"


def lock_account(username: str) -> None:
    if passwd_status(username) == "P":
        run(["usermod", "--lock", username], check=False)


def unlock_account(username: str) -> None:
    if passwd_status(username) == "L":
        run(["usermod", "--unlock", username], check=False)


def set_unix_password(username: str, password: str) -> None:
    if not password:
        raise ValueError("Customer password cannot be empty")
    if len(password) > 1024:
        raise ValueError("Customer password is too long")
    if "\n" in password or ":" in password:
        raise ValueError("Password cannot contain a newline or colon")
    run(["chpasswd"], input_text=f"{username}:{password}\n")


def unix_password_hash(username: str) -> str:
    for line in Path("/etc/shadow").read_text(encoding="utf-8").splitlines():
        fields = line.split(":")
        if fields and fields[0] == username and len(fields) > 1:
            return fields[1]
    raise RuntimeError(f"Password hash unavailable for {username}")


def set_unix_password_hash(username: str, password_hash: str) -> None:
    if not password_hash or "\n" in password_hash or ":" in password_hash:
        raise ValueError("Stored customer password hash is invalid")
    run(["chpasswd", "--encrypted"], input_text=f"{username}:{password_hash}\n")


def create_unix_user(username: str, password: str) -> str:
    if not SSH_USERNAME_RE.fullmatch(username):
        raise ValueError(
            "Username must be a valid panel name or a numeric Telegram ID"
        )
    try:
        pwd.getpwnam(username)
    except KeyError:
        pass
    else:
        raise ValueError("That username already exists")
    useradd_command = ["useradd"]
    if username.isdigit():
        useradd_command.append("--badname")
    run(
        useradd_command + [
            "--no-create-home",
            "--gid",
            "vpnusers",
            "--shell",
            "/usr/sbin/nologin",
            username,
        ]
    )
    try:
        set_unix_password(username, password)
    except Exception:
        run(["userdel", username], check=False)
        raise
    return unix_password_hash(username)


def restore_unix_users() -> None:
    with db() as conn:
        rows = conn.execute(
            "SELECT username, password_hash FROM users ORDER BY created_at"
        ).fetchall()
    for row in rows:
        username = str(row["username"])
        try:
            pwd.getpwnam(username)
            continue
        except KeyError:
            pass
        password_hash = str(row["password_hash"])
        if not password_hash:
            print(
                f"panel: cannot restore {username}; stored password hash is missing",
                flush=True,
            )
            continue
        useradd_command = ["useradd"]
        if username.isdigit():
            useradd_command.append("--badname")
        run(
            useradd_command + [
                "--no-create-home",
                "--gid",
                "vpnusers",
                "--shell",
                "/usr/sbin/nologin",
                username,
            ]
        )
        set_unix_password_hash(username, password_hash)


def migrate_legacy_telegram_usernames() -> None:
    with db() as conn:
        rows = conn.execute(
            "SELECT username,telegram_id,credential_token FROM users WHERE telegram_id<>'' ORDER BY created_at"
        ).fetchall()
    for row in rows:
        old_username = str(row["username"])
        telegram_id = str(row["telegram_id"])
        try:
            new_username = telegram_ssh_username(telegram_id)
        except ValueError:
            continue
        if old_username == new_username:
            continue
        with db() as conn:
            collision = conn.execute("SELECT 1 FROM users WHERE username=?", (new_username,)).fetchone()
        if collision or not row["credential_token"]:
            print(f"panel: cannot migrate legacy Telegram user {old_username}", flush=True)
            continue
        password = decrypt_credential(str(row["credential_token"]))
        try:
            new_hash = create_unix_user(new_username, password)
            try:
                with db() as conn:
                    conn.execute("DELETE FROM live_sessions WHERE username=?", (old_username,))
                    conn.execute(
                        "UPDATE users SET username=?,password_hash=?,updated_at=? WHERE username=?",
                        (new_username,new_hash,iso_now(),old_username),
                    )
                    conn.execute(
                        "UPDATE telegram_trials SET ssh_username=? WHERE ssh_username=?",
                        (new_username,old_username),
                    )
            except Exception:
                delete_unix_user(new_username)
                raise
            delete_unix_user(old_username)
            audit("system", "telegram.username_migrate", new_username, old_username)
            print(f"panel: migrated Telegram user {old_username} -> {new_username}", flush=True)
        except Exception as exc:
            print(f"panel: Telegram username migration failed for {old_username}: {type(exc).__name__}", flush=True)


def delete_unix_user(username: str) -> None:
    disconnect_user(username)
    run(["userdel", username], check=False)


def user_processes() -> dict[str, list[dict[str, object]]]:
    result = run(
        ["ps", "-eo", "uid=,pid=,etimes=,comm=,args="],
        check=False,
    )
    found: dict[str, list[dict[str, object]]] = {}
    if result.returncode != 0:
        return found
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 4)
        if len(parts) < 5:
            continue
        uid_text, pid, elapsed, command, args = parts
        if command != "sshd":
            continue
        try:
            uid = int(uid_text)
            if uid == 0:
                continue
            user = pwd.getpwuid(uid).pw_name
        except (ValueError, KeyError):
            continue
        found.setdefault(user, []).append(
            {
                "pid": int(pid),
                "elapsed": int(elapsed),
                "args": args,
            }
        )
    return found


def disconnect_user(username: str) -> None:
    for process in user_processes().get(username, []):
        try:
            os.kill(int(process["pid"]), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass


def endpoint_key(address: str, port: str | int) -> str:
    address = address.strip("[]")
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def normalize_endpoint(value: str) -> str:
    value = value.strip()
    if value.startswith("[") and "]:" in value:
        address, port = value[1:].rsplit("]:", 1)
        return endpoint_key(address, port)
    address, port = value.rsplit(":", 1)
    return endpoint_key(address, port)


def read_tcp_counters() -> dict[str, int]:
    result = run(
        [
            "ss",
            "-H",
            "-t",
            "-i",
            "-n",
            "state",
            "established",
            "(",
            "sport",
            "=",
            ":22",
            ")",
        ],
        check=False,
    )
    if result.returncode != 0:
        return {}
    counters: dict[str, int] = {}
    current_endpoint = ""
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not line[:1].isspace():
            fields = stripped.split()
            if len(fields) >= 4:
                try:
                    current_endpoint = normalize_endpoint(fields[3])
                except ValueError:
                    current_endpoint = ""
            continue
        if not current_endpoint:
            continue
        received = re.search(r"\bbytes_received:(\d+)", stripped)
        acknowledged = re.search(r"\bbytes_acked:(\d+)", stripped)
        sent = re.search(r"\bbytes_sent:(\d+)", stripped)
        outbound = acknowledged or sent
        if received and outbound:
            counters[current_endpoint] = int(received.group(1)) + int(
                outbound.group(1)
            )
    return counters


def sample_accounting() -> None:
    counters = read_tcp_counters()
    now = iso_now()
    stale_before = (utcnow() - dt.timedelta(minutes=2)).replace(
        microsecond=0
    ).isoformat()
    with STATE_LOCK, db() as conn:
        sessions = conn.execute("SELECT * FROM live_sessions").fetchall()
        for session in sessions:
            endpoint = str(session["endpoint"])
            if endpoint not in counters:
                continue
            current = counters[endpoint]
            previous = int(session["last_total"])
            delta = current - previous if current >= previous else current
            conn.execute(
                """
                UPDATE users SET used_bytes=used_bytes+?, updated_at=?
                WHERE username=?
                """,
                (max(0, delta), now, session["username"]),
            )
            conn.execute(
                """
                UPDATE live_sessions SET last_total=?, last_seen=?
                WHERE endpoint=?
                """,
                (current, now, endpoint),
            )
        conn.execute(
            "DELETE FROM live_sessions WHERE last_seen < ?", (stale_before,)
        )


def reconcile_accounts() -> None:
    processes = user_processes()
    with STATE_LOCK, db() as conn:
        rows = conn.execute("SELECT * FROM users").fetchall()
        for row in rows:
            username = str(row["username"])
            allowed, _ = account_should_work(row)
            if allowed:
                unlock_account(username)
            else:
                lock_account(username)
                disconnect_user(username)
                continue

            maximum = max(1, int(row["max_connections"]))
            active = sorted(
                processes.get(username, []),
                key=lambda item: int(item["elapsed"]),
                reverse=True,
            )
            for extra in active[maximum:]:
                try:
                    os.kill(int(extra["pid"]), signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass


def make_backup(actor: str = "system", source_ip: str = "") -> Path:
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    temp_db = DATA / f".panel-{stamp}.db"
    with sqlite3.connect(DB_PATH) as source, sqlite3.connect(temp_db) as target:
        source.backup(target)
    archive = BACKUP_DIR / f"ssh-vpn-backup-{stamp}.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(temp_db, arcname="panel.db")
        tar.add(SSH_DIR, arcname="ssh")
        for protected_name in ("session_secret", f"totp_secret_{ADMIN_USERNAME}.txt"):
            protected_path = DATA / protected_name
            if protected_path.exists():
                tar.add(protected_path, arcname=protected_name)
    temp_db.unlink(missing_ok=True)
    os.chmod(archive, 0o600)
    audit(actor, "backup.create", archive.name, source_ip=source_ip)
    return archive


def telegram_api(token: str, method: str, values: dict[str, object] | None = None, timeout: int = 10) -> object:
    url = f"https://api.telegram.org/bot{token}/{method}"
    data = urllib.parse.urlencode(values or {}).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))
    if not payload.get("ok"):
        raise ValueError(f"Telegram API rejected {method}")
    return payload.get("result")


def base36(value: int) -> str:
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
    if value == 0:
        return "0"
    output = ""
    while value:
        value, remainder = divmod(value, 36)
        output = alphabet[remainder] + output
    return output


def normalize_phone_username(phone: str, telegram_id: str) -> str:
    digits = "".join(character for character in phone if character.isdigit())
    if len(digits) < 7:
        raise ValueError("شماره تماس معتبر نیست")
    base = ("u" + digits)[-31:]
    with db() as conn:
        row = conn.execute("SELECT telegram_id FROM users WHERE username=?", (base,)).fetchone()
    if row and str(row["telegram_id"]) != telegram_id:
        base = (base[:25] + base36(int(telegram_id))[-6:])[:32]
    return base


def telegram_ssh_username(telegram_id: str) -> str:
    value = str(telegram_id).strip()
    if not value.isdigit() or len(value) < 5 or len(value) > 20:
        raise ValueError("شناسه عددی تلگرام معتبر نیست")
    return value


def telegram_customer(bot_owner: str, telegram_id: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            "SELECT * FROM telegram_customers WHERE bot_owner=? AND telegram_id=?",
            (bot_owner, telegram_id),
        ).fetchone()


def upsert_telegram_customer(
    bot_owner: str,
    telegram_id: str,
    sender: dict[str, object],
    phone: str = "",
) -> sqlite3.Row:
    telegram_username = str(sender.get("username") or "")[:64]
    display_name = " ".join(
        part for part in (str(sender.get("first_name") or ""), str(sender.get("last_name") or "")) if part
    )[:120]
    now = iso_now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO telegram_customers(
              bot_owner,telegram_id,phone,telegram_username,display_name,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?)
            ON CONFLICT(bot_owner,telegram_id) DO UPDATE SET
              phone=CASE WHEN excluded.phone<>'' THEN excluded.phone ELSE telegram_customers.phone END,
              telegram_username=excluded.telegram_username,
              display_name=excluded.display_name,
              updated_at=excluded.updated_at
            """,
            (bot_owner, telegram_id, phone, telegram_username, display_name, now, now),
        )
        return conn.execute(
            "SELECT * FROM telegram_customers WHERE bot_owner=? AND telegram_id=?",
            (bot_owner, telegram_id),
        ).fetchone()


def active_sales_agents(bot_owner: str) -> list[sqlite3.Row]:
    candidates = set(admin_descendants(bot_owner, include_self=True))
    if not candidates:
        return []
    placeholders = ",".join("?" for _ in candidates)
    with db() as conn:
        rows = conn.execute(
            f"""SELECT a.*,
              (SELECT COUNT(*) FROM telegram_customers c WHERE c.assigned_reseller=a.username) AS assigned_count
              FROM admins a WHERE a.username IN ({placeholders})
              AND a.enabled=1 AND a.public_sales_enabled=1
              ORDER BY assigned_count,a.username""",
            tuple(candidates),
        ).fetchall()
    return [row for row in rows if not expiration_passed(row["expires_on"])]


def assigned_sales_agent(bot_owner: str, telegram_id: str) -> sqlite3.Row | None:
    customer = telegram_customer(bot_owner, telegram_id)
    if customer and customer["assigned_reseller"]:
        row = admin_record(str(customer["assigned_reseller"]))
        if row and bool(row["enabled"]) and not expiration_passed(row["expires_on"]):
            return row
    agents = active_sales_agents(bot_owner)
    if not agents:
        fallback = admin_record(bot_owner)
        agents = [fallback] if fallback else []
    if not agents:
        return None
    selected = agents[0]
    with db() as conn:
        conn.execute(
            "UPDATE telegram_customers SET assigned_reseller=?,updated_at=? WHERE bot_owner=? AND telegram_id=? AND assigned_reseller=''",
            (selected["username"], iso_now(), bot_owner, telegram_id),
        )
    customer = telegram_customer(bot_owner, telegram_id)
    return admin_record(str(customer["assigned_reseller"])) if customer else selected


def telegram_trial(owner: str, telegram_id: str) -> tuple[str, str, bool, str]:
    with db() as conn:
        prior = conn.execute(
            "SELECT ssh_username FROM telegram_trials WHERE owner_username=? AND telegram_id=?",
            (owner, telegram_id),
        ).fetchone()
        if prior:
            user = conn.execute(
                "SELECT username,credential_token,owner_username FROM users WHERE username=?",
                (prior["ssh_username"],),
            ).fetchone()
            if user and user["credential_token"]:
                return (str(user["username"]), decrypt_credential(str(user["credential_token"])),
                        False, str(user["owner_username"]))
            raise ValueError("Your trial has already been used")
    customer = telegram_customer(owner, telegram_id)
    if not customer:
        raise ValueError("ابتدا ربات را با /start فعال کنید")
    agent = assigned_sales_agent(owner, telegram_id)
    if not agent:
        raise ValueError("در حال حاضر نماینده فعالی وجود ندارد")
    agent_username = str(agent["username"])
    username = telegram_ssh_username(telegram_id)
    with db() as conn:
        existing_user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if existing_user:
            if str(existing_user["telegram_id"]) != telegram_id or not existing_user["credential_token"]:
                raise ValueError("این شناسه تلگرام قبلاً ثبت شده است")
            conn.execute("""INSERT INTO telegram_trials(owner_username,telegram_id,ssh_username,created_at)
              VALUES(?,?,?,?) ON CONFLICT(owner_username,telegram_id) DO UPDATE SET ssh_username=excluded.ssh_username""",
              (owner,telegram_id,username,iso_now()))
            return (username,decrypt_credential(str(existing_user["credential_token"])),False,
                    str(existing_user["owner_username"]))
    password = secrets.token_urlsafe(12)
    traffic_limit = 1024**3
    expires_at = (utcnow() + dt.timedelta(days=1)).replace(microsecond=0).isoformat()
    expires = dt.datetime.fromisoformat(expires_at).date().isoformat()
    validate_reseller_allocation(agent_username, traffic_limit, expires)
    with STATE_LOCK:
        customer_hash = create_unix_user(username, password)
        try:
            with db() as conn:
                now = iso_now()
                conn.execute(
                    """
                    INSERT INTO users(username,traffic_limit,expires_on,expires_at,max_connections,
                      enabled,note,password_hash,credential_token,owner_username,source,
                      telegram_id,created_at,updated_at)
                    VALUES(?,?,?,?,1,1,?,?,?,?,?,?,?,?)
                    """,
                    (username, traffic_limit, expires, expires_at, "Telegram 1-day trial",
                     customer_hash, encrypt_credential(password), agent_username, "telegram",
                     telegram_id, now, now),
                )
                conn.execute(
                    "INSERT INTO telegram_trials(owner_username,telegram_id,ssh_username,created_at) VALUES(?,?,?,?)",
                    (owner, telegram_id, username, now),
                )
            reconcile_accounts()
        except Exception:
            delete_unix_user(username)
            raise
    audit(f"telegram:{owner}", "trial.create", username, telegram_id)
    return username, password, True, agent_username


def telegram_menu() -> str:
    return json.dumps({"inline_keyboard": [
        [
            {"text": "🎁 دریافت اکانت و کانفیگ", "callback_data": "get"},
        ],
        [
            {"text": "👤 حساب من", "callback_data": "account"},
            {"text": "🧑‍💼 نماینده من", "callback_data": "agent"},
        ],
        [
            {"text": "🔑 تغییر رمز VPN", "callback_data": "password"},
        ],
        [
            {"text": "🛍 نمایندگان فعال", "callback_data": "agents"},
            {"text": "📈 درخواست پنل فروش", "callback_data": "reseller"},
        ],
        [
            {"text": "🧾 پلن‌های فروش", "callback_data": "plans"},
            {"text": "📲 نرم‌افزارهای اتصال", "callback_data": "clients"},
        ],
        [
            {"text": "☎️ تماس با مدیر", "callback_data": "contact"},
            {"text": "❓ راهنما", "callback_data": "help"},
        ],
    ]}, ensure_ascii=False)


def telegram_contact_keyboard() -> str:
    return json.dumps({
        "keyboard": [[{"text": "📱 ثبت شماره تماس من", "request_contact": True}]],
        "resize_keyboard": True,
        "one_time_keyboard": True,
        "input_field_placeholder": "برای ادامه شماره تماس را ثبت کنید",
    }, ensure_ascii=False)


def telegram_agents_keyboard(agents: list[sqlite3.Row]) -> str:
    buttons = []
    for agent in agents[:20]:
        label = str(agent["public_name"] or agent["username"])
        buttons.append([{"text": f"🧑‍💼 {label}", "callback_data": f"pick:{agent['username']}"}])
    buttons.append([{"text": "↩️ بازگشت به منو", "callback_data": "help"}])
    return json.dumps({"inline_keyboard": buttons}, ensure_ascii=False)


def telegram_plans_keyboard(plans: list[sqlite3.Row]) -> str:
    buttons = [[{"text": f"درخواست {str(plan['name'])}", "callback_data": f"buy:{plan['id']}"}] for plan in plans[:20]]
    buttons.append([{"text": "↩️ بازگشت به منو", "callback_data": "help"}])
    return json.dumps({"inline_keyboard": buttons}, ensure_ascii=False)


def telegram_reply(
    token: str,
    chat_id: str,
    text_value: str,
    *,
    menu: bool = False,
    reply_markup: str = "",
) -> None:
    values: dict[str, object] = {"chat_id": chat_id, "text": text_value}
    if reply_markup:
        values["reply_markup"] = reply_markup
    elif menu:
        values["reply_markup"] = telegram_menu()
    telegram_api(token, "sendMessage", values, timeout=12)


def telegram_user(bot_owner: str, telegram_id: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute(
            """SELECT u.* FROM telegram_trials t JOIN users u ON u.username=t.ssh_username
            WHERE t.owner_username=? AND t.telegram_id=?""",
            (bot_owner, telegram_id),
        ).fetchone()


def set_telegram_pending_action(bot_owner: str, telegram_id: str, action: str) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO telegram_pending_actions(bot_owner,telegram_id,action,created_at)
            VALUES(?,?,?,?) ON CONFLICT(bot_owner,telegram_id) DO UPDATE SET
            action=excluded.action,created_at=excluded.created_at""",
            (bot_owner, telegram_id, action, iso_now()),
        )


def clear_telegram_pending_action(bot_owner: str, telegram_id: str) -> None:
    with db() as conn:
        conn.execute(
            "DELETE FROM telegram_pending_actions WHERE bot_owner=? AND telegram_id=?",
            (bot_owner, telegram_id),
        )


def handle_telegram_update(owner: sqlite3.Row, token: str, update: dict[str, object]) -> None:
    callback = update.get("callback_query")
    callback_command = ""
    if isinstance(callback, dict):
        callback_command = str(callback.get("data") or "").strip().lower()
        callback_id = str(callback.get("id") or "")
        if callback_id:
            telegram_api(token, "answerCallbackQuery", {"callback_query_id": callback_id}, timeout=8)
        message = callback.get("message")
        sender = callback.get("from")
    else:
        message = update.get("message")
        sender = message.get("from") if isinstance(message, dict) else None
    if not isinstance(message, dict):
        return
    chat = message.get("chat")
    if not isinstance(chat, dict) or not isinstance(sender, dict):
        return
    chat_id = str(chat.get("id", ""))
    private_chat = str(chat.get("type") or "private") == "private"
    telegram_id = str(sender.get("id", ""))
    bot_owner = str(owner["username"])
    shared_contact = message.get("contact")
    if isinstance(shared_contact, dict):
        shared_user_id = str(shared_contact.get("user_id") or "")
        if shared_user_id and shared_user_id != telegram_id:
            telegram_reply(token, chat_id, "لطفاً فقط شماره متعلق به حساب خودتان را ارسال کنید.")
            return
        phone = str(shared_contact.get("phone_number") or "")[:32]
        customer = upsert_telegram_customer(bot_owner, telegram_id, sender, phone)
        with db() as conn:
            conn.execute(
                "UPDATE reseller_applications SET phone=?,updated_at=? WHERE bot_owner=? AND telegram_id=? AND status='pending'",
                (phone,iso_now(),bot_owner,telegram_id),
            )
        agent = assigned_sales_agent(bot_owner, telegram_id)
        agent_label = str(agent["public_name"] or agent["username"]) if agent else "در حال تخصیص"
        telegram_reply(
            token, chat_id,
            f"✅ شماره تماس شما برای درخواست پنل فروش ثبت شد.\n\n🆔 نام کاربری SSH از Telegram ID عددی شما ساخته می‌شود.\n🧑‍💼 نماینده ثابت شما: {agent_label}",
            menu=True,
        )
        return
    text_message = str(message.get("text") or "").strip()
    if not text_message and not callback_command:
        return
    customer = upsert_telegram_customer(bot_owner, telegram_id, sender)
    command = callback_command or text_message.split()[0].split("@", 1)[0].lower()
    if callback_command:
        command = "/" + callback_command
    elif command == "/start" and len(text_message.split()) > 1 and text_message.split()[1].lower() == "plans":
        command = "/plans"
    contact = str(owner["contact_text"] or "اطلاعات تماس مدیر هنوز ثبت نشده است.")
    if command == "/cancel":
        clear_telegram_pending_action(bot_owner, telegram_id)
        telegram_reply(token, chat_id, "عملیات لغو شد.", menu=True)
        return
    if command in ("/account", "/get", "/trial", "/config", "/password") and not private_chat:
        telegram_reply(token, chat_id, "برای امنیت، اطلاعات حساب و رمز فقط در گفت‌وگوی خصوصی با ربات نمایش داده می‌شود.")
        return
    if not callback_command and text_message and not text_message.startswith("/"):
        with db() as conn:
            pending = conn.execute(
                "SELECT action,created_at FROM telegram_pending_actions WHERE bot_owner=? AND telegram_id=?",
                (bot_owner, telegram_id),
            ).fetchone()
        if pending and str(pending["action"]) == "password":
            created = dt.datetime.fromisoformat(str(pending["created_at"]))
            if created.tzinfo is None:
                created = created.replace(tzinfo=dt.timezone.utc)
            if created < utcnow() - dt.timedelta(minutes=10):
                clear_telegram_pending_action(bot_owner, telegram_id)
                telegram_reply(token, chat_id, "زمان تغییر رمز تمام شد؛ دوباره دکمه تغییر رمز را بزنید.", menu=True)
                return
            user = telegram_user(bot_owner, telegram_id)
            if not user:
                clear_telegram_pending_action(bot_owner, telegram_id)
                telegram_reply(token, chat_id, "ابتدا اکانت خود را دریافت کنید.", menu=True)
                return
            password = text_message
            if len(password) > 128 or ":" in password or "\n" in password or "\r" in password:
                telegram_reply(token, chat_id, "رمز باید حداکثر ۱۲۸ کاراکتر و بدون دونقطه یا خط جدید باشد. /cancel برای لغو")
                return
            with STATE_LOCK:
                set_unix_password(str(user["username"]), password)
                password_hash = unix_password_hash(str(user["username"]))
                with db() as conn:
                    conn.execute(
                        "UPDATE users SET password_hash=?,credential_token=?,updated_at=? WHERE username=?",
                        (password_hash, encrypt_credential(password), iso_now(), user["username"]),
                    )
                disconnect_user(str(user["username"]))
                reconcile_accounts()
            clear_telegram_pending_action(bot_owner, telegram_id)
            audit(f"telegram:{bot_owner}", "user.password_change", str(user["username"]), telegram_id)
            telegram_reply(token, chat_id, "✅ رمز VPN تغییر کرد و اتصال‌های قبلی بسته شدند. کانفیگ جدید در پیام بعدی است.")
            telegram_reply(token, chat_id, npv_tunnel_config(str(user["username"]), password))
            telegram_reply(token, chat_id, "منوی راه‌بان", menu=True)
            return
    if command in ("/start", "/help"):
        text_value = (
            f"به {panel_title()} خوش آمدید 🌿\n\n"
            "از دکمه‌های زیر استفاده کنید:\n"
            "• دریافت اکانت و کانفیگ: ساخت یا نمایش دوباره حساب\n"
            "• حساب من: رمز، IP، پورت، مصرف، مانده و انقضا\n"
            "• نماینده من: فروشنده‌ای که همیشه به شما متصل است\n"
            "• درخواست پنل فروش: ورود به شبکه نمایندگان"
        )
        telegram_reply(token, chat_id, text_value, menu=True)
        return
    elif command == "/contact":
        telegram_reply(token, chat_id, "☎️ راه ارتباط با مدیر:\n\n" + contact, menu=True)
        return
    elif command == "/clients":
        telegram_reply(token, chat_id,
            "📲 نرم‌افزارهای اتصال\n\n"
            "Android — NPV Tunnel:\nhttps://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv\n\n"
            "iPhone / iPad — NPV Tunnel:\nhttps://apps.apple.com/us/app/npv-tunnel/id1629465476\n\n"
            "Windows / macOS / Android / iOS — Termius:\nhttps://termius.com/download\n\n"
            "Windows — OpenSSH رسمی مایکروسافت:\nhttps://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-install-first-use\n\n"
            "Windows — PuTTY:\nhttps://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html"
            "\n\nWindows — NetMod (پشتیبانی SSH):\nhttps://sourceforge.net/projects/netmodhttp/files/Setup/\n\n"
            "Windows — Nekoray قدیمی و آرشیوشده:\nhttps://github.com/MatsuriDayo/nekoray/releases\n\n"
            "جایگزین فعال Nekoray با پشتیبانی SSH — Throne:\nhttps://github.com/throneproj/Throne/releases",
            menu=True)
        return
    elif command == "/plans":
        agent = assigned_sales_agent(bot_owner, telegram_id)
        if not agent:
            telegram_reply(token, chat_id, "نماینده فعالی برای نمایش پلن‌ها وجود ندارد.", menu=True)
            return
        plans = plans_for_agent(str(agent["username"]))
        if not plans:
            telegram_reply(token, chat_id, "نماینده شما هنوز پلن فروشی تعریف نکرده است.", menu=True)
            return
        lines = [f"🧾 پلن‌های {str(agent['public_name'] or agent['username'])}:"]
        for plan in plans:
            description = f"\n  توضیحات: {plan['description']}" if plan["description"] else ""
            lines.append(f"\n• {plan['name']}\n  مدت: {human_duration(int(plan['duration_minutes']))}\n  حجم: {human_bytes(int(plan['traffic_bytes']))}\n  اتصال: {int(plan['max_connections'])}\n  قیمت: {str(plan['price_label'] or 'تماس با نماینده')}{description}")
        telegram_reply(token, chat_id, "\n".join(lines), reply_markup=telegram_plans_keyboard(plans))
        return
    elif command.startswith("/buy:"):
        try:
            plan_id = int(command.split(":", 1)[1])
        except ValueError:
            telegram_reply(token, chat_id, "پلن معتبر نیست.", menu=True)
            return
        agent = assigned_sales_agent(bot_owner, telegram_id)
        new_request = False
        with db() as conn:
            plan = conn.execute("SELECT * FROM service_plans WHERE id=? AND enabled=1 AND deleted_at=''", (plan_id,)).fetchone()
            if not agent or not plan or str(plan["owner_username"]) not in admin_ancestors(str(agent["username"])):
                telegram_reply(token, chat_id, "این پلن دیگر فعال نیست.", menu=True)
                return
            prior = conn.execute("SELECT id FROM purchase_requests WHERE telegram_id=? AND plan_id=? AND status='pending'", (telegram_id, plan_id)).fetchone()
            if prior:
                request_id = int(prior["id"])
            else:
                now = iso_now()
                request_id = int(conn.execute("""INSERT INTO purchase_requests(bot_owner,telegram_id,assigned_reseller,plan_id,status,created_at,updated_at)
                    VALUES(?,?,?,?, 'pending',?,?)""", (bot_owner,telegram_id,agent["username"],plan_id,now,now)).lastrowid)
                new_request = True
        agent_label = str(agent["public_name"] or agent["username"])
        telegram_reply(token, chat_id, f"✅ درخواست خرید شماره {request_id} برای پلن «{plan['name']}» ثبت شد.\n\n🧑‍💼 نماینده ثابت: {agent_label}\n👤 نام کاربری پنل نماینده: {agent['username']}\n💳 هماهنگی پرداخت و فعال‌سازی:\n{str(agent['contact_text'] or 'اطلاعات تماس نماینده ثبت نشده است.')}", menu=True)
        notification_id = str(agent["notification_telegram_id"] or "")
        if new_request and notification_id:
            customer_name = str(customer["display_name"] or "—")
            customer_username = str(customer["telegram_username"] or "")
            contact_link = f"https://t.me/{customer_username}" if customer_username else f"tg://user?id={telegram_id}"
            try:
                telegram_reply(
                    token,
                    notification_id,
                    f"🔔 سفارش جدید برای شما\n\nشماره سفارش: #{request_id}\nمشتری: {customer_name}\nTelegram ID: {telegram_id}\nراه ارتباط: {contact_link}\n\nپلن: {plan['name']}\nمدت: {human_duration(int(plan['duration_minutes']))}\nحجم: {human_bytes(int(plan['traffic_bytes']))}\nاتصال هم‌زمان: {int(plan['max_connections'])}\nقیمت: {str(plan['price_label'] or 'توافقی')}\n\nبرای هماهنگی پرداخت با مشتری تماس بگیرید.\nپنل سفارش‌ها: {PANEL_PUBLIC_URL}/applications",
                )
                audit(f"telegram:{bot_owner}", "purchase.agent_notified", str(request_id), str(agent["username"]))
            except Exception as exc:
                audit(f"telegram:{bot_owner}", "purchase.agent_notify_failed", str(request_id), type(exc).__name__)
        return
    elif command == "/agents":
        agents = active_sales_agents(bot_owner)
        if not agents:
            telegram_reply(token, chat_id, "در حال حاضر نماینده عمومی فعالی ثبت نشده است.", menu=True)
            return
        lines = ["🛍 نمایندگان فعال راه‌بان:"]
        for item in agents[:20]:
            label = str(item["public_name"] or item["username"])
            lines.append(f"• {label} — {str(item['contact_text'] or 'تماس در پنل')}")
        if customer["assigned_reseller"]:
            lines.append("\nنماینده شما قبلاً ثابت شده و قابل تغییر توسط کاربر نیست.")
        telegram_reply(token, chat_id, "\n".join(lines), reply_markup=telegram_agents_keyboard(agents))
        return
    elif command.startswith("/pick:"):
        requested = command.split(":", 1)[1]
        if customer["assigned_reseller"]:
            telegram_reply(token, chat_id, "نماینده شما قبلاً ثبت شده و همیشه همان نماینده خواهد بود.", menu=True)
            return
        valid = {str(item["username"]): item for item in active_sales_agents(bot_owner)}
        if requested not in valid:
            telegram_reply(token, chat_id, "این نماینده فعال نیست.", menu=True)
            return
        with db() as conn:
            conn.execute(
                "UPDATE telegram_customers SET assigned_reseller=?,updated_at=? WHERE bot_owner=? AND telegram_id=? AND assigned_reseller=''",
                (requested, iso_now(), bot_owner, telegram_id),
            )
        label = str(valid[requested]["public_name"] or requested)
        telegram_reply(token, chat_id, f"✅ {label} به‌عنوان نماینده ثابت شما ثبت شد.", menu=True)
        return
    elif command == "/agent":
        agent = assigned_sales_agent(bot_owner, telegram_id)
        if not agent:
            telegram_reply(token, chat_id, "هنوز نماینده‌ای برای شما پیدا نشده است.", menu=True)
            return
        label = str(agent["public_name"] or agent["username"])
        telegram_reply(token, chat_id, f"🧑‍💼 نماینده ثابت شما: {label}\n\n{str(agent['contact_text'] or 'اطلاعات تماس ثبت نشده است.')}", menu=True)
        return
    elif command == "/account":
        with db() as conn:
            trial = conn.execute(
                "SELECT ssh_username FROM telegram_trials WHERE owner_username=? AND telegram_id=?",
                (bot_owner, telegram_id),
            ).fetchone()
            user = conn.execute("SELECT * FROM users WHERE username=?", (trial["ssh_username"],)).fetchone() if trial else None
        agent = assigned_sales_agent(bot_owner, telegram_id)
        agent_label = str(agent["public_name"] or agent["username"]) if agent else "—"
        if not user:
            telegram_reply(token, chat_id, f"🆔 Telegram ID: {telegram_id}\nهنوز اکانتی ندارید.\n🧑‍💼 نماینده ثابت: {agent_label}", menu=True)
            return
        status, _ = user_status(user)
        limit_bytes = int(user["traffic_limit"])
        used_bytes = int(user["used_bytes"])
        limit = human_bytes(limit_bytes) if limit_bytes else "نامحدود"
        remaining = human_bytes(max(0, limit_bytes - used_bytes)) if limit_bytes else "نامحدود"
        active_connections = len(user_processes().get(str(user["username"]), []))
        password = decrypt_credential(str(user["credential_token"])) if user["credential_token"] else "برای دریافت رمز، از نماینده کانفیگ جدید بخواهید"
        telegram_reply(
            token, chat_id,
            f"👤 حساب من\n\n🆔 Telegram ID: {telegram_id}\nنام کاربری SSH: {user['username']}\nرمز عبور: {password}\nIP / Host: {CUSTOMER_PUBLIC_HOST}\nPort: {CUSTOMER_PUBLIC_PORT}\n\nوضعیت: {status}\nمصرف‌شده: {human_bytes(used_bytes)}\nحجم کل: {limit}\nباقی‌مانده: {remaining}\nانقضا (شمسی): {jalali_datetime(user['expires_at'] or user['expires_on'])}\nاتصال فعال: {active_connections} از {int(user['max_connections'])}\nآخرین IP: {user['last_ip'] or '—'}\nنماینده: {agent_label}",
            menu=True,
        )
        return
    elif command == "/password":
        if not private_chat:
            telegram_reply(token, chat_id, "برای امنیت، تغییر رمز را فقط در گفت‌وگوی خصوصی با ربات انجام دهید.")
            return
        if not telegram_user(bot_owner, telegram_id):
            telegram_reply(token, chat_id, "ابتدا از دکمه دریافت اکانت و کانفیگ استفاده کنید.", menu=True)
            return
        set_telegram_pending_action(bot_owner, telegram_id, "password")
        telegram_reply(token, chat_id, "🔑 رمز جدید VPN را در پیام بعدی بفرستید.\n\nهر رمزی تا ۱۲۸ کاراکتر پذیرفته می‌شود؛ دونقطه و خط جدید مجاز نیست. این درخواست ۱۰ دقیقه اعتبار دارد.\nبرای لغو: /cancel")
        return
    elif command == "/reseller":
        agent = assigned_sales_agent(bot_owner, telegram_id)
        requested_parent = str(agent["username"]) if agent else bot_owner
        with db() as conn:
            prior = conn.execute(
                "SELECT id,status FROM reseller_applications WHERE bot_owner=? AND telegram_id=? ORDER BY id DESC LIMIT 1",
                (bot_owner, telegram_id),
            ).fetchone()
            if prior and prior["status"] == "pending":
                telegram_reply(token, chat_id, f"درخواست شماره {prior['id']} قبلاً ثبت شده و در انتظار بررسی است.", menu=True)
                return
            now = iso_now()
            cursor = conn.execute(
                """INSERT INTO reseller_applications(bot_owner,telegram_id,phone,telegram_username,
                requested_parent,status,created_at,updated_at) VALUES(?,?,?,?,?,'pending',?,?)""",
                (bot_owner, telegram_id, customer["phone"], customer["telegram_username"], requested_parent, now, now),
            )
            request_id = cursor.lastrowid
        audit(f"telegram:{bot_owner}", "reseller.application", str(request_id), telegram_id)
        if customer["phone"]:
            telegram_reply(token, chat_id, f"✅ درخواست پنل فروش شما با شماره {request_id} ثبت شد. پس از بررسی، اطلاعات ورود از همین ربات ارسال می‌شود.", menu=True)
        else:
            telegram_reply(token, chat_id, f"✅ درخواست پنل فروش شما با شماره {request_id} و Telegram ID {telegram_id} ثبت شد. ثبت شماره تماس اختیاری است؛ در صورت تمایل دکمه زیر را بزنید.", reply_markup=telegram_contact_keyboard())
        return
    elif command in ("/get", "/trial", "/config"):
        if not bool(owner["trial_enabled"]):
            telegram_reply(
                token, chat_id,
                "در حال حاضر امکان دریافت تست غیرفعال است.\n\n" + contact,
                menu=True,
            )
            return
        else:
            try:
                username, password, created, agent_username = telegram_trial(bot_owner, telegram_id)
                if created:
                    telegram_reply(
                        token, chat_id,
                        f"✅ تست شما ساخته شد.\n\n👤 نام کاربری: {username}\n🧑‍💼 نماینده: {agent_username}\n⏳ اعتبار: یک روز\n📦 حجم: ۱ گیگابایت\n👥 اتصال هم‌زمان: ۱\n\nکانفیگ در پیام بعدی ارسال می‌شود؛ روی آن نگه دارید و Copy را بزنید.",
                    )
                # Keep the configuration in its own message with no prefix,
                # suffix, formatting or contact text so mobile clients can copy it cleanly.
                telegram_reply(token, chat_id, npv_tunnel_config(username, password))
                telegram_reply(token, chat_id, "منوی راه‌بان", menu=True)
                return
            except ValueError as exc:
                error_text = str(exc)
                if "already been used" in error_text:
                    error_text = "سهمیه تست این حساب قبلاً استفاده شده است."
                elif "remaining credit" in error_text:
                    error_text = "اعتبار کافی برای ساخت تست وجود ندارد."
                elif "expiry" in error_text:
                    error_text = "تاریخ اعتبار فروشنده اجازه ساخت تست جدید را نمی‌دهد."
                telegram_reply(token, chat_id, "امکان ساخت تست وجود ندارد:\n" + error_text, menu=True)
                return
    else:
        telegram_reply(token, chat_id, "دستور را متوجه نشدم؛ از دکمه‌های زیر استفاده کنید.", menu=True)


def telegram_loop() -> None:
    announced: set[str] = set()
    while not STOP.wait(2):
        try:
            with db() as conn:
                bots = conn.execute(
                    "SELECT * FROM admins WHERE enabled=1 AND telegram_token<>''"
                ).fetchall()
            for owner in bots:
                name = str(owner["username"])
                try:
                    token = decrypt_credential(str(owner["telegram_token"]))
                    if name not in announced:
                        telegram_api(token, "setMyCommands", {"commands": json.dumps([
                            {"command":"get","description":"دریافت اکانت و کانفیگ"},
                            {"command":"account","description":"مشاهده وضعیت حساب من"},
                            {"command":"password","description":"تغییر رمز VPN"},
                            {"command":"cancel","description":"لغو تغییر رمز"},
                            {"command":"agents","description":"نمایش نمایندگان فعال"},
                            {"command":"plans","description":"نمایش پلن‌های نماینده من"},
                            {"command":"clients","description":"دانلود نرم‌افزارهای اتصال"},
                            {"command":"reseller","description":"درخواست پنل فروش"},
                            {"command":"contact","description":"تماس با مدیر و پشتیبانی"},
                            {"command":"help","description":"نمایش راهنما و منوی دکمه‌ای"},
                        ], ensure_ascii=False)})
                        telegram_api(token, "setMyDescription", {
                            "description": f"{panel_title()} — دریافت تست یک‌روزه، کانفیگ و ارتباط با پشتیبانی"
                        })
                        telegram_api(token, "setMyShortDescription", {
                            "short_description": "دریافت تست، کانفیگ و پشتیبانی راه‌بان"
                        })
                        announced.add(name)
                    with db() as conn:
                        state = conn.execute(
                            "SELECT update_offset FROM telegram_bot_state WHERE owner_username=?", (name,)
                        ).fetchone()
                    offset = int(state["update_offset"]) if state else 0
                    updates = telegram_api(token, "getUpdates", {"offset": offset, "timeout": 1, "allowed_updates": '["message","callback_query"]'}, timeout=5)
                    if not isinstance(updates, list):
                        continue
                    for update in updates:
                        if not isinstance(update, dict):
                            continue
                        handle_telegram_update(owner, token, update)
                        offset = max(offset, int(update.get("update_id", 0)) + 1)
                    if updates:
                        with db() as conn:
                            conn.execute(
                                "INSERT INTO telegram_bot_state(owner_username,update_offset) VALUES(?,?) ON CONFLICT(owner_username) DO UPDATE SET update_offset=excluded.update_offset",
                                (name, offset),
                            )
                except Exception as exc:
                    print(f"telegram: {name}: {type(exc).__name__}", flush=True)
        except Exception:
            traceback.print_exc()


def maintenance_loop() -> None:
    last_backup_date = ""
    while not STOP.wait(INTERVAL):
        try:
            sample_accounting()
            reconcile_accounts()
            today = utcnow().date().isoformat()
            if utcnow().hour == 3 and last_backup_date != today:
                make_backup()
                last_backup_date = today
        except Exception:
            traceback.print_exc()


def sshd_log_loop(process: subprocess.Popen[str]) -> None:
    if not process.stderr:
        return
    accepted = re.compile(
        r"Accepted password for ((?:[a-z][a-z0-9_-]{2,31}|[0-9]{5,20})) "
        r"from ([0-9a-fA-F:.]+) port (\d+)"
    )
    for line in process.stderr:
        print(f"sshd: {line.rstrip()}", flush=True)
        match = accepted.search(line)
        if match:
            username, address, port = match.groups()
            try:
                ipaddress.ip_address(address)
            except ValueError:
                continue
            with db() as conn:
                now = iso_now()
                conn.execute(
                    "UPDATE users SET last_ip=?, updated_at=? WHERE username=?",
                    (address, now, username),
                )
                conn.execute(
                    """
                    INSERT INTO live_sessions(
                      endpoint, username, last_total, last_seen, connected_at)
                    VALUES (?, ?, 0, ?, ?)
                    ON CONFLICT(endpoint) DO UPDATE SET
                      username=excluded.username,
                      last_total=0,
                      last_seen=excluded.last_seen,
                      connected_at=excluded.connected_at
                    """,
                    (endpoint_key(address, port), username, now, now),
                )


def start_sshd() -> None:
    global SSHD_PROCESS
    test = run(["/usr/sbin/sshd", "-t", "-f", "/etc/ssh/sshd_config"], check=False)
    if test.returncode != 0:
        raise RuntimeError(f"sshd configuration invalid: {test.stderr}")
    SSHD_PROCESS = subprocess.Popen(
        ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_config"],
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    threading.Thread(
        target=sshd_log_loop, args=(SSHD_PROCESS,), daemon=True
    ).start()


STYLE = """
:root{color-scheme:dark;--bg:#0b1220;--card:#121c2e;--line:#263653;
--text:#e8eef8;--muted:#9fb0ca;--blue:#4c8dff;--green:#38c793;--red:#ff6b6b;
--amber:#f6bd5b}*{box-sizing:border-box}body{margin:0;background:var(--bg);
color:var(--text);font:15px system-ui,-apple-system,sans-serif}main{max-width:1180px;
margin:0 auto;padding:26px}.top{display:flex;justify-content:space-between;
align-items:center;gap:16px;margin-bottom:22px}.top h1{margin:0;font-size:24px}
.nav{display:flex;gap:8px;flex-wrap:wrap}a{color:#8fb6ff;text-decoration:none}
.btn,button{display:inline-block;border:0;border-radius:8px;background:var(--blue);
color:white;padding:9px 13px;font-weight:650;cursor:pointer}.secondary{background:#2a3a56}
.danger{background:#a83e4a}.card{background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:18px;margin-bottom:18px}.grid{display:grid;
grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}.metric strong{
display:block;font-size:24px;margin-top:5px}.muted{color:var(--muted)}table{
width:100%;border-collapse:collapse}th,td{text-align:start;padding:11px 9px;
border-bottom:1px solid var(--line);vertical-align:middle}th{color:var(--muted);
font-size:12px;text-transform:uppercase}.actions{display:flex;gap:6px;flex-wrap:wrap}
.actions form{margin:0}.actions button{padding:6px 9px;font-size:12px}label{display:block;
color:var(--muted);margin:12px 0 5px}input,textarea,select{width:100%;border:1px solid
var(--line);border-radius:8px;background:#0e1727;color:var(--text);padding:10px}
.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:0 18px}
.copy-field{display:flex;gap:7px;align-items:center}.copy-field input{flex:1}
.copy-field button{white-space:nowrap}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;
font-weight:700;background:#273752}.active{color:var(--green)}.blocked{color:var(--red)}
.warning{color:var(--amber)}.notice{border-left:4px solid var(--blue);
padding:12px;background:#132541;margin-bottom:16px}.error{border-color:var(--red)}
.login{max-width:430px;margin:10vh auto}.login h1{margin-top:0}code{background:#0c1524;
padding:2px 5px;border-radius:5px}.config{font:14px ui-monospace,SFMono-Regular,Menlo,
monospace;min-height:210px;resize:vertical}.share{display:flex;gap:8px;flex-wrap:wrap;
margin-top:12px}@media(max-width:720px){main{padding:15px}
.form-grid{grid-template-columns:1fr}.table-wrap{overflow-x:auto}}
.hero{background:linear-gradient(135deg,#122747,#17213b 55%,#30245a);padding:24px;
border-radius:18px;border:1px solid #34486b;box-shadow:0 18px 55px #0005}.eyebrow{
text-transform:uppercase;letter-spacing:.14em;color:#7dd3fc;font-size:11px;font-weight:800}
.hero h2{font-size:30px;margin:8px 0}.role{font-size:12px;padding:5px 9px;border-radius:99px;
background:#ffffff12;border:1px solid #ffffff20}.progress{height:8px;background:#0b1322;
border-radius:99px;overflow:hidden;margin-top:9px}.progress span{display:block;height:100%;
background:linear-gradient(90deg,#38c793,#4c8dff);border-radius:99px}.group-grid{display:grid;
grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px}.group-card{background:#111d31;
border:1px solid var(--line);border-radius:14px;padding:16px}.group-card h3{margin:0 0 10px}
.toolbar{display:flex;gap:10px;align-items:end;flex-wrap:wrap}.toolbar>*{flex:1;min-width:160px}
.quick{width:100%;border:1px solid var(--line);border-radius:10px;padding:8px;background:#0d1829}
.quick summary{cursor:pointer;font-weight:750;color:#9fc1ff}.quick[open] summary{margin-bottom:8px}
.quick span{display:block;margin:8px 0 4px}.quick form{display:flex;gap:5px;flex-wrap:wrap}
.quick form button{flex:1;min-width:56px}
@media(max-width:720px){.top{align-items:flex-start;flex-direction:column}.nav{width:100%}
.nav a,.nav form,.nav button{flex:1;text-align:center}.hero h2{font-size:24px}table.responsive
thead{display:none}table.responsive,table.responsive tbody,table.responsive tr,table.responsive td{
display:block;width:100%}table.responsive tr{padding:12px 0;border-bottom:1px solid var(--line)}
table.responsive td{border:0;padding:5px 4px}table.responsive td:before{content:attr(data-label);
display:block;color:var(--muted);font-size:10px;text-transform:uppercase}.actions{margin-top:8px}}
"""

APP_JS = r"""
document.addEventListener("click", async (event) => {
  const confirmButton = event.target.closest("[data-confirm]");
  if (confirmButton && !window.confirm(confirmButton.dataset.confirm)) {
    event.preventDefault();
    return;
  }
  const button = event.target.closest("[data-copy]");
  if (!button) return;
  event.preventDefault();
  const target = document.querySelector(button.dataset.copy);
  if (!target) return;
  const value = target.value || target.textContent || "";
  try {
    await navigator.clipboard.writeText(value);
  } catch (_) {
    target.focus();
    target.select();
    document.execCommand("copy");
  }
  const old = button.textContent;
  button.textContent = "کپی شد";
  setTimeout(() => { button.textContent = old; }, 1400);
});
"""


def page(title: str, body: str, session: dict[str, object] | None = None) -> str:
    nav = ""
    if session:
        csrf = html.escape(str(session["csrf"]))
        reseller_link = '<a class="btn secondary" href="/resellers">نمایندگان</a>' if can_create_resellers(session) else ""
        role = "مالک" if is_owner(session) else "نماینده"
        nav = f"""
        <div class="nav">
          <a class="btn secondary" href="/">داشبورد</a>
          <a class="btn secondary" href="/users/new">ساخت کاربر</a>
          {reseller_link}
          <a class="btn secondary" href="/plans">پلن‌ها</a>
          <a class="btn secondary" href="/applications">درخواست‌ها</a>
          <a class="btn secondary" href="/clients">نرم‌افزارها</a>
          <a class="btn secondary" href="/audit">گزارش</a>
          <a class="btn secondary" href="/settings">تنظیمات</a>
          <form method="post" action="/logout">
            <input type="hidden" name="csrf" value="{csrf}">
            <button class="secondary">خروج</button>
          </form>
        </div>"""
    return f"""<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{html.escape(title)} · {html.escape(panel_title())}</title>
    <style>{STYLE}</style><script src="/app.js" defer></script></head><body><main>
    <div class="top"><div><h1>{html.escape(panel_title())}</h1>
    {f'<span class="role">{role} · {html.escape(str(session["u"]))}</span>' if session else ''}</div>{nav}</div>{body}
    <footer class="muted" style="text-align:center;margin:2rem 0 1rem">
      پیشنهاد و بازخورد: <a dir="ltr" href="mailto:rahbanssh@gmail.com">rahbanssh@gmail.com</a>
    </footer></main></body></html>"""


def customer_config(username: str, password: str) -> str:
    return (
        "SSH VPN\n"
        f"Host: {CUSTOMER_PUBLIC_HOST}\n"
        f"Port: {CUSTOMER_PUBLIC_PORT}\n"
        f"Username: {username}\n"
        f"Password: {password}\n\n"
        "SOCKS5 command:\n"
        f"ssh -N -D 1080 {username}@{CUSTOMER_PUBLIC_HOST}\n"
    )


def npv_tunnel_config(username: str, password: str) -> str:
    payload = {
        "sshConfigType": "SSH-Direct",
        "remarks": f"SSH - {username}",
        "sshHost": CUSTOMER_PUBLIC_HOST,
        "sshPort": CUSTOMER_PUBLIC_PORT,
        "sshUsername": username,
        "sshPassword": password,
        "sni": "",
        "tlsVersion": "DEFAULT",
        "httpProxy": "",
        "authenticateProxy": False,
        "proxyUsername": "",
        "proxyPassword": "",
        "payload": "",
        "dnsTTMode": "UDP",
        "dnsServer": "",
        "nameserver": "",
        "publicKey": "",
        "udpgwPort": 7300,
        "udpgwTransparentDNS": True,
    }
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return "npvt-ssh://" + base64.b64encode(raw).decode("ascii")


def credential_page(
    session: dict[str, object], username: str, password: str, heading: str
) -> str:
    npvt_config = npv_tunnel_config(username, password)
    details = customer_config(username, password)
    body = f"""<section class="card"><h2>{html.escape(heading)}</h2>
    <div class="notice">This connection can be viewed again from the dashboard.</div>
    <label>NPV Tunnel — paste-ready import config</label>
    <textarea id="npvt-config" class="config" readonly>{html.escape(npvt_config)}</textarea>
    <div class="share">
      <button type="button" data-copy="#npvt-config">Copy NPV config</button>
      <a class="btn secondary" href="/">Return to dashboard</a>
    </div>
    <h3>Connection details</h3>
    <div class="form-grid">
      <div><label>IP / Host</label><div class="copy-field">
        <input id="config-host" readonly value="{html.escape(CUSTOMER_PUBLIC_HOST, quote=True)}">
        <button type="button" data-copy="#config-host">Copy</button></div></div>
      <div><label>Port</label><div class="copy-field">
        <input id="config-port" readonly value="{CUSTOMER_PUBLIC_PORT}">
        <button type="button" data-copy="#config-port">Copy</button></div></div>
      <div><label>Username</label><div class="copy-field">
        <input id="config-username" readonly value="{html.escape(username, quote=True)}">
        <button type="button" data-copy="#config-username">Copy</button></div></div>
      <div><label>Password</label><div class="copy-field">
        <input id="config-password" readonly value="{html.escape(password, quote=True)}">
        <button type="button" data-copy="#config-password">Copy</button></div></div>
    </div>
    <label>Plain SSH details</label>
    <textarea id="ssh-details" class="config" readonly>{html.escape(details)}</textarea>
    <button type="button" data-copy="#ssh-details">Copy SSH details</button>
    </section>"""
    return page(heading, body, session)


def user_status(row: sqlite3.Row) -> tuple[str, str]:
    allowed, reason = account_should_work(row)
    labels = {
        "active": "فعال", "disabled": "غیرفعال", "expired": "منقضی",
        "quota reached": "حجم تمام شده", "group disabled": "گروه غیرفعال",
        "group expired": "اعتبار گروه تمام شده",
    }
    return (labels.get(reason, reason), "active" if allowed else "blocked")


def dashboard(session: dict[str, object], notice: str = "", group: str = "") -> str:
    sample_accounting()
    processes = user_processes()
    actor = str(session["u"])
    with db() as conn:
        if is_owner(session):
            resellers = conn.execute(
                "SELECT * FROM admins WHERE role='reseller' ORDER BY username"
            ).fetchall()
            valid_groups = {str(row["username"]) for row in resellers}
            if group and group in valid_groups:
                rows = conn.execute(
                    "SELECT * FROM users WHERE owner_username=? ORDER BY created_at DESC",
                    (group,),
                ).fetchall()
            else:
                group = ""
                rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
        else:
            resellers = []
            rows = conn.execute(
                "SELECT * FROM users WHERE owner_username=? ORDER BY created_at DESC",
                (actor,),
            ).fetchall()
    total = len(rows)
    online = sum(1 for row in rows if processes.get(str(row["username"])))
    active = sum(1 for row in rows if account_should_work(row)[0])
    used = sum(int(row["used_bytes"]) for row in rows)
    csrf = html.escape(str(session["csrf"]))
    notice_html = f'<div class="notice">{html.escape(notice)}</div>' if notice else ""
    group_options = '<option value="">همه گروه‌ها</option>' + ''.join(
        f'<option value="{html.escape(str(item["username"]), quote=True)}" '
        f'{"selected" if group == str(item["username"]) else ""}>{html.escape(str(item["username"]))}</option>'
        for item in resellers
    )
    user_rows = []
    for row in rows:
        username = html.escape(str(row["username"]))
        reason, css = user_status(row)
        limit = int(row["traffic_limit"])
        usage = human_bytes(int(row["used_bytes"]))
        if limit:
            usage += f" / {human_bytes(limit)}"
        expires = html.escape(jalali_datetime(row["expires_at"] or row["expires_on"]))
        sessions = len(processes.get(str(row["username"]), []))
        last_ip = html.escape(row["last_ip"] or "—")
        quick_extend = "".join(
            f'<button name="days" value="{days}" class="secondary">+{label}</button>'
            for days, label in ((1, "۱ روز"), (7, "۱ هفته"), (30, "۱ ماه"), (90, "۳ ماه"), (365, "۱ سال"))
        )
        quick_quota = "".join(
            f'<button name="gib" value="{gib}" class="secondary">+{gib} GiB</button>'
            for gib in (1, 5, 10, 50)
        )
        quick_connections = "".join(
            f'<button name="maximum" value="{maximum}" class="secondary">{maximum}</button>'
            for maximum in (1, 2, 5, 10, 100)
        )
        user_rows.append(
            f"""<tr><td><strong>{username}</strong><br><span class="muted">
            {html.escape(row["note"] or "")}</span></td>
            <td data-label="Group">{html.escape(str(row["owner_username"] or ADMIN_USERNAME))}</td>
            <td data-label="Status"><span class="badge {css}">{html.escape(reason)}</span></td>
            <td data-label="Usage">{usage}</td><td data-label="Expires">{expires}</td>
            <td data-label="Connections">{sessions}/{int(row["max_connections"])}</td><td data-label="Last IP">{last_ip}</td>
            <td data-label="Actions"><div class="actions">
              <a class="btn secondary" href="/users/edit?u={urllib.parse.quote(str(row["username"]))}">ویرایش</a>
              <form method="post" action="/users/config"><input type="hidden" name="csrf" value="{csrf}">
                <input type="hidden" name="username" value="{username}"><button>کانفیگ</button></form>
              <form method="post" action="/users/reset"><input type="hidden" name="csrf" value="{csrf}">
                <input type="hidden" name="username" value="{username}"><button class="secondary">صفر کردن مصرف</button></form>
              <form method="post" action="/users/disconnect"><input type="hidden" name="csrf" value="{csrf}">
                <input type="hidden" name="username" value="{username}"><button class="secondary">قطع اتصال</button></form>
              <form method="post" action="/users/regenerate"><input type="hidden" name="csrf" value="{csrf}">
                <input type="hidden" name="username" value="{username}"><button class="secondary"
                data-confirm="رمز کاربر عوض و اتصال‌های فعلی قطع شود؟">کانفیگ جدید</button></form>
              <form method="post" action="/users/delete"><input type="hidden" name="csrf" value="{csrf}">
                <input type="hidden" name="username" value="{username}"><button class="danger"
                data-confirm="این حساب برای همیشه حذف شود؟">حذف</button></form>
              <details class="quick"><summary>مدیریت سریع</summary>
                <span class="muted">افزایش اعتبار</span><form method="post" action="/users/extend">
                <input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="username" value="{username}">{quick_extend}</form>
                <span class="muted">افزایش حجم</span><form method="post" action="/users/quota-add">
                <input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="username" value="{username}">{quick_quota}</form>
                <span class="muted">حداکثر اتصال هم‌زمان</span><form method="post" action="/users/connections">
                <input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="username" value="{username}">{quick_connections}</form>
              </details>
            </div></td></tr>"""
        )
    empty = '<tr><td colspan="8" class="muted">هنوز حساب مشتری ساخته نشده است.</td></tr>'
    if is_owner(session):
        reseller_cards = []
        for item in resellers:
            credit, allocated, remaining = reseller_allocation(str(item["username"]))
            percent = min(100, int(allocated * 100 / credit)) if credit else 0
            reseller_cards.append(f'''<div class="group-card"><h3>{html.escape(str(item["username"]))}</h3>
            <div class="muted">{html.escape(str(item["note"] or "گروه نماینده"))}</div>
            <p><strong>{human_bytes(remaining)}</strong> باقی‌مانده از {human_bytes(credit)}</p>
            <div class="progress"><span style="width:{percent}%"></span></div></div>''')
        group_panel = f'''<section><div class="top"><h2>شبکه نمایندگان</h2>
        <a class="btn" href="/resellers/new">ساخت نماینده</a></div>
        <div class="group-grid">{"".join(reseller_cards) or '<div class="group-card muted">هنوز نماینده‌ای ساخته نشده است.</div>'}</div></section>'''
        credit_metric = f'<div class="card metric"><span class="muted">تعداد نمایندگان</span><strong>{len(resellers)}</strong></div>'
        filter_panel = f'''<form class="toolbar card" method="get" action="/"><div><label>فیلتر گروه</label>
        <select name="group">{group_options}</select></div><div><button>اعمال فیلتر</button></div></form>'''
    else:
        credit, allocated, remaining = reseller_allocation(actor)
        credit_metric = f'<div class="card metric"><span class="muted">اعتبار باقی‌مانده</span><strong>{human_bytes(remaining)}</strong><small class="muted"> از {human_bytes(credit)}</small></div>'
        group_panel = ""
        filter_panel = ""
    body = f"""{notice_html}
    <section class="hero"><span class="eyebrow">مدیریت فروش دسترسی امن</span>
      <h2>به راه‌بان خوش آمدید</h2><p class="muted">نمایندگان، اعتبار حجمی، پلن‌ها، مشتریان و مصرف زنده را یک‌جا مدیریت کنید.</p></section><br>
    <section class="grid">
      <div class="card metric"><span class="muted">کل کاربران</span><strong>{total}</strong></div>
      <div class="card metric"><span class="muted">کاربران فعال</span><strong>{active}</strong></div>
      <div class="card metric"><span class="muted">کاربران آنلاین</span><strong>{online}</strong></div>
      <div class="card metric"><span class="muted">ترافیک مصرف‌شده</span><strong>{human_bytes(used)}</strong></div>
      {credit_metric}</section>{group_panel}{filter_panel}
    <section class="card"><div class="top"><h2>حساب‌های مشتریان</h2>
      <a class="btn" href="/users/new">ساخت حساب</a></div>
      <div class="table-wrap"><table class="responsive"><thead><tr><th>کاربر</th><th>گروه</th><th>وضعیت</th>
      <th>مصرف</th><th>انقضا</th><th>اتصال</th><th>آخرین IP</th><th>عملیات</th>
      </tr></thead><tbody>{''.join(user_rows) or empty}</tbody></table></div>
    </section>"""
    return page("داشبورد", body, session)


def user_form(
    session: dict[str, object],
    row: sqlite3.Row | None = None,
    error: str = "",
) -> str:
    editing = row is not None
    username = html.escape(str(row["username"])) if row else ""
    limit = ""
    if row and int(row["traffic_limit"]):
        limit = f"{int(row['traffic_limit']) / 1024**3:.3f}".rstrip("0").rstrip(".")
    expires = html.escape(row["expires_on"] or "") if row else ""
    maximum = int(row["max_connections"]) if row else MAX_CONNECTIONS_PER_USER
    enabled = bool(row["enabled"]) if row else True
    note = html.escape(row["note"] or "") if row else ""
    current_owner = str(row["owner_username"] or ADMIN_USERNAME) if row else str(session["u"])
    if is_owner(session):
        with db() as conn:
            owners = conn.execute(
                "SELECT username,role FROM admins WHERE enabled=1 ORDER BY role,username"
            ).fetchall()
        owner_options = ''.join(
            f'<option value="{html.escape(str(item["username"]), quote=True)}" '
            f'{"selected" if current_owner == str(item["username"]) else ""}>'
            f'{html.escape(str(item["username"]))} ({html.escape(str(item["role"]))})</option>'
            for item in owners
        )
        owner_field = f'<div><label>گروه / نماینده</label><select name="owner_username">{owner_options}</select></div>'
    else:
        owner_field = f'<input type="hidden" name="owner_username" value="{html.escape(str(session["u"]), quote=True)}">'
    csrf = html.escape(str(session["csrf"]))
    action = "/users/update" if editing else "/users/create"
    heading = "ویرایش مشتری" if editing else "ساخت مشتری"
    username_field = (
        f'<input type="hidden" name="username" value="{username}"><code>{username}</code>'
        if editing
        else '<input name="username" required minlength="3" maxlength="32" pattern="[a-z][a-z0-9_-]{2,31}">'
    )
    password_help = (
        "برای حفظ رمز فعلی خالی بگذارید."
        if editing
        else "برای ساخت رمز قوی خودکار خالی بگذارید."
    )
    error_html = f'<div class="notice error">{html.escape(error)}</div>' if error else ""
    body = f"""<section class="card" dir="rtl"><h2>{heading}</h2>{error_html}
    <form method="post" action="{action}">
      <input type="hidden" name="csrf" value="{csrf}">
      <div class="form-grid">
        <div><label>نام کاربری</label>{username_field}</div>
        <div><label>رمز عبور</label><input dir="ltr" type="password" name="password">
          <span class="muted">{password_help}</span></div>
        {owner_field}
        <div><label>محدودیت حجم (GiB)</label><input dir="ltr" type="number" name="limit_gb" min="0" max="100000" step="0.001" value="{limit}">
          <span class="muted">صفر یعنی نامحدود.</span></div>
        <div><label>تاریخ انقضا UTC</label><input type="date" name="expires_on" value="{expires}"></div>
        <div><label>حداکثر اتصال هم‌زمان</label><input dir="ltr" type="number"
          name="max_connections" min="1" max="{MAX_CONNECTIONS_PER_USER}" value="{maximum}"></div>
        <div><label>وضعیت</label><select name="enabled">
          <option value="1" {'selected' if enabled else ''}>فعال</option>
          <option value="0" {'selected' if not enabled else ''}>غیرفعال</option>
        </select></div>
      </div>
      <label>یادداشت</label><textarea name="note" maxlength="500" rows="3">{note}</textarea>
      <p><button>{heading}</button> <a class="btn secondary" href="/">انصراف</a></p>
    </form></section>"""
    return page(heading, body, session)


def reseller_form(
    session: dict[str, object], row: sqlite3.Row | None = None
) -> str:
    if not can_create_resellers(session):
        return page("دسترسی غیرمجاز", "<section class=card>اجازه ساخت زیرنماینده برای این حساب فعال نیست.</section>", session)
    editing = row is not None
    username = html.escape(str(row["username"])) if row else ""
    credit = ""
    if row and int(row["traffic_credit"]):
        credit = f"{int(row['traffic_credit']) / 1024**3:.3f}".rstrip("0").rstrip(".")
    expires = html.escape(str(row["expires_on"] or "")) if row else ""
    note = html.escape(str(row["note"] or "")) if row else ""
    contact = html.escape(str(row["contact_text"] or "")) if row else ""
    notification_id = html.escape(str(row["notification_telegram_id"] or ""), quote=True) if row else ""
    public_name = html.escape(str(row["public_name"] or "")) if row else ""
    enabled = bool(row["enabled"]) if row else True
    public_sales = bool(row["public_sales_enabled"]) if row else False
    child_permission = bool(row["can_create_resellers"]) if row else True
    parent = str(row["parent_username"] or ADMIN_USERNAME) if row else str(session["u"])
    csrf = html.escape(str(session["csrf"]))
    username_field = (
        f'<input type="hidden" name="username" value="{username}"><code>{username}</code>'
        if editing else
        '<input name="username" required minlength="3" maxlength="32" pattern="[a-z][a-z0-9_-]{2,31}">'
    )
    if is_owner(session) and not editing:
        with db() as conn:
            parents = conn.execute("SELECT username,role FROM admins WHERE enabled=1 ORDER BY role,username").fetchall()
        parent_options = "".join(
            f'<option value="{html.escape(str(item["username"]), quote=True)}" {"selected" if parent == str(item["username"]) else ""}>{html.escape(str(item["username"]))}</option>'
            for item in parents
        )
        parent_field = f'<div><label>شاخه بالاتر</label><select name="parent_username">{parent_options}</select></div>'
    else:
        parent_field = f'<input type="hidden" name="parent_username" value="{html.escape(parent, quote=True)}"><div><label>شاخه بالاتر</label><code>{html.escape(parent)}</code></div>'
    heading = "ویرایش نماینده" if editing else "ساخت زیرنماینده"
    action = "/resellers/update" if editing else "/resellers/create"
    return page(heading, f'''<section class="card" dir="rtl"><span class="eyebrow">شبکه فروش چندسطحی</span>
    <h2>{heading}</h2><form method="post" action="{action}">
    <input type="hidden" name="csrf" value="{csrf}"><div class="form-grid">
    <div><label>نام کاربری نماینده</label>{username_field}</div>
    <div><label>{'رمز جدید (خالی یعنی بدون تغییر)' if editing else 'رمز ورود پنل'}</label>
    <input type="password" name="password" {'required' if not editing else ''}></div>
    {parent_field}
    <div><label>اعتبار قابل فروش (GiB)</label><input dir="ltr" type="number" name="credit_gb" min="0.001" max="100000" step="0.001" value="{credit}" required></div>
    <div><label>تاریخ پایان اعتبار</label><input type="date" name="expires_on" value="{expires}" required></div>
    <div><label>وضعیت پنل</label><select name="enabled"><option value="1" {'selected' if enabled else ''}>فعال</option>
    <option value="0" {'selected' if not enabled else ''}>غیرفعال</option></select></div>
    <div><label>نمایش در فهرست فروشندگان ربات</label><select name="public_sales_enabled"><option value="1" {'selected' if public_sales else ''}>فعال</option><option value="0" {'selected' if not public_sales else ''}>غیرفعال</option></select></div>
    <div><label>اجازه ساخت زیرنماینده</label><select name="can_create_resellers"><option value="1" {'selected' if child_permission else ''}>دارد</option><option value="0" {'selected' if not child_permission else ''}>ندارد</option></select></div></div>
    <label>نام عمومی فروشگاه یا نماینده</label><input name="public_name" maxlength="80" value="{public_name}" placeholder="مثلاً فروشگاه پارس">
    <label>یادداشت داخلی گروه</label><textarea name="note" maxlength="500">{note}</textarea>
    <label>راه تماس مشتری با نماینده</label><textarea name="contact_text" maxlength="1000" placeholder="آیدی تلگرام، شماره تماس و ساعت پاسخ‌گویی">{contact}</textarea>
    <label>Telegram ID عددی برای اعلان سفارش‌ها</label><input dir="ltr" name="notification_telegram_id" inputmode="numeric" pattern="[0-9]{{5,20}}" maxlength="20" value="{notification_id}" placeholder="مثلاً 123456789">
    <p><button>{heading}</button> <a class="btn secondary" href="/resellers">انصراف</a></p></form></section>''', session)


def resellers_page(session: dict[str, object]) -> str:
    if not can_create_resellers(session):
        return page("دسترسی غیرمجاز", "<section class=card>اجازه مدیریت زیرنمایندگان فعال نیست.</section>", session)
    csrf = html.escape(str(session["csrf"]))
    with db() as conn:
        if is_owner(session):
            rows = conn.execute("SELECT * FROM admins WHERE role='reseller' ORDER BY parent_username,username").fetchall()
        else:
            rows = conn.execute("SELECT * FROM admins WHERE role='reseller' AND parent_username=? ORDER BY username", (str(session["u"]),)).fetchall()
    rendered = []
    for row in rows:
        username = str(row["username"])
        credit, allocated, remaining = reseller_allocation(username)
        rendered.append(f'''<tr><td data-label="نماینده"><strong>{html.escape(str(row["public_name"] or username))}</strong><br>
        <code>{html.escape(username)}</code><br>
        <span class="muted">{html.escape(str(row["note"] or ""))}</span></td>
        <td data-label="شاخه بالاتر">{html.escape(str(row["parent_username"] or ADMIN_USERNAME))}</td>
        <td data-label="اعتبار">{human_bytes(remaining)} / {human_bytes(credit)}</td>
        <td data-label="تخصیص یافته">{human_bytes(allocated)}</td><td data-label="انقضا">{html.escape(str(row["expires_on"] or "بدون انقضا"))}</td>
        <td data-label="وضعیت"><span class="badge {'active' if row['enabled'] else 'blocked'}">{'فعال' if row['enabled'] else 'غیرفعال'}</span><br><span class="muted">{'فروش عمومی' if row['public_sales_enabled'] else 'فروش خصوصی'}</span></td>
        <td data-label="Actions"><div class="actions"><a class="btn secondary" href="/resellers/edit?u={urllib.parse.quote(username)}">Edit</a>
        <a class="btn secondary" href="/?group={urllib.parse.quote(username)}">Users</a>
        <form method="post" action="/resellers/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="username" value="{html.escape(username, quote=True)}">
        <button class="danger" data-confirm="Delete this reseller? Their customers must be removed first.">Delete</button></form></div></td></tr>''')
    return page("شبکه نمایندگان", f'''<section class="card" dir="rtl"><div class="top"><div><span class="eyebrow">ساختار چندسطحی</span><h2>شبکه نمایندگان</h2></div>
    <a class="btn" href="/resellers/new">ساخت زیرنماینده</a></div><div class="table-wrap"><table class="responsive"><thead><tr>
    <th>نماینده</th><th>شاخه بالاتر</th><th>اعتبار باقی‌مانده</th><th>تخصیص یافته</th><th>انقضا</th><th>وضعیت</th><th>عملیات</th></tr></thead>
    <tbody>{''.join(rendered) or '<tr><td class="muted">هنوز زیرنماینده‌ای ساخته نشده است.</td></tr>'}</tbody></table></div></section>''', session)


def applications_page(session: dict[str, object]) -> str:
    actor = str(session["u"])
    csrf = html.escape(str(session["csrf"]))
    with db() as conn:
        if is_owner(session):
            rows = conn.execute("SELECT * FROM reseller_applications ORDER BY id DESC LIMIT 250").fetchall()
            purchases = conn.execute("""SELECT p.*,s.name,s.price_label,s.duration_minutes,s.traffic_bytes,s.max_connections,t.phone,t.telegram_username FROM purchase_requests p
              JOIN service_plans s ON s.id=p.plan_id LEFT JOIN telegram_customers t ON t.bot_owner=p.bot_owner AND t.telegram_id=p.telegram_id
              ORDER BY p.id DESC LIMIT 250""").fetchall()
        else:
            rows = conn.execute("SELECT * FROM reseller_applications WHERE requested_parent=? ORDER BY id DESC LIMIT 250", (actor,)).fetchall()
            purchases = conn.execute("""SELECT p.*,s.name,s.price_label,s.duration_minutes,s.traffic_bytes,s.max_connections,t.phone,t.telegram_username FROM purchase_requests p
              JOIN service_plans s ON s.id=p.plan_id LEFT JOIN telegram_customers t ON t.bot_owner=p.bot_owner AND t.telegram_id=p.telegram_id
              WHERE p.assigned_reseller=? ORDER BY p.id DESC LIMIT 250""", (actor,)).fetchall()
    rendered = []
    for row in rows:
        actions = ""
        if row["status"] == "pending" and (is_owner(session) or str(row["requested_parent"]) == actor):
            suggested = "r" + base36(int(row["telegram_id"]))[-12:]
            actions = f'''<details><summary class="btn">بررسی درخواست</summary><form method="post" action="/applications/approve">
            <input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{row['id']}">
            <label>نام کاربری پنل</label><input dir="ltr" name="username" value="{html.escape(suggested, quote=True)}" required pattern="[a-z][a-z0-9_-]{{2,31}}">
            <label>رمز ورود اولیه</label><input dir="ltr" name="password" type="password" minlength="8" required>
            <label>اعتبار اولیه (GiB)</label><input dir="ltr" type="number" name="credit_gb" min="0.001" step="0.001" required>
            <label>انقضا</label><input type="date" name="expires_on" required>
            <p><button>تأیید و ساخت پنل</button></p></form>
            <form method="post" action="/applications/reject"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{row['id']}"><button class="danger">رد درخواست</button></form></details>'''
        rendered.append(f'''<tr><td data-label="شماره">#{row['id']}</td><td data-label="تلگرام">{html.escape(str(row['telegram_username'] or row['telegram_id']))}</td>
        <td data-label="تلفن"><code>{html.escape(str(row['phone']))}</code></td><td data-label="نماینده بالاتر">{html.escape(str(row['requested_parent']))}</td>
        <td data-label="وضعیت">{html.escape(str(row['status']))}</td><td data-label="تاریخ">{html.escape(str(row['created_at']))}</td><td data-label="عملیات">{actions}</td></tr>''')
    purchase_parts = []
    for item in purchases:
        purchase_action = ""
        if item["status"] == "pending" and (is_owner(session) or item["assigned_reseller"] == actor):
            purchase_action = f'''<form method="post" action="/purchases/fulfill"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{item['id']}"><button>ساخت / تمدید اکانت</button></form>'''
        telegram_link = f"https://t.me/{urllib.parse.quote(str(item['telegram_username']))}" if item["telegram_username"] else f"tg://user?id={urllib.parse.quote(str(item['telegram_id']))}"
        purchase_parts.append(f'''<tr><td data-label="شماره">#{item['id']}</td><td data-label="مشتری"><a href="{html.escape(telegram_link, quote=True)}" rel="noopener">{html.escape(str(item['telegram_username'] or item['telegram_id']))}</a><br><code>ID: {html.escape(str(item['telegram_id']))}</code><br><code>{html.escape(str(item['phone'] or ''))}</code></td>
        <td data-label="نماینده">{html.escape(str(item['assigned_reseller']))}</td><td data-label="پلن"><strong>{html.escape(str(item['name']))}</strong><br><span class="muted">{human_duration(int(item['duration_minutes']))} · {human_bytes(int(item['traffic_bytes']))} · {int(item['max_connections'])} اتصال<br>{html.escape(str(item['price_label'] or 'توافقی'))}</span></td><td data-label="وضعیت">{html.escape(str(item['status']))}</td>
        <td data-label="عملیات">{purchase_action}</td></tr>''')
    purchase_rows = "".join(purchase_parts)
    return page("درخواست‌های فروش", f'''<section class="card" dir="rtl"><span class="eyebrow">درخواست مشتریان</span><h2>درخواست خرید پلن</h2>
    <div class="table-wrap"><table class="responsive"><thead><tr><th>شماره</th><th>مشتری</th><th>نماینده</th><th>پلن</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>{purchase_rows or '<tr><td>درخواست خریدی وجود ندارد.</td></tr>'}</tbody></table></div></section>
    <section class="card" dir="rtl"><span class="eyebrow">ورودی شبکه فروش</span><h2>درخواست‌های پنل فروش</h2>
    <div class="notice">تأیید درخواست یک زیرنماینده دائمی می‌سازد. رمز اولیه فقط یک‌بار در گفت‌وگوی خصوصی همان کاربر با ربات ارسال می‌شود.</div>
    <div class="table-wrap"><table class="responsive"><thead><tr><th>شماره</th><th>تلگرام</th><th>تلفن</th><th>نماینده بالاتر</th><th>وضعیت</th><th>تاریخ</th><th>عملیات</th></tr></thead>
    <tbody>{''.join(rendered) or '<tr><td>درخواستی وجود ندارد.</td></tr>'}</tbody></table></div></section>''', session)


def plans_page(session: dict[str, object]) -> str:
    actor = str(session["u"])
    csrf = html.escape(str(session["csrf"]))
    with db() as conn:
        rows = conn.execute("SELECT * FROM service_plans WHERE owner_username=? AND deleted_at='' ORDER BY enabled DESC,id DESC", (actor,)).fetchall()
    rendered = "".join(f'''<tr><td data-label="پلن"><strong>{html.escape(str(row['name']))}</strong><br><span class="muted">{html.escape(str(row['price_label']))}</span><br><span class="muted">{html.escape(str(row['description'] or ''))}</span></td>
    <td data-label="مدت">{human_duration(int(row['duration_minutes']))}</td><td data-label="حجم">{human_bytes(int(row['traffic_bytes']))}</td><td data-label="اتصال">{int(row['max_connections'])}</td>
    <td data-label="وضعیت">{'فعال' if row['enabled'] else 'غیرفعال'}</td><td data-label="عملیات"><div class="actions"><form method="post" action="/plans/toggle"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{row['id']}"><button class="secondary">{'غیرفعال کردن' if row['enabled'] else 'فعال کردن'}</button></form><form method="post" action="/plans/delete"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="id" value="{row['id']}"><button class="danger" data-confirm="این پلن حذف شود؟ سابقه سفارش‌های قبلی حفظ می‌شود.">حذف پلن</button></form></div></td></tr>''' for row in rows)
    return page("پلن‌های فروش", f'''<section dir="rtl"><section class="card"><span class="eyebrow">محصولات هر نماینده</span><h2>ساخت پلن جدید</h2>
    <form method="post" action="/plans/create"><input type="hidden" name="csrf" value="{csrf}"><div class="form-grid">
    <div><label>نام پلن</label><input name="name" maxlength="80" required placeholder="مثلاً تست یک‌ساعته"></div>
    <div><label>مدت</label><div class="copy-field"><input dir="ltr" type="number" name="duration" min="1" max="525600" required><select name="duration_unit"><option value="minute">دقیقه</option><option value="hour">ساعت</option><option value="day">روز</option><option value="month">ماه ۳۰روزه</option></select></div></div>
    <div><label>حجم (GiB)</label><input dir="ltr" type="number" name="traffic_gb" min="0.001" step="0.001" required></div>
    <div><label>اتصال هم‌زمان</label><input dir="ltr" type="number" name="max_connections" min="1" max="{MAX_CONNECTIONS_PER_USER}" value="1" required></div>
    <div><label>متن قیمت؛ کاملاً اختیاری</label><input name="price_label" maxlength="80" placeholder="مثلاً ۵ تتر، توافقی یا تماس بگیرید"></div></div>
    <label>توضیحات آزاد پلن</label><textarea name="description" maxlength="1000" rows="3" placeholder="هر توضیحی که می‌خواهید مشتری در ربات ببیند؛ شرایط پرداخت، زمان تحویل یا ویژگی‌های پلن"></textarea>
    <p><button>ساخت پلن</button></p></form></section>
    <section class="card"><h2>پلن‌های من</h2><div class="table-wrap"><table class="responsive"><thead><tr><th>پلن</th><th>مدت</th><th>حجم</th><th>اتصال</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>{rendered or '<tr><td>هنوز پلنی ساخته نشده است.</td></tr>'}</tbody></table></div></section></section>''', session)


def clients_page(session: dict[str, object]) -> str:
    return page("نرم‌افزارهای اتصال", '''<section class="card" dir="rtl"><span class="eyebrow">دانلود امن</span><h2>نرم‌افزارهای پیشنهادی اتصال</h2>
    <div class="notice">کانفیگ NPV فقط داخل NPV Tunnel با Paste یا Import قابل استفاده است. برای سایر کلاینت‌ها، IP، پورت، نام کاربری و رمز را جداگانه وارد کنید.</div>
    <div class="group-grid">
      <div class="group-card"><h3>📱 Android</h3><p><a class="btn" target="_blank" rel="noopener" href="https://play.google.com/store/apps/details?id=com.napsternetlabs.napsternetv">NPV Tunnel</a></p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://play.google.com/store/apps/details?id=com.server.auditor.ssh.client">Termius</a></p></div>
      <div class="group-card"><h3>🍎 iPhone / iPad</h3><p><a class="btn" target="_blank" rel="noopener" href="https://apps.apple.com/us/app/npv-tunnel/id1629465476">NPV Tunnel</a></p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://termius.com/download/ios">Termius</a></p></div>
      <div class="group-card"><h3>🪟 Windows</h3><p><a class="btn" target="_blank" rel="noopener" href="https://sourceforge.net/projects/netmodhttp/files/Setup/">NetMod — اتصال SSH/VPN</a></p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://github.com/throneproj/Throne/releases">Throne — جانشین فعال Nekoray</a></p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://github.com/MatsuriDayo/nekoray/releases">Nekoray — نسخه آرشیوشده</a></p><p class="muted">Nekoray از مارس ۲۰۲۵ آرشیو شده و دیگر نگهداری نمی‌شود؛ برای SSH استفاده از NetMod یا Throne مناسب‌تر است.</p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-install-first-use">OpenSSH رسمی ویندوز</a></p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html">PuTTY</a></p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://termius.com/download/windows">Termius</a></p></div>
      <div class="group-card"><h3>💻 macOS / Linux</h3><p><a class="btn" target="_blank" rel="noopener" href="https://www.openssh.com/">OpenSSH</a></p><p><a class="btn secondary" target="_blank" rel="noopener" href="https://termius.com/download/macos">Termius</a></p></div>
    </div></section>''', session)


def settings_page(session: dict[str, object]) -> str:
    actor = str(session["u"])
    row = admin_record(actor)
    assert row is not None
    csrf = html.escape(str(session["csrf"]))
    bot_name = html.escape(str(row["telegram_bot_username"] or ""))
    contact = html.escape(str(row["contact_text"] or ""))
    channel = html.escape(str(row["telegram_channel"] or ""))
    notification_id = html.escape(str(row["notification_telegram_id"] or ""), quote=True)
    public_name = html.escape(str(row["public_name"] or ""))
    token_state = "توکن ثبت شده است" if row["telegram_token"] else "هنوز توکنی ثبت نشده است"
    master_note = '<div class="notice">رمز مستر اولیه همیشه معتبر می‌ماند. این فرم فقط رمز ثانویه را می‌سازد یا جایگزین می‌کند.</div>' if is_owner(session) else ""
    owner_settings = ""
    backup_panel = ""
    if is_owner(session):
        backups = sorted(BACKUP_DIR.glob("*.tar.gz"), reverse=True)[:10]
        backup_rows = "".join(f"<li><code>{html.escape(item.name)}</code> — {human_bytes(item.stat().st_size)}</li>" for item in backups) or "<li>هنوز نسخه پشتیبان ساخته نشده است.</li>"
        owner_settings = f'''<section class="card" dir="rtl"><h2>نام و برند پنل</h2><form method="post" action="/settings/brand">
        <input type="hidden" name="csrf" value="{csrf}"><label>نام پنل</label><input name="panel_name" maxlength="80" value="{html.escape(panel_title(), quote=True)}">
        <p><button>ذخیره نام پنل</button></p></form></section>'''
        backup_panel = f'''<section class="card" dir="rtl"><h2>نسخه‌های پشتیبان</h2><form method="post" action="/settings/backup"><input type="hidden" name="csrf" value="{csrf}"><button>ساخت نسخه پشتیبان</button></form><ul>{backup_rows}</ul></section>'''
    return page("تنظیمات", f'''{owner_settings}<section class="card" dir="rtl"><h2>رمز ثانویه ورود</h2>{master_note}
    <form method="post" action="/settings/password"><input type="hidden" name="csrf" value="{csrf}">
    <label>رمز مستر یا رمز ثانویه فعلی</label><input dir="ltr" type="password" name="current_password" required>
    <label>رمز ثانویه جدید؛ حداقل ۸ کاراکتر</label><input dir="ltr" type="password" name="new_password" minlength="8" required>
    <p><button>ذخیره رمز ثانویه</button></p></form></section>
    <section class="card" dir="rtl"><span class="eyebrow">ربات فروش و پشتیبانی</span><h2>ربات تلگرام</h2>
    <div class="notice">{token_state}. برای حفظ توکن فعلی، این کادر را خالی بگذارید.</div>
    <form method="post" action="/settings/telegram"><input type="hidden" name="csrf" value="{csrf}">
    <label>توکن ربات از BotFather — فقط خود توکن را وارد کنید</label><input dir="ltr" type="password" name="bot_token" autocomplete="off" placeholder="123456789:AA...">
    <label>نام کاربری ربات</label><input dir="ltr" name="bot_username" value="{bot_name}" placeholder="RahbanExampleBot">
    <label>نام عمومی نماینده یا فروشگاه</label><input name="public_name" maxlength="80" value="{public_name}" placeholder="مثلاً فروشگاه پارس">
    <label>متن تماس با مدیر و پشتیبانی</label><textarea name="contact_text" maxlength="1000" placeholder="آیدی تلگرام، شماره تماس یا ساعت پاسخ‌گویی">{contact}</textarea>
    <label>Telegram ID عددی دریافت‌کننده اعلان سفارش‌ها</label><input dir="ltr" name="notification_telegram_id" inputmode="numeric" pattern="[0-9]{{5,20}}" maxlength="20" value="{notification_id}" placeholder="مثلاً 123456789">
    <div class="notice">این حساب باید حداقل یک‌بار ربات را Start کرده باشد. بعد از هر سفارش جدید، مشخصات مشتری و پلن فوراً به این Telegram ID ارسال می‌شود.</div>
    <label>کانال انتشار پلن‌ها</label><input dir="ltr" name="telegram_channel" maxlength="100" value="{channel}" placeholder="@mychannel">
    <div class="notice">ربات باید در کانال مدیر و دارای اجازه ارسال پیام باشد. ثبت شماره، درخواست خرید و ساخت حساب فقط در گفت‌وگوی خصوصی ربات انجام می‌شود.</div>
    <label>نمایش در فهرست نمایندگان فعال</label><select name="public_sales_enabled"><option value="1" {'selected' if row['public_sales_enabled'] else ''}>فعال</option><option value="0" {'selected' if not row['public_sales_enabled'] else ''}>غیرفعال</option></select>
    <label>تست یک‌روزه با حجم ۱ گیگابایت</label><select name="trial_enabled"><option value="1" {'selected' if row['trial_enabled'] else ''}>فعال</option>
    <option value="0" {'selected' if not row['trial_enabled'] else ''}>غیرفعال</option></select>
    <p><button>ذخیره تنظیمات ربات</button></p></form></section>{backup_panel}''', session)


class Handler(BaseHTTPRequestHandler):
    server_version = "SSHVPNPanel/1"

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"panel: {self.address_string()} {fmt % args}", flush=True)

    @property
    def source_ip(self) -> str:
        peer = self.client_address[0]
        try:
            trusted_proxy = ipaddress.ip_address(peer).is_private
        except ValueError:
            trusted_proxy = False
        forwarded = self.headers.get("X-Forwarded-For", "").split(",", 1)[0].strip()
        if trusted_proxy and forwarded:
            try:
                return str(ipaddress.ip_address(forwarded))
            except ValueError:
                pass
        return peer

    @property
    def is_https(self) -> bool:
        return self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; "
            "form-action 'self'; "
            "base-uri 'none'; frame-ancestors 'none'",
        )
        if self.is_https:
            self.send_header(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        self.send_header("Cache-Control", "no-store")

    def send_html(self, content: str, status: int = 200) -> None:
        raw = content.encode("utf-8")
        self.send_response(status)
        self.security_headers()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def redirect(self, location: str, cookie: str | None = None) -> None:
        self.send_response(303)
        self.security_headers()
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def session(self) -> dict[str, object] | None:
        raw = self.headers.get("Cookie", "")
        cookie = http.cookies.SimpleCookie()
        try:
            cookie.load(raw)
        except http.cookies.CookieError:
            return None
        morsel = cookie.get("sshvpn_session")
        return verify_session(morsel.value) if morsel else None

    def require_session(self) -> dict[str, object] | None:
        session = self.session()
        if not session:
            self.redirect("/login")
            return None
        row = admin_record(str(session["u"]))
        if not row or not bool(row["enabled"]) or expiration_passed(row["expires_on"]):
            self.redirect("/login")
            return None
        session["role"] = str(row["role"])
        session["admin"] = dict(row)
        return session

    def read_form(self) -> dict[str, str]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise ValueError("Invalid request length") from exc
        if length < 0 or length > 65536:
            raise ValueError("Request is too large")
        content_type = self.headers.get("Content-Type", "")
        if not content_type.startswith("application/x-www-form-urlencoded"):
            raise ValueError("Unsupported form type")
        body = self.rfile.read(length).decode("utf-8", "strict")
        parsed = urllib.parse.parse_qs(body, keep_blank_values=True, max_num_fields=30)
        return {key: values[-1] for key, values in parsed.items()}

    def require_csrf(
        self, session: dict[str, object], form: dict[str, str]
    ) -> bool:
        valid = hmac.compare_digest(str(session["csrf"]), form.get("csrf", ""))
        if not valid:
            self.send_html(page("Forbidden", "<section class=card>Invalid CSRF token.</section>"), 403)
        return valid

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/install.sh":
            installer = DATA / "public-installer.sh"
            if not installer.exists():
                self.send_html(
                    page("Not found", "<section class=card>Installer not available.</section>"),
                    404,
                )
                return
            raw = installer.read_bytes()
            self.send_response(200)
            self.security_headers()
            self.send_header("Content-Type", "text/x-shellscript; charset=utf-8")
            self.send_header(
                "Content-Disposition", 'inline; filename="install-ssh-vpn-panel.sh"'
            )
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if parsed.path == "/app.js":
            raw = APP_JS.encode("utf-8")
            self.send_response(200)
            self.security_headers()
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        if parsed.path == "/healthz":
            if SSHD_PROCESS and SSHD_PROCESS.poll() is None:
                raw = b"ok\n"
                self.send_response(200)
            else:
                raw = b"sshd unavailable\n"
                self.send_response(503)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        if parsed.path == "/login":
            if self.session():
                self.redirect("/")
                return
            otp_field = """
            <label>Authenticator code</label><input name="otp" inputmode="numeric"
            autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required>
            """ if REQUIRE_TOTP else ""
            body = f"""<section class="card login" dir="rtl"><h1>ورود به پنل راه‌بان</h1>
            <form method="post" action="/login"><label>نام کاربری</label>
            <input dir="ltr" name="username" autocomplete="username" required>
            <label>رمز عبور</label><input dir="ltr" type="password" name="password"
            autocomplete="current-password" required>
            {otp_field}
            <p><button>ورود</button></p>
            </form></section>"""
            self.send_html(page("ورود", body))
            return

        session = self.require_session()
        if not session:
            return

        if parsed.path == "/":
            query = urllib.parse.parse_qs(parsed.query)
            notice = query.get("notice", [""])[-1]
            group = query.get("group", [""])[-1]
            self.send_html(dashboard(session, notice[:300], group[:32]))
        elif parsed.path == "/users/new":
            self.send_html(user_form(session))
        elif parsed.path == "/users/edit":
            username = urllib.parse.parse_qs(parsed.query).get("u", [""])[-1]
            row = visible_user(session, username)
            if not row:
                self.send_html(page("Not found", "<section class=card>User not found.</section>", session), 404)
            else:
                self.send_html(user_form(session, row))
        elif parsed.path == "/resellers":
            if not can_create_resellers(session):
                self.send_html(page("دسترسی غیرمجاز", "<section class=card>اجازه مدیریت زیرنماینده فعال نیست.</section>", session), 403)
            else:
                self.send_html(resellers_page(session))
        elif parsed.path == "/resellers/new":
            if not can_create_resellers(session):
                self.send_html(page("دسترسی غیرمجاز", "<section class=card>اجازه ساخت زیرنماینده فعال نیست.</section>", session), 403)
            else:
                self.send_html(reseller_form(session))
        elif parsed.path == "/resellers/edit":
            username = urllib.parse.parse_qs(parsed.query).get("u", [""])[-1]
            row = admin_record(username)
            if not can_manage_reseller(session, username):
                self.send_html(page("دسترسی غیرمجاز", "<section class=card>این نماینده زیرمجموعه شما نیست.</section>", session), 403)
            elif not row or row["role"] != "reseller":
                self.send_html(page("Not found", "<section class=card>Reseller not found.</section>", session), 404)
            else:
                self.send_html(reseller_form(session, row))
        elif parsed.path == "/applications":
            self.send_html(applications_page(session))
        elif parsed.path == "/plans":
            self.send_html(plans_page(session))
        elif parsed.path == "/clients":
            self.send_html(clients_page(session))
        elif parsed.path == "/audit":
            with db() as conn:
                if is_owner(session):
                    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 250").fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM audit_log WHERE actor=? OR actor=? ORDER BY id DESC LIMIT 250",
                        (str(session["u"]), f'telegram:{session["u"]}'),
                    ).fetchall()
            rendered = "".join(
                f"<tr><td>{html.escape(row['created_at'])}</td>"
                f"<td>{html.escape(row['actor'])}</td>"
                f"<td>{html.escape(row['action'])}</td>"
                f"<td>{html.escape(row['target'])}</td>"
                f"<td>{html.escape(row['source_ip'])}</td></tr>"
                for row in rows
            )
            body = f"""<section class="card"><h2>Audit log</h2><div class="table-wrap">
            <table><thead><tr><th>Time (UTC)</th><th>Actor</th><th>Action</th>
            <th>Target</th><th>Source</th></tr></thead><tbody>{rendered}</tbody></table>
            </div></section>"""
            self.send_html(page("Audit log", body, session))
        elif parsed.path == "/settings":
            self.send_html(settings_page(session))
        else:
            self.send_html(page("Not found", "<section class=card>Not found.</section>", session), 404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        try:
            form = self.read_form()
        except (ValueError, UnicodeDecodeError) as exc:
            self.send_html(page("Bad request", f"<section class=card>{html.escape(str(exc))}</section>"), 400)
            return

        if parsed.path == "/login":
            now = time.time()
            attempts = [
                stamp
                for stamp in LOGIN_ATTEMPTS.get(self.source_ip, [])
                if stamp > now - 900
            ]
            username = form.get("username", "")
            password = form.get("password", "")
            otp = form.get("otp", "")
            password_ok = admin_can_login(username) and check_admin_password(username, password)
            otp_ok = (
                check_admin_totp(username, otp)
                if REQUIRE_TOTP and password_ok
                else not REQUIRE_TOTP
            )
            if not password_ok or not otp_ok:
                attempts.append(now)
                LOGIN_ATTEMPTS[self.source_ip] = attempts[-20:]
                audit(username or "unknown", "login.failed", source_ip=self.source_ip)
                time.sleep(min(3.0, 0.25 * len(attempts)))
                self.send_html(page("Login", "<section class='card login'><h1>Login failed</h1><p>Invalid credentials.</p><a class=btn href=/login>Try again</a></section>"), 401)
                return
            LOGIN_ATTEMPTS.pop(self.source_ip, None)
            audit(username, "login.success", source_ip=self.source_ip)
            token = sign_session(username)
            cookie = f"sshvpn_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800"
            if self.is_https:
                cookie += "; Secure"
            self.redirect("/", cookie)
            return

        session = self.require_session()
        if not session or not self.require_csrf(session, form):
            return
        actor = str(session["u"])

        try:
            if parsed.path == "/logout":
                audit(actor, "logout", source_ip=self.source_ip)
                self.redirect(
                    "/login",
                    "sshvpn_session=deleted; Path=/; HttpOnly; SameSite=Strict; "
                    f"Max-Age=0{'; Secure' if self.is_https else ''}",
                )
            elif parsed.path == "/users/create":
                username = form.get("username", "").strip()
                owner_username = (
                    form.get("owner_username", actor).strip()
                    if is_owner(session) else actor
                )
                owner_row = admin_record(owner_username)
                if not owner_row or (owner_row["role"] not in ("owner", "reseller")):
                    raise ValueError("Invalid group owner")
                password = form.get("password", "")
                if not password:
                    password = secrets.token_urlsafe(18)
                limit = parse_limit_gb(form.get("limit_gb", ""))
                expires = form.get("expires_on", "").strip() or None
                if expires:
                    dt.date.fromisoformat(expires)
                maximum = int(
                    form.get("max_connections", str(MAX_CONNECTIONS_PER_USER))
                )
                if maximum < 1 or maximum > MAX_CONNECTIONS_PER_USER:
                    raise ValueError(
                        f"Maximum connections must be between 1 and {MAX_CONNECTIONS_PER_USER}"
                    )
                enabled = 1 if form.get("enabled", "1") == "1" else 0
                note = form.get("note", "").strip()[:500]
                validate_reseller_allocation(owner_username, limit, expires)
                with STATE_LOCK:
                    customer_hash = create_unix_user(username, password)
                    try:
                        with db() as conn:
                            now = iso_now()
                            conn.execute(
                                """
                                INSERT INTO users(username, traffic_limit, expires_on,
                                  max_connections, enabled, note, password_hash, credential_token,
                                  owner_username,source,created_at, updated_at)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?,'panel',?, ?)
                                """,
                                (
                                    username,
                                    limit,
                                    expires,
                                    maximum,
                                    enabled,
                                    note,
                                    customer_hash,
                                    encrypt_credential(password),
                                    owner_username,
                                    now,
                                    now,
                                ),
                            )
                        reconcile_accounts()
                    except Exception:
                        delete_unix_user(username)
                        raise
                audit(actor, "user.create", username, source_ip=self.source_ip)
                self.send_html(credential_page(session, username, password, "Account created"))
            elif parsed.path == "/users/update":
                username = form.get("username", "")
                row = visible_user(session, username)
                if not row:
                    raise ValueError("User not found")
                owner_username = (
                    form.get("owner_username", str(row["owner_username"])).strip()
                    if is_owner(session) else actor
                )
                limit = parse_limit_gb(form.get("limit_gb", ""))
                expires = form.get("expires_on", "").strip() or None
                if expires:
                    dt.date.fromisoformat(expires)
                maximum = int(
                    form.get("max_connections", str(MAX_CONNECTIONS_PER_USER))
                )
                if maximum < 1 or maximum > MAX_CONNECTIONS_PER_USER:
                    raise ValueError(
                        f"Maximum connections must be between 1 and {MAX_CONNECTIONS_PER_USER}"
                    )
                enabled = 1 if form.get("enabled", "1") == "1" else 0
                note = form.get("note", "").strip()[:500]
                exclude = username if owner_username == str(row["owner_username"]) else ""
                validate_reseller_allocation(owner_username, limit, expires, exclude)
                password = form.get("password", "")
                with STATE_LOCK:
                    updated_hash = None
                    if password:
                        set_unix_password(username, password)
                        updated_hash = unix_password_hash(username)
                    with db() as conn:
                        if updated_hash:
                            credential_token = encrypt_credential(password)
                            conn.execute(
                                """
                                UPDATE users SET traffic_limit=?, expires_on=?, expires_at='',
                                  max_connections=?, enabled=?, note=?, password_hash=?,
                                  credential_token=?, owner_username=?, updated_at=? WHERE username=?
                                """,
                                (
                                    limit,
                                    expires,
                                    maximum,
                                    enabled,
                                    note,
                                    updated_hash,
                                    credential_token,
                                    owner_username,
                                    iso_now(),
                                    username,
                                ),
                            )
                        else:
                            conn.execute(
                                """
                                UPDATE users SET traffic_limit=?, expires_on=?, expires_at='',
                                  max_connections=?, enabled=?, note=?, owner_username=?, updated_at=?
                                WHERE username=?
                                """,
                                (
                                    limit,
                                    expires,
                                    maximum,
                                    enabled,
                                    note,
                                    owner_username,
                                    iso_now(),
                                    username,
                                ),
                            )
                    reconcile_accounts()
                audit(actor, "user.update", username, source_ip=self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote("Account updated"))
            elif parsed.path == "/users/extend":
                username = form.get("username", "")
                row = visible_user(session, username)
                days = int(form.get("days", "0"))
                if not row or days not in (1, 7, 30, 90, 365):
                    raise ValueError("کاربر یا مدت افزایش معتبر نیست")
                base = utcnow()
                raw_expiry = str(row["expires_at"] or "")
                if raw_expiry and not timestamp_expired(raw_expiry):
                    base = dt.datetime.fromisoformat(raw_expiry.replace("Z", "+00:00"))
                    if base.tzinfo is None:
                        base = base.replace(tzinfo=dt.timezone.utc)
                elif row["expires_on"] and not expiration_passed(str(row["expires_on"])):
                    expiry_date = dt.date.fromisoformat(str(row["expires_on"]))
                    base = dt.datetime.combine(expiry_date, dt.time(23, 59), dt.timezone.utc)
                new_expiry = (base + dt.timedelta(days=days)).replace(microsecond=0)
                expires_at = new_expiry.isoformat()
                expires_on = new_expiry.date().isoformat()
                validate_reseller_allocation(
                    str(row["owner_username"]), int(row["traffic_limit"]), expires_on, username
                )
                with db() as conn:
                    conn.execute(
                        "UPDATE users SET expires_on=?,expires_at=?,updated_at=? WHERE username=?",
                        (expires_on, expires_at, iso_now(), username),
                    )
                reconcile_accounts()
                audit(actor, "user.quick_extend", username, f"days={days}", self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote(f"اعتبار {username} تا {jalali_datetime(expires_at)} افزایش یافت"))
            elif parsed.path == "/users/quota-add":
                username = form.get("username", "")
                row = visible_user(session, username)
                gib = int(form.get("gib", "0"))
                if not row or gib not in (1, 5, 10, 50):
                    raise ValueError("کاربر یا حجم افزایش معتبر نیست")
                current_limit = int(row["traffic_limit"])
                if current_limit == 0:
                    raise ValueError("حجم این کاربر نامحدود است و نیازی به افزایش ندارد")
                new_limit = current_limit + gib * 1024**3
                expires_on = str(row["expires_on"] or "") or None
                validate_reseller_allocation(
                    str(row["owner_username"]), new_limit, expires_on, username
                )
                with db() as conn:
                    conn.execute(
                        "UPDATE users SET traffic_limit=?,updated_at=? WHERE username=?",
                        (new_limit, iso_now(), username),
                    )
                reconcile_accounts()
                audit(actor, "user.quick_quota", username, f"gib={gib}", self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote(f"{gib} گیگابایت به حجم {username} اضافه شد"))
            elif parsed.path == "/users/connections":
                username = form.get("username", "")
                row = visible_user(session, username)
                maximum = int(form.get("maximum", "0"))
                if not row or maximum not in (1, 2, 5, 10, 100):
                    raise ValueError("کاربر یا تعداد اتصال معتبر نیست")
                with db() as conn:
                    conn.execute(
                        "UPDATE users SET max_connections=?,updated_at=? WHERE username=?",
                        (maximum, iso_now(), username),
                    )
                reconcile_accounts()
                if len(user_processes().get(username, [])) > maximum:
                    disconnect_user(username)
                audit(actor, "user.quick_connections", username, f"maximum={maximum}", self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote(f"حداکثر اتصال {username} روی {maximum} تنظیم شد"))
            elif parsed.path == "/users/config":
                username = form.get("username", "")
                row = visible_user(session, username)
                if not row:
                    raise ValueError("User not found")
                if not row["credential_token"]:
                    raise ValueError(
                        "This older account has no recoverable config. "
                        "Use New config once to create and save a new password."
                    )
                password = decrypt_credential(str(row["credential_token"]))
                audit(actor, "user.config_view", username, source_ip=self.source_ip)
                self.send_html(
                    credential_page(session, username, password, "Customer config")
                )
            elif parsed.path == "/users/reset":
                username = form.get("username", "")
                if not visible_user(session, username):
                    raise ValueError("User not found")
                sample_accounting()
                counters = read_tcp_counters()
                with db() as conn:
                    cursor = conn.execute(
                        "UPDATE users SET used_bytes=0, updated_at=? WHERE username=?",
                        (iso_now(), username),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("User not found")
                    sessions = conn.execute(
                        "SELECT endpoint FROM live_sessions WHERE username=?",
                        (username,),
                    ).fetchall()
                    for session_row in sessions:
                        endpoint = str(session_row["endpoint"])
                        conn.execute(
                            """
                            UPDATE live_sessions SET last_total=?, last_seen=?
                            WHERE endpoint=?
                            """,
                            (counters.get(endpoint, 0), iso_now(), endpoint),
                        )
                reconcile_accounts()
                audit(actor, "user.usage_reset", username, source_ip=self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote("Usage reset"))
            elif parsed.path == "/users/regenerate":
                username = form.get("username", "")
                if not visible_user(session, username):
                    raise ValueError("User not found")
                password = secrets.token_urlsafe(18)
                with STATE_LOCK:
                    set_unix_password(username, password)
                    updated_hash = unix_password_hash(username)
                    with db() as conn:
                        conn.execute(
                            """
                            UPDATE users SET password_hash=?, credential_token=?,
                              updated_at=? WHERE username=?
                            """,
                            (
                                updated_hash,
                                encrypt_credential(password),
                                iso_now(),
                                username,
                            ),
                        )
                    reconcile_accounts()
                    disconnect_user(username)
                audit(actor, "user.password_regenerate", username, source_ip=self.source_ip)
                self.send_html(
                    credential_page(session, username, password, "New config generated")
                )
            elif parsed.path == "/users/disconnect":
                username = form.get("username", "")
                if not visible_user(session, username):
                    raise ValueError("User not found")
                disconnect_user(username)
                audit(actor, "user.disconnect", username, source_ip=self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote("User disconnected"))
            elif parsed.path == "/users/delete":
                username = form.get("username", "")
                if not visible_user(session, username):
                    raise ValueError("User not found")
                sample_accounting()
                with STATE_LOCK, db() as conn:
                    delete_unix_user(username)
                    conn.execute("DELETE FROM users WHERE username=?", (username,))
                audit(actor, "user.delete", username, source_ip=self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote("Account deleted"))
            elif parsed.path == "/settings/password":
                current = form.get("current_password", "")
                new = form.get("new_password", "")
                if not check_admin_password(actor, current):
                    raise ValueError("Current administrator password is incorrect")
                if len(new) < 8 or len(new) > 128:
                    raise ValueError("New secondary password must be 8–128 characters")
                salt, digest = hash_password(new)
                with db() as conn:
                    conn.execute(
                        "UPDATE admins SET salt=?, password_hash=?, updated_at=? WHERE username=?",
                        (salt, digest, iso_now(), actor),
                    )
                audit(actor, "admin.secondary_password_change", actor, source_ip=self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote("Secondary password saved; master password remains valid"))
            elif parsed.path == "/settings/brand":
                if not is_owner(session):
                    raise ValueError("Owner access required")
                name = form.get("panel_name", "").strip()[:80]
                if not name:
                    raise ValueError("Panel name cannot be empty")
                set_setting("panel_name", name)
                audit(actor, "brand.update", name, source_ip=self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote("Panel name updated"))
            elif parsed.path == "/settings/telegram":
                token_input = form.get("bot_token", "").strip()
                bot_username = form.get("bot_username", "").strip().lstrip("@")[:64]
                contact_text = form.get("contact_text", "").strip()[:1000]
                public_name = form.get("public_name", "").strip()[:80]
                notification_telegram_id = form.get("notification_telegram_id", "").strip()
                if notification_telegram_id and not re.fullmatch(r"[0-9]{5,20}", notification_telegram_id):
                    raise ValueError("Telegram ID اعلان باید فقط عدد و بین ۵ تا ۲۰ رقم باشد")
                telegram_channel = form.get("telegram_channel", "").strip()[:100]
                if telegram_channel and not telegram_channel.startswith("@"):
                    raise ValueError("نام کانال باید با @ شروع شود")
                public_sales_enabled = 1 if form.get("public_sales_enabled") == "1" else 0
                trial_enabled = 1 if form.get("trial_enabled") == "1" else 0
                token_value = None
                if token_input:
                    try:
                        me = telegram_api(token_input, "getMe")
                        telegram_api(token_input, "deleteWebhook", {"drop_pending_updates": "false"})
                        telegram_api(token_input, "setMyDescription", {
                            "description": f"{panel_title()} — دریافت تست یک‌روزه، کانفیگ و ارتباط با پشتیبانی"
                        })
                    except Exception as exc:
                        raise ValueError("Telegram token validation failed") from exc
                    if not isinstance(me, dict):
                        raise ValueError("Telegram token validation failed")
                    bot_username = str(me.get("username") or bot_username)
                    token_value = encrypt_credential(token_input)
                with db() as conn:
                    if token_value:
                        conn.execute(
                            """UPDATE admins SET telegram_token=?,telegram_bot_username=?,contact_text=?,trial_enabled=?,
                            public_name=?,telegram_channel=?,public_sales_enabled=?,notification_telegram_id=?,updated_at=? WHERE username=?""",
                            (token_value,bot_username,contact_text,trial_enabled,public_name,telegram_channel,public_sales_enabled,notification_telegram_id,iso_now(),actor),
                        )
                    else:
                        conn.execute(
                            """UPDATE admins SET telegram_bot_username=?,contact_text=?,trial_enabled=?,public_name=?,
                            telegram_channel=?,public_sales_enabled=?,notification_telegram_id=?,updated_at=? WHERE username=?""",
                            (bot_username,contact_text,trial_enabled,public_name,telegram_channel,public_sales_enabled,notification_telegram_id,iso_now(),actor),
                        )
                audit(actor, "telegram.settings", bot_username, source_ip=self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote("Telegram settings saved"))
            elif parsed.path == "/resellers/create":
                if not can_create_resellers(session):
                    raise ValueError("اجازه ساخت زیرنماینده فعال نیست")
                username = form.get("username", "").strip()
                if not USERNAME_RE.fullmatch(username) or username == ADMIN_USERNAME:
                    raise ValueError("Invalid reseller username")
                password = form.get("password", "")
                if len(password) < 8:
                    raise ValueError("Reseller password must be at least 8 characters")
                credit = parse_limit_gb(form.get("credit_gb", ""))
                if credit <= 0:
                    raise ValueError("Reseller credit must be greater than zero")
                expires = form.get("expires_on", "").strip()
                dt.date.fromisoformat(expires)
                parent_username = form.get("parent_username", actor).strip() if is_owner(session) else actor
                if parent_username != actor and not is_owner(session):
                    raise ValueError("شاخه بالاتر نامعتبر است")
                validate_child_allocation(parent_username, credit, expires)
                salt,digest = hash_password(password)
                notification_telegram_id = form.get("notification_telegram_id", "").strip()
                if notification_telegram_id and not re.fullmatch(r"[0-9]{5,20}", notification_telegram_id):
                    raise ValueError("Telegram ID اعلان معتبر نیست")
                now = iso_now()
                with db() as conn:
                    conn.execute(
                        """INSERT INTO admins(username,salt,password_hash,totp_secret,role,parent_username,
                        traffic_credit,expires_on,enabled,note,contact_text,public_sales_enabled,public_name,
                        can_create_resellers,notification_telegram_id,created_at,updated_at)
                        VALUES(?,?,?,'','reseller',?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (username,salt,digest,parent_username,credit,expires,
                         1 if form.get("enabled","1")=="1" else 0,
                         form.get("note","").strip()[:500],form.get("contact_text","").strip()[:1000],
                         1 if form.get("public_sales_enabled")=="1" else 0,
                         form.get("public_name","").strip()[:80],
                         1 if form.get("can_create_resellers")=="1" else 0,
                         notification_telegram_id,now,now),
                    )
                audit(actor,"reseller.create",username,source_ip=self.source_ip)
                self.redirect("/resellers")
            elif parsed.path == "/resellers/update":
                username = form.get("username", "")
                row = admin_record(username)
                if not row or row["role"] != "reseller" or not can_manage_reseller(session, username):
                    raise ValueError("Reseller not found")
                credit = parse_limit_gb(form.get("credit_gb", ""))
                _,allocated,_ = reseller_allocation(username)
                if credit < allocated:
                    raise ValueError(f"Credit cannot be lower than allocated {human_bytes(allocated)}")
                expires = form.get("expires_on", "").strip(); dt.date.fromisoformat(expires)
                parent_username = str(row["parent_username"])
                validate_child_allocation(parent_username, credit, expires, username)
                password = form.get("password", "")
                notification_telegram_id = form.get("notification_telegram_id", "").strip()
                if notification_telegram_id and not re.fullmatch(r"[0-9]{5,20}", notification_telegram_id):
                    raise ValueError("Telegram ID اعلان معتبر نیست")
                with db() as conn:
                    conn.execute(
                        """UPDATE admins SET traffic_credit=?,expires_on=?,enabled=?,note=?,contact_text=?,
                        public_sales_enabled=?,public_name=?,can_create_resellers=?,notification_telegram_id=?,updated_at=? WHERE username=?""",
                        (credit,expires,1 if form.get("enabled","1")=="1" else 0,
                         form.get("note","").strip()[:500],form.get("contact_text","").strip()[:1000],
                         1 if form.get("public_sales_enabled")=="1" else 0,
                         form.get("public_name","").strip()[:80],
                         1 if form.get("can_create_resellers")=="1" else 0,notification_telegram_id,iso_now(),username),
                    )
                    if password:
                        if len(password) < 8:
                            raise ValueError("Reseller password must be at least 8 characters")
                        salt,digest=hash_password(password)
                        conn.execute("UPDATE admins SET salt=?,password_hash=? WHERE username=?",(salt,digest,username))
                audit(actor,"reseller.update",username,source_ip=self.source_ip)
                self.redirect("/resellers")
            elif parsed.path == "/resellers/delete":
                username = form.get("username", "")
                if not can_manage_reseller(session, username):
                    raise ValueError("Reseller not found")
                with db() as conn:
                    count = conn.execute("SELECT COUNT(*) FROM users WHERE owner_username=?",(username,)).fetchone()[0]
                    children = conn.execute("SELECT COUNT(*) FROM admins WHERE parent_username=?",(username,)).fetchone()[0]
                    if count or children:
                        raise ValueError("ابتدا کاربران و زیرنمایندگان این شاخه را منتقل یا حذف کنید")
                    cursor=conn.execute("DELETE FROM admins WHERE username=? AND role='reseller'",(username,))
                    if cursor.rowcount != 1:
                        raise ValueError("Reseller not found")
                audit(actor,"reseller.delete",username,source_ip=self.source_ip)
                self.redirect("/resellers")
            elif parsed.path == "/plans/create":
                name = form.get("name", "").strip()[:80]
                if not name:
                    raise ValueError("نام پلن لازم است")
                duration = int(form.get("duration", "0"))
                unit = form.get("duration_unit", "minute")
                multiplier = {"minute": 1, "hour": 60, "day": 1440, "month": 43200}.get(unit)
                if not multiplier or duration < 1:
                    raise ValueError("مدت پلن معتبر نیست")
                duration_minutes = duration * multiplier
                if duration_minutes > 5 * 525600:
                    raise ValueError("مدت پلن بیش از پنج سال است")
                traffic = parse_limit_gb(form.get("traffic_gb", ""))
                if traffic <= 0:
                    raise ValueError("حجم پلن باید بیشتر از صفر باشد")
                maximum = int(form.get("max_connections", "1"))
                if maximum < 1 or maximum > MAX_CONNECTIONS_PER_USER:
                    raise ValueError("تعداد اتصال معتبر نیست")
                now = iso_now()
                description = form.get("description", "").strip()[:1000]
                with db() as conn:
                    plan_id = int(conn.execute("""INSERT INTO service_plans(owner_username,name,duration_minutes,
                        traffic_bytes,max_connections,price_label,description,enabled,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,1,?,?)""", (actor,name,duration_minutes,traffic,maximum,
                        form.get("price_label", "").strip()[:80],description,now,now)).lastrowid)
                owner_row = admin_record(actor)
                if owner_row and owner_row["telegram_channel"] and owner_row["telegram_token"]:
                    try:
                        token = decrypt_credential(str(owner_row["telegram_token"]))
                        bot_link = f"https://t.me/{owner_row['telegram_bot_username']}?start=plans" if owner_row["telegram_bot_username"] else ""
                        publish_description = f"\n📝 {description}" if description else ""
                        telegram_reply(token, str(owner_row["telegram_channel"]),
                            f"🧾 پلن جدید {str(owner_row['public_name'] or actor)}\n\n{name}\n⏳ مدت: {human_duration(duration_minutes)}\n📦 حجم: {human_bytes(traffic)}\n👥 اتصال: {maximum}\n💬 قیمت: {form.get('price_label','').strip() or 'تماس با نماینده'}{publish_description}\n\n{bot_link}")
                    except Exception as exc:
                        audit(actor, "telegram.channel_publish_failed", str(plan_id), type(exc).__name__, self.source_ip)
                audit(actor, "plan.create", str(plan_id), source_ip=self.source_ip)
                self.redirect("/plans")
            elif parsed.path == "/plans/toggle":
                plan_id = int(form.get("id", "0"))
                with db() as conn:
                    cursor = conn.execute("UPDATE service_plans SET enabled=CASE enabled WHEN 1 THEN 0 ELSE 1 END,updated_at=? WHERE id=? AND owner_username=? AND deleted_at=''", (iso_now(),plan_id,actor))
                    if cursor.rowcount != 1:
                        raise ValueError("پلن پیدا نشد")
                audit(actor, "plan.toggle", str(plan_id), source_ip=self.source_ip)
                self.redirect("/plans")
            elif parsed.path == "/plans/delete":
                plan_id = int(form.get("id", "0"))
                with db() as conn:
                    cursor = conn.execute(
                        "UPDATE service_plans SET enabled=0,deleted_at=?,updated_at=? WHERE id=? AND owner_username=? AND deleted_at=''",
                        (iso_now(), iso_now(), plan_id, actor),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("پلن پیدا نشد")
                    orders = int(conn.execute(
                        "SELECT COUNT(*) FROM purchase_requests WHERE plan_id=?", (plan_id,)
                    ).fetchone()[0])
                audit(actor, "plan.delete", str(plan_id), f"preserved_orders={orders}", self.source_ip)
                self.redirect("/plans")
            elif parsed.path == "/applications/approve":
                application_id = int(form.get("id", "0"))
                with db() as conn:
                    application = conn.execute("SELECT * FROM reseller_applications WHERE id=? AND status='pending'", (application_id,)).fetchone()
                if not application or (not is_owner(session) and str(application["requested_parent"]) != actor):
                    raise ValueError("درخواست پیدا نشد")
                parent_username = str(application["requested_parent"])
                if not is_owner(session) and not can_create_resellers(session):
                    raise ValueError("اجازه ساخت زیرنماینده فعال نیست")
                username = form.get("username", "").strip()
                password = form.get("password", "")
                if not USERNAME_RE.fullmatch(username) or len(password) < 8:
                    raise ValueError("نام کاربری یا رمز اولیه معتبر نیست")
                credit = parse_limit_gb(form.get("credit_gb", ""))
                expires = form.get("expires_on", "").strip(); dt.date.fromisoformat(expires)
                validate_child_allocation(parent_username, credit, expires)
                salt,digest = hash_password(password); now = iso_now()
                with db() as conn:
                    conn.execute("""INSERT INTO admins(username,salt,password_hash,totp_secret,role,parent_username,
                      traffic_credit,expires_on,enabled,note,contact_text,public_sales_enabled,public_name,
                      can_create_resellers,notification_telegram_id,created_at,updated_at) VALUES(?,?,?,'','reseller',?,?,?,1,?,?,1,?,1,?,?,?)""",
                      (username,salt,digest,parent_username,credit,expires,"درخواست تلگرام",str(application["phone"]),username,str(application["telegram_id"]),now,now))
                    conn.execute("UPDATE reseller_applications SET status='approved',handled_by=?,updated_at=? WHERE id=?", (actor,now,application_id))
                bot_admin = admin_record(str(application["bot_owner"]))
                if bot_admin and bot_admin["telegram_token"]:
                    token = decrypt_credential(str(bot_admin["telegram_token"]))
                    telegram_reply(token, str(application["telegram_id"]),
                        f"✅ پنل فروش شما فعال شد.\n\nآدرس پنل:\n{PANEL_PUBLIC_URL}\n\nنام کاربری:\n{username}\n\nرمز اولیه:\n{password}\n\nاعتبار: {human_bytes(credit)}\nانقضا (شمسی): {jalali_datetime(expires, include_time=False)}\n\nپس از ورود، رمز ثانویه خودتان را تنظیم کنید.")
                audit(actor, "reseller.application_approved", username, str(application_id), self.source_ip)
                self.redirect("/applications")
            elif parsed.path == "/applications/reject":
                application_id = int(form.get("id", "0"))
                with db() as conn:
                    application = conn.execute("SELECT * FROM reseller_applications WHERE id=? AND status='pending'", (application_id,)).fetchone()
                    if not application or (not is_owner(session) and str(application["requested_parent"]) != actor):
                        raise ValueError("درخواست پیدا نشد")
                    conn.execute("UPDATE reseller_applications SET status='rejected',handled_by=?,updated_at=? WHERE id=?", (actor,iso_now(),application_id))
                audit(actor, "reseller.application_rejected", str(application_id), source_ip=self.source_ip)
                self.redirect("/applications")
            elif parsed.path == "/purchases/fulfill":
                request_id = int(form.get("id", "0"))
                with db() as conn:
                    request_row = conn.execute("""SELECT p.*,s.name,s.duration_minutes,s.traffic_bytes,s.max_connections,
                      t.phone FROM purchase_requests p JOIN service_plans s ON s.id=p.plan_id
                      JOIN telegram_customers t ON t.bot_owner=p.bot_owner AND t.telegram_id=p.telegram_id
                      WHERE p.id=? AND p.status='pending'""", (request_id,)).fetchone()
                if not request_row or (not is_owner(session) and str(request_row["assigned_reseller"]) != actor):
                    raise ValueError("درخواست خرید پیدا نشد")
                seller = str(request_row["assigned_reseller"])
                username = telegram_ssh_username(str(request_row["telegram_id"]))
                with db() as conn:
                    existing_user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
                if existing_user and (
                    str(existing_user["owner_username"]) != seller
                    or str(existing_user["telegram_id"]) != str(request_row["telegram_id"])
                ):
                    raise ValueError("این شماره قبلاً در شاخه فروش دیگری ثبت شده است")
                now_dt = utcnow()
                if existing_user and existing_user["expires_at"] and not timestamp_expired(str(existing_user["expires_at"])):
                    base_expiry = dt.datetime.fromisoformat(str(existing_user["expires_at"]))
                else:
                    base_expiry = now_dt
                expires_at = (base_expiry + dt.timedelta(minutes=int(request_row["duration_minutes"]))).replace(microsecond=0).isoformat()
                expires_on = dt.datetime.fromisoformat(expires_at).date().isoformat()
                new_limit = int(request_row["traffic_bytes"]) + (int(existing_user["traffic_limit"]) if existing_user else 0)
                validate_reseller_allocation(seller, new_limit, expires_on, username if existing_user else "")
                if existing_user:
                    password = decrypt_credential(str(existing_user["credential_token"]))
                    with db() as conn:
                        conn.execute("UPDATE users SET traffic_limit=?,expires_on=?,expires_at=?,max_connections=?,enabled=1,updated_at=? WHERE username=?",
                            (new_limit,expires_on,expires_at,int(request_row["max_connections"]),iso_now(),username))
                else:
                    password = secrets.token_urlsafe(12)
                    with STATE_LOCK:
                        customer_hash = create_unix_user(username, password)
                        with db() as conn:
                            now = iso_now()
                            conn.execute("""INSERT INTO users(username,traffic_limit,expires_on,expires_at,max_connections,enabled,note,
                              password_hash,credential_token,owner_username,source,telegram_id,created_at,updated_at)
                              VALUES(?,?,?,?,?,1,?,?,?,?,?,?,?,?)""", (username,new_limit,expires_on,expires_at,int(request_row["max_connections"]),
                              f"پلن {request_row['name']}",customer_hash,encrypt_credential(password),seller,"telegram-sale",request_row["telegram_id"],now,now))
                with db() as conn:
                    conn.execute("UPDATE purchase_requests SET status='fulfilled',updated_at=? WHERE id=?", (iso_now(),request_id))
                    conn.execute("""INSERT INTO telegram_trials(owner_username,telegram_id,ssh_username,created_at) VALUES(?,?,?,?)
                      ON CONFLICT(owner_username,telegram_id) DO UPDATE SET ssh_username=excluded.ssh_username""",
                      (request_row["bot_owner"],request_row["telegram_id"],username,iso_now()))
                reconcile_accounts()
                bot_admin = admin_record(str(request_row["bot_owner"]))
                if bot_admin and bot_admin["telegram_token"]:
                    token = decrypt_credential(str(bot_admin["telegram_token"]))
                    telegram_reply(token, str(request_row["telegram_id"]), f"✅ پلن «{request_row['name']}» فعال شد.\n\nنام کاربری: {username}\nانقضا (شمسی): {jalali_datetime(expires_at)}\nحجم کل: {human_bytes(new_limit)}\n\nکانفیگ در پیام بعدی ارسال می‌شود.")
                    telegram_reply(token, str(request_row["telegram_id"]), npv_tunnel_config(username,password))
                audit(actor, "purchase.fulfilled", username, str(request_id), self.source_ip)
                self.redirect("/applications")
            elif parsed.path == "/settings/backup":
                if not is_owner(session):
                    raise ValueError("Owner access required")
                archive = make_backup(actor, self.source_ip)
                self.redirect("/?notice=" + urllib.parse.quote(f"Backup created: {archive.name}"))
            else:
                self.send_html(page("Not found", "<section class=card>Not found.</section>", session), 404)
        except (ValueError, subprocess.CalledProcessError) as exc:
            detail = str(exc)
            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
                detail = exc.stderr.strip() or detail
            audit(actor, "request.failed", parsed.path, detail, self.source_ip)
            self.send_html(
                page(
                    "Request failed",
                    f"<section class='card'><h2>Request failed</h2><p>{html.escape(detail)}</p>"
                    "<a class='btn secondary' href='/'>Return to dashboard</a></section>",
                    session,
                ),
                400,
            )
        except Exception:
            traceback.print_exc()
            audit(actor, "request.error", parsed.path, source_ip=self.source_ip)
            self.send_html(
                page(
                    "Internal error",
                    "<section class='card'>The operation failed safely. Check container logs.</section>",
                    session,
                ),
                500,
            )


def shutdown(*_: object) -> None:
    STOP.set()
    if SSHD_PROCESS and SSHD_PROCESS.poll() is None:
        SSHD_PROCESS.terminate()


def main() -> None:
    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    initialize_filesystem()
    initialize_database()
    restore_unix_users()
    secret_key()
    migrate_legacy_telegram_usernames()
    start_sshd()
    reconcile_accounts()
    threading.Thread(target=maintenance_loop, daemon=True).start()
    threading.Thread(target=telegram_loop, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 8080), Handler)
    server.daemon_threads = True
    print("panel: listening on 0.0.0.0:8080", flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
