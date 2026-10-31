import os
import re
import hmac
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(APP_DIR, "data", "keys.db"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
KEY_PEPPER = os.environ.get("KEY_PEPPER", "")
ALLOWED_ORIGINS = os.environ.get("ALLOWED_ORIGINS", "*")

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS.split(",") if ALLOWED_ORIGINS != "*" else "*"}})

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            duration_seconds INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            activated_at TEXT,
            device_hash TEXT,
            status TEXT NOT NULL DEFAULT 'unused'
        )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON keys(status)")

def hash_secret(value):
    return hashlib.sha256((KEY_PEPPER + value).encode("utf-8")).hexdigest()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get("X-Admin-Token", "")
        if not ADMIN_TOKEN or not hmac.compare_digest(supplied, ADMIN_TOKEN):
            return jsonify(ok=False, error="UNAUTHORIZED"), 401
        return fn(*args, **kwargs)
    return wrapper

def body_json():
    return request.get_json(silent=True) or {}

def valid_device_id(value):
    return isinstance(value, str) and 4 <= len(value) <= 160 and re.fullmatch(r"[A-Za-z0-9._:-]+", value)

def duration_seconds(data):
    # Accept either duration_seconds, or duration + unit.
    if "duration_seconds" in data:
        n = data.get("duration_seconds")
        if isinstance(n, bool) or not isinstance(n, int) or not 60 <= n <= 315360000:
            raise ValueError("duration_seconds must be an integer from 60 to 315360000")
        return n
    amount = data.get("duration")
    unit = data.get("unit", "days")
    factors = {"minutes": 60, "hours": 3600, "days": 86400}
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 1:
        raise ValueError("duration must be a positive integer")
    if unit not in factors:
        raise ValueError("unit must be minutes, hours, or days")
    seconds = amount * factors[unit]
    if seconds > 315360000:
        raise ValueError("duration is too long")
    return seconds

def new_key():
    # Human-readable, high-entropy key; only its hash is stored.
    raw = secrets.token_urlsafe(24).replace("-", "").replace("_", "").upper()
    return "DV-" + raw[:28]

@app.get("/")
def home():
    return send_from_directory(APP_DIR, "admin.html")

@app.get("/health")
def health():
    return jsonify(ok=True, service="key-manager")

@app.post("/api/add_key")
@admin_required
def add_key():
    data = body_json()
    try:
        seconds = duration_seconds(data)
    except ValueError as exc:
        return jsonify(ok=False, error="INVALID_DURATION", message=str(exc)), 400

    for _ in range(5):
        key = new_key()
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO keys(key_hash,key_prefix,duration_seconds,created_at,status) VALUES(?,?,?,?, 'unused')",
                    (hash_secret(key), key[:7], seconds, iso(now_utc()))
                )
            return jsonify(ok=True, key=key, duration_seconds=seconds, status="unused"), 201
        except sqlite3.IntegrityError:
            continue
    return jsonify(ok=False, error="KEY_GENERATION_FAILED"), 500

@app.get("/api/get_key")
@admin_required
def get_key():
    # Raw keys are intentionally not recoverable: only hashes are stored.
    with db() as conn:
        rows = conn.execute("""
            SELECT id,key_prefix,duration_seconds,created_at,status
            FROM keys WHERE status='unused' ORDER BY id DESC LIMIT 500
        """).fetchall()
    return jsonify(ok=True, keys=[dict(r) for r in rows],
                   note="Only key prefixes are listed. Full keys are shown once when created.")

@app.get("/api/key_status")
@admin_required
def key_status():
    with db() as conn:
        rows = conn.execute("""
            SELECT id,key_prefix,duration_seconds,created_at,activated_at,expires_at,status
            FROM keys ORDER BY id DESC LIMIT 500
        """).fetchall()
    return jsonify(ok=True, keys=[dict(r) for r in rows])

@app.post("/api/verify_key")
def verify_key():
    data = body_json()
    key = data.get("key", "")
    device_id = data.get("device_id", "")
    if not isinstance(key, str) or not re.fullmatch(r"DV-[A-Z0-9]{20,40}", key.upper()):
        return jsonify(ok=False, status="invalid", error="INVALID_KEY"), 400
    if not valid_device_id(device_id):
        return jsonify(ok=False, status="invalid", error="INVALID_DEVICE_ID"), 400

    kh = hash_secret(key.upper())
    dh = hash_secret(device_id)
    conn = db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM keys WHERE key_hash=?", (kh,)).fetchone()
        if row is None:
            conn.execute("ROLLBACK")
            return jsonify(ok=False, status="invalid", error="INVALID_KEY"), 404

        current = now_utc()
        if row["status"] == "unused":
            expires = current + timedelta(seconds=row["duration_seconds"])
            conn.execute("""
                UPDATE keys SET status='used', activated_at=?, expires_at=?, device_hash=?
                WHERE id=? AND status='unused'
            """, (iso(current), iso(expires), dh, row["id"]))
            conn.execute("COMMIT")
            return jsonify(ok=True, status="activated", message="KEY_ACTIVATED",
                           expires_at=iso(expires), duration_seconds=row["duration_seconds"])

        if row["device_hash"] != dh:
            conn.execute("ROLLBACK")
            return jsonify(ok=False, status="used_by_other_device", error="KEY_ALREADY_USED"), 409

        expires_at = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if current >= expires_at:
            conn.execute("COMMIT")
            return jsonify(ok=False, status="expired", error="KEY_EXPIRED",
                           activated_at=row["activated_at"], expires_at=row["expires_at"]), 403

        conn.execute("COMMIT")
        remaining = max(0, int((expires_at - current).total_seconds()))
        return jsonify(ok=True, status="already_activated", message="KEY_VALID_FOR_THIS_DEVICE",
                       activated_at=row["activated_at"], expires_at=row["expires_at"],
                       remaining_seconds=remaining)
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    finally:
        conn.close()

@app.post("/api/delete_key")
@admin_required
def delete_key():
    data = body_json()
    key_id = data.get("id")
    if isinstance(key_id, bool) or not isinstance(key_id, int):
        return jsonify(ok=False, error="INVALID_ID"), 400
    with db() as conn:
        cur = conn.execute("DELETE FROM keys WHERE id=?", (key_id,))
    if cur.rowcount == 0:
        return jsonify(ok=False, error="NOT_FOUND"), 404
    return jsonify(ok=True, deleted=True)

init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
