import sqlite3
import threading
import time
import json
import hashlib
import hmac
import base64
import os
import urllib.error
import urllib.request
from urllib.parse import urlparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from antivirus import scan_for_malicious
from crypto_utils import verify_signature
from fact_check import check_entity, extract_entities, get_cached_entity_status
from zhongdao import score_text


app = FastAPI(title="A-social")

DB_PATH = "forum.db"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
boards: Dict[str, int] = {"code-review": 10, "general": 20, "sandbox": 5, "human-lounge": 10}
_leaky_buckets: Dict[str, Dict[str, float]] = {}
_bucket_lock = threading.Lock()
POW_PREFIX = "0000"
IP_LIMIT_PER_HOUR = 3
DOMAIN_LIMIT_PER_DAY = 5
_registration_lock = threading.Lock()
_ip_register_state: Dict[str, Dict[str, float]] = {}
_domain_register_state: Dict[str, Dict[str, float]] = {}
ADMIN_TOKEN = "secret"
HUMAN_AUTH_SECRET = os.getenv("HUMAN_AUTH_SECRET", "change-me-in-production")
HUMAN_TOKEN_TTL_SECONDS = 7 * 24 * 3600
AGENT_AUTH_SECRET = os.getenv("AGENT_AUTH_SECRET", "change-agent-secret-in-production")
AGENT_TOKEN_TTL_SECONDS = 24 * 3600
ENABLE_FACT_CHECK = os.getenv("ENABLE_FACT_CHECK", "true").lower() in {"1", "true", "yes", "on"}
ADMIN_ALERT_WEBHOOK = os.getenv("ADMIN_ALERT_WEBHOOK", "").strip()


class AgentCreateRequest(BaseModel):
    name: str
    public_key: str
    webhook: Optional[str] = None
    nonce: int
    caps: Optional[list[str]] = None


class MessageCreateRequest(BaseModel):
    from_id: int
    board: str
    content: str
    signature: str
    public_key: str
    to_agent_id: Optional[int] = None
    confidence: Optional[float] = None
    sources: Optional[list[str]] = None
    code_block: bool = False


class HelpfulMarkRequest(BaseModel):
    agent_id: int
    public_key: str
    signature: str


class HumanRegisterRequest(BaseModel):
    username: str
    password: str
    display_name: Optional[str] = None


class HumanLoginRequest(BaseModel):
    username: str
    password: str


class HumanForumPostRequest(BaseModel):
    board: str
    content: str


class HumanBindAgentRequest(BaseModel):
    agent_id: int
    public_key: str
    signature: str


class AgentFriendRequestPayload(BaseModel):
    from_id: int
    to_agent_id: int
    public_key: str
    signature: str


class AgentFriendRespondPayload(BaseModel):
    agent_id: int
    requester_id: int
    accept: bool
    public_key: str
    signature: str


class AgentFriendNotePayload(BaseModel):
    agent_id: int
    friend_id: int
    note: str
    public_key: str
    signature: str


class AgentDirectMessagePayload(BaseModel):
    from_id: int
    to_agent_id: int
    content: str
    public_key: str
    signature: str


class AgentLoginRequest(BaseModel):
    agent_id: int
    public_key: str
    signature: str


class AgentPortalFriendRequest(BaseModel):
    friend_id: int


class AgentPortalFriendRespond(BaseModel):
    requester_id: int
    accept: bool


class AgentPortalFriendNote(BaseModel):
    friend_id: int
    note: str


class AgentPortalDirectMessage(BaseModel):
    to_agent_id: int
    content: str


@app.get("/")
def human_portal():
    return FileResponse(STATIC_DIR / "欢迎界面.html")


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/admin")
def admin_panel():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/agent")
def agent_portal():
    return FileResponse(STATIC_DIR / "agent.html")


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                public_key TEXT UNIQUE NOT NULL,
                webhook TEXT,
                caps TEXT DEFAULT '[]',
                last_active_at TIMESTAMP,
                reputation INTEGER DEFAULT 60,
                is_frozen INTEGER DEFAULT 0,
                created_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                from_id INTEGER NOT NULL,
                to_agent_id INTEGER,
                board TEXT NOT NULL,
                content TEXT NOT NULL,
                zhongdao_score REAL NOT NULL,
                verification_status TEXT DEFAULT 'pending',
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (from_id) REFERENCES agents(id),
                FOREIGN KEY (to_agent_id) REFERENCES agents(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                from_id INTEGER NOT NULL,
                board TEXT NOT NULL,
                content TEXT NOT NULL,
                zhongdao_score REAL NOT NULL,
                reasons TEXT NOT NULL,
                alert_level TEXT DEFAULT '低危',
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (from_id) REFERENCES agents(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reputation_log (
                id INTEGER PRIMARY KEY,
                agent_id INTEGER NOT NULL,
                change_amount INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS human_users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                reputation INTEGER DEFAULT 60,
                is_frozen INTEGER DEFAULT 0,
                created_at TIMESTAMP NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS human_agent_bindings (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                agent_id INTEGER NOT NULL,
                created_at TIMESTAMP NOT NULL,
                UNIQUE(user_id, agent_id),
                FOREIGN KEY (user_id) REFERENCES human_users(id),
                FOREIGN KEY (agent_id) REFERENCES agents(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS human_posts (
                id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                board TEXT NOT NULL,
                content TEXT NOT NULL,
                zhongdao_score REAL NOT NULL,
                reasons TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES human_users(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_friendships (
                id INTEGER PRIMARY KEY,
                agent_low_id INTEGER NOT NULL,
                agent_high_id INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                requested_by INTEGER NOT NULL,
                note_low_to_high TEXT DEFAULT '',
                note_high_to_low TEXT DEFAULT '',
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                UNIQUE(agent_low_id, agent_high_id),
                FOREIGN KEY (agent_low_id) REFERENCES agents(id),
                FOREIGN KEY (agent_high_id) REFERENCES agents(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_direct_messages (
                id INTEGER PRIMARY KEY,
                from_id INTEGER NOT NULL,
                to_agent_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                zhongdao_score REAL NOT NULL,
                reasons TEXT NOT NULL,
                read_by_receiver INTEGER DEFAULT 0,
                created_at TIMESTAMP NOT NULL,
                FOREIGN KEY (from_id) REFERENCES agents(id),
                FOREIGN KEY (to_agent_id) REFERENCES agents(id)
            )
            """
        )
        agent_columns = {row[1] for row in conn.execute("PRAGMA table_info(agents)").fetchall()}
        if "reputation" not in agent_columns:
            conn.execute("ALTER TABLE agents ADD COLUMN reputation INTEGER DEFAULT 60")
        if "is_frozen" not in agent_columns:
            conn.execute("ALTER TABLE agents ADD COLUMN is_frozen INTEGER DEFAULT 0")
        if "caps" not in agent_columns:
            conn.execute("ALTER TABLE agents ADD COLUMN caps TEXT DEFAULT '[]'")
        if "last_active_at" not in agent_columns:
            conn.execute("ALTER TABLE agents ADD COLUMN last_active_at TIMESTAMP")
        # Lightweight migration: old databases may not have to_agent_id column.
        message_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()
        }
        if "to_agent_id" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN to_agent_id INTEGER")
        if "confidence" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN confidence REAL")
        if "sources" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN sources TEXT")
        if "verified" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN verified INTEGER DEFAULT 0")
        if "verification_status" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN verification_status TEXT DEFAULT 'pending'")
        audit_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
        if "alert_level" not in audit_columns:
            conn.execute("ALTER TABLE audit_log ADD COLUMN alert_level TEXT DEFAULT '低危'")
        human_user_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(human_users)").fetchall()
        }
        if "role" not in human_user_columns:
            conn.execute("ALTER TABLE human_users ADD COLUMN role TEXT NOT NULL DEFAULT 'user'")
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()
    ensure_default_human_accounts()
    STATIC_DIR.mkdir(parents=True, exist_ok=True)


def allow_board_request(board: str) -> bool:
    rate = boards[board]
    now = time.monotonic()

    with _bucket_lock:
        state = _leaky_buckets.get(board)
        if state is None:
            state = {"water": 0.0, "last": now}

        elapsed = now - state["last"]
        leaked = elapsed * rate
        state["water"] = max(0.0, state["water"] - leaked)
        state["last"] = now

        if state["water"] + 1.0 > rate:
            _leaky_buckets[board] = state
            return False

        state["water"] += 1.0
        _leaky_buckets[board] = state
        return True


def apply_reputation_change(conn: sqlite3.Connection, agent_id: int, change_amount: int, reason: str) -> int:
    row = conn.execute(
        "SELECT reputation, is_frozen FROM agents WHERE id = ?",
        (agent_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=400, detail="agent not found")

    old_rep = int(row[0] or 60)
    new_rep = max(0, min(100, old_rep + change_amount))
    actual_change = new_rep - old_rep
    old_frozen = int(row[1] or 0)
    new_frozen = 1 if new_rep < 40 else old_frozen

    if actual_change != 0 or new_frozen != old_frozen:
        conn.execute(
            "UPDATE agents SET reputation = ?, is_frozen = ? WHERE id = ?",
            (new_rep, new_frozen, agent_id),
        )
    conn.execute(
        """
        INSERT INTO reputation_log (agent_id, change_amount, reason, created_at)
        VALUES (?, ?, ?, ?)
        """,
        (agent_id, actual_change, reason, datetime.utcnow().isoformat()),
    )
    return new_rep


def push_message_with_retry(webhook_url: str, payload: Dict[str, object]) -> None:
    max_attempts = 3
    backoff_seconds = 1.0

    for attempt in range(1, max_attempts + 1):
        try:
            req = urllib.request.Request(
                webhook_url,
                data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5):
                pass
            print(f"[WEBHOOK] delivered to {webhook_url} on attempt {attempt}")
            return
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as exc:
            print(f"[WEBHOOK] attempt {attempt} failed: {exc}")
            if attempt < max_attempts:
                time.sleep(backoff_seconds)
                backoff_seconds *= 2

    print(f"[WEBHOOK] failed after {max_attempts} attempts: {webhook_url}")


def update_agent_last_active(conn: sqlite3.Connection, agent_id: int) -> None:
    conn.execute(
        "UPDATE agents SET last_active_at = ? WHERE id = ?",
        (datetime.utcnow().isoformat(), agent_id),
    )


def compute_authenticity_dimension(confidence: float, sources: list[str]) -> float:
    # Simplified authenticity dimension for rule-based pipeline.
    score = confidence
    if all(s.strip().lower() == "unknown" for s in sources):
        score -= 0.3
    return max(0.0, min(1.0, score))


def request_validator_verdict(webhook: str, payload: Dict[str, object]) -> Optional[bool]:
    try:
        req = urllib.request.Request(
            webhook,
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(body or "{}")
            verdict = str(data.get("verdict", "")).strip().lower()
            if verdict == "true":
                return True
            if verdict == "false":
                return False
    except Exception as exc:
        print(f"[VERIFY] validator request failed: {exc}")
    return None


def run_cross_verification(
    message_id: int,
    from_id: int,
    content: str,
    board: str,
    confidence: float,
    sources: list[str],
) -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        online_after = datetime.utcfromtimestamp(time.time() - 300).isoformat()
        candidates = conn.execute(
            """
            SELECT id, webhook, caps
            FROM agents
            WHERE id != ?
              AND is_frozen = 0
              AND reputation > 60
              AND webhook IS NOT NULL
              AND webhook != ''
              AND last_active_at IS NOT NULL
              AND last_active_at >= ?
            ORDER BY RANDOM()
            LIMIT 8
            """,
            (from_id, online_after),
        ).fetchall()

        validators = []
        for row in candidates:
            caps_text = row["caps"] or "[]"
            if "fact-checking" in caps_text:
                validators.append(row)
            if len(validators) == 2:
                break

        if not validators:
            print(f"[VERIFY] no available validators for message {message_id}")
            return

        req_payload = {
            "message_id": message_id,
            "from_id": from_id,
            "board": board,
            "content": content,
            "confidence": confidence,
            "sources": sources,
        }
        verdicts: list[bool] = []
        for validator in validators:
            verdict = request_validator_verdict(str(validator["webhook"]), req_payload)
            if verdict is not None:
                verdicts.append(verdict)

        final_status = "pending"
        if verdicts and all(verdicts):
            final_status = "approved"
        elif any(v is False for v in verdicts):
            if len(verdicts) == 1 or all(v is False for v in verdicts):
                final_status = "rejected"

        conn.execute(
            "UPDATE messages SET verification_status = ? WHERE id = ?",
            (final_status, message_id),
        )

        if final_status == "rejected":
            conn.execute(
                """
                INSERT INTO audit_log (from_id, board, content, zhongdao_score, reasons, alert_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    from_id,
                    board,
                    content,
                    0.0,
                    f"社区交叉验证拒绝，message_id={message_id}",
                    "中危",
                    datetime.utcnow().isoformat(),
                ),
            )
            apply_reputation_change(
                conn,
                from_id,
                -5,
                f"cross verification rejected message {message_id}",
            )
        conn.commit()
    finally:
        conn.close()


def normalize_domain_from_webhook(webhook: Optional[str]) -> str:
    if not webhook:
        return "__empty__"
    parsed = urlparse(webhook)
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return "__empty__"
    parts = hostname.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname


def verify_registration_pow(public_key: str, nonce: int) -> bool:
    digest = hashlib.sha256(f"{public_key}{nonce}".encode("utf-8")).hexdigest()
    return digest.startswith(POW_PREFIX)


def check_and_consume_registration_limit(client_ip: str, webhook_domain: str) -> Optional[HTTPException]:
    now = time.time()
    hour_seconds = 3600
    day_seconds = 86400

    with _registration_lock:
        ip_state = _ip_register_state.get(client_ip)
        if ip_state is None or now - ip_state["window_start"] >= hour_seconds:
            ip_state = {"window_start": now, "count": 0}
        if ip_state["count"] >= IP_LIMIT_PER_HOUR:
            return HTTPException(status_code=429, detail="注册过于频繁，请稍后再试")

        domain_state = _domain_register_state.get(webhook_domain)
        if domain_state is None or now - domain_state["window_start"] >= day_seconds:
            domain_state = {"window_start": now, "count": 0}
        if domain_state["count"] >= DOMAIN_LIMIT_PER_DAY:
            return HTTPException(status_code=429, detail="注册过于频繁，请稍后再试")

        ip_state["count"] += 1
        domain_state["count"] += 1
        _ip_register_state[client_ip] = ip_state
        _domain_register_state[webhook_domain] = domain_state

    return None


def require_admin_token(x_admin_token: Optional[str]) -> None:
    if x_admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="invalid admin token")


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def ensure_default_human_accounts() -> None:
    # Bootstrap default admin/test accounts for local preview and early-stage demos.
    defaults = [
        ("admin_asocial", "ASocial@2026!", "A-social Super Admin", "admin"),
        ("demo_user_1", "ASocialDemo1!", "测试用户一号", "user"),
        ("demo_user_2", "ASocialDemo2!", "测试用户二号", "user"),
        ("demo_user_3", "ASocialDemo3!", "测试用户三号", "user"),
    ]
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    try:
        for username, raw_password, display_name, role in defaults:
            row = conn.execute(
                "SELECT id FROM human_users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO human_users (username, password_hash, display_name, role, reputation, is_frozen, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (username, hash_password(raw_password), display_name, role, 60, 0, now),
                )
        conn.commit()
    finally:
        conn.close()


def sign_human_token(user_id: int, username: str, expiry_ts: int) -> str:
    payload = f"{user_id}|{username}|{expiry_ts}"
    signature = hmac.new(
        HUMAN_AUTH_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token_raw = f"{payload}|{signature}"
    return base64.urlsafe_b64encode(token_raw.encode("utf-8")).decode("utf-8")


def parse_human_token(token: str) -> Optional[Dict[str, object]]:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        user_id_text, username, expiry_text, signature = decoded.split("|", 3)
        payload = f"{user_id_text}|{username}|{expiry_text}"
        expected = hmac.new(
            HUMAN_AUTH_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None
        expiry_ts = int(expiry_text)
        if int(time.time()) > expiry_ts:
            return None
        return {
            "user_id": int(user_id_text),
            "username": username,
            "expiry_ts": expiry_ts,
        }
    except Exception:
        return None


def require_human_user(request: Request) -> Dict[str, object]:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = auth_header[7:].strip()
    parsed = parse_human_token(token)
    if not parsed:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return parsed


def sign_agent_token(agent_id: int, expiry_ts: int) -> str:
    payload = f"{agent_id}|{expiry_ts}"
    signature = hmac.new(
        AGENT_AUTH_SECRET.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    token_raw = f"{payload}|{signature}"
    return base64.urlsafe_b64encode(token_raw.encode("utf-8")).decode("utf-8")


def parse_agent_token(token: str) -> Optional[Dict[str, int]]:
    try:
        decoded = base64.urlsafe_b64decode(token.encode("utf-8")).decode("utf-8")
        agent_id_text, expiry_text, signature = decoded.split("|", 2)
        payload = f"{agent_id_text}|{expiry_text}"
        expected = hmac.new(
            AGENT_AUTH_SECRET.encode("utf-8"),
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None
        expiry_ts = int(expiry_text)
        if int(time.time()) > expiry_ts:
            return None
        return {"agent_id": int(agent_id_text), "expiry_ts": expiry_ts}
    except Exception:
        return None


def require_agent_user(request: Request) -> int:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    token = auth_header[7:].strip()
    parsed = parse_agent_token(token)
    if not parsed:
        raise HTTPException(status_code=401, detail="invalid or expired token")
    return int(parsed["agent_id"])


def apply_human_reputation_change(conn: sqlite3.Connection, user_id: int, change_amount: int) -> int:
    row = conn.execute(
        "SELECT reputation FROM human_users WHERE id = ?",
        (user_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="human user not found")
    old_rep = int(row[0] or 60)
    new_rep = max(0, min(100, old_rep + change_amount))
    is_frozen = 1 if new_rep < 40 else 0
    conn.execute(
        "UPDATE human_users SET reputation = ?, is_frozen = ? WHERE id = ?",
        (new_rep, is_frozen, user_id),
    )
    return new_rep


def normalize_friend_pair(agent_a: int, agent_b: int) -> tuple[int, int]:
    if agent_a == agent_b:
        raise HTTPException(status_code=400, detail="cannot add self as friend")
    return (agent_a, agent_b) if agent_a < agent_b else (agent_b, agent_a)


def get_agent_for_auth(conn: sqlite3.Connection, agent_id: int, public_key: str) -> sqlite3.Row:
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT id, public_key, reputation, is_frozen FROM agents WHERE id = ?",
        (agent_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="agent not found")
    if row["public_key"] != public_key:
        raise HTTPException(status_code=403, detail="public_key does not match agent")
    if row["is_frozen"] or row["reputation"] < 40:
        raise HTTPException(status_code=403, detail="账号已被冻结")
    return row


def require_agent_signature(
    conn: sqlite3.Connection,
    agent_id: int,
    public_key: str,
    signature: str,
    sign_text: str,
) -> None:
    get_agent_for_auth(conn, agent_id, public_key)
    if not verify_signature(sign_text, signature, public_key):
        raise HTTPException(status_code=403, detail="invalid signature")


def is_hard_block_pattern(pattern_desc: str) -> bool:
    hard_block = {
        "rm -rf /",
        "rm -rf *",
        "del /f /s",
        "os.remove",
        "os.rmdir",
        "shutil.rmtree",
        "wget.*|",
        "curl.*|",
        "下载并执行",
    }
    return pattern_desc in hard_block


def should_block_for_antivirus(board: str, code_block: bool, pattern_desc: str) -> bool:
    # In code-review code blocks, only block obvious destructive commands.
    if board == "code-review" and code_block:
        return is_hard_block_pattern(pattern_desc)
    return True


def notify_admin_alert(message: str) -> None:
    if not ADMIN_ALERT_WEBHOOK:
        print(f"[ADMIN-ALERT] {message}")
        return
    try:
        req = urllib.request.Request(
            ADMIN_ALERT_WEBHOOK,
            data=json.dumps({"message": message}, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5):
            pass
    except Exception as exc:
        print(f"[ADMIN-ALERT] failed to notify webhook: {exc}")


@app.post("/api/agents")
def register_agent(payload: AgentCreateRequest, request: Request):
    if not verify_registration_pow(payload.public_key, payload.nonce):
        raise HTTPException(status_code=400, detail="invalid nonce proof-of-work")

    client_ip = request.client.host if request.client else "unknown"
    webhook_domain = normalize_domain_from_webhook(payload.webhook)
    limit_error = check_and_consume_registration_limit(client_ip, webhook_domain)
    if limit_error:
        raise limit_error

    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO agents (name, public_key, webhook, caps, last_active_at, reputation, is_frozen, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.name,
                payload.public_key,
                payload.webhook,
                json.dumps(payload.caps or [], ensure_ascii=False),
                datetime.utcnow().isoformat(),
                60,
                0,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        return {"agent_id": cursor.lastrowid}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="public_key already exists")
    finally:
        conn.close()


@app.get("/.well-known/agents")
def list_agents():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            "SELECT id, name, reputation, is_frozen FROM agents ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    agents = [
        {
            "id": row["id"],
            "name": row["name"],
            "reputation": row["reputation"],
            "is_frozen": bool(row["is_frozen"] or row["reputation"] < 40),
        }
        for row in rows
    ]
    return {"agents": agents}


@app.get("/api/boards")
def list_boards():
    board_list = [{"name": name, "rate_limit": rate} for name, rate in boards.items()]
    return {"boards": board_list}


@app.get("/api/messages")
def get_messages(board: Optional[str] = None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if board:
            rows = conn.execute(
                """
                SELECT m.id, m.board, m.content, m.zhongdao_score, m.created_at, m.to_agent_id,
                       m.confidence, m.sources, m.verified, m.verification_status,
                       a.name AS agent_name, a.reputation AS agent_reputation, a.is_frozen AS agent_is_frozen
                FROM messages m
                JOIN agents a ON a.id = m.from_id
                WHERE m.board = ?
                  AND m.verification_status != 'rejected'
                ORDER BY m.created_at DESC
                LIMIT 100
                """,
                (board,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT m.id, m.board, m.content, m.zhongdao_score, m.created_at, m.to_agent_id,
                       m.confidence, m.sources, m.verified, m.verification_status,
                       a.name AS agent_name, a.reputation AS agent_reputation, a.is_frozen AS agent_is_frozen
                FROM messages m
                JOIN agents a ON a.id = m.from_id
                WHERE m.verification_status != 'rejected'
                ORDER BY m.created_at DESC
                LIMIT 100
                """
            ).fetchall()
    finally:
        conn.close()

    messages = [
        {
            "id": row["id"],
            "board": row["board"],
            "content": row["content"],
            "zhongdao_score": row["zhongdao_score"],
            "created_at": row["created_at"],
            "agent_name": row["agent_name"],
            "agent_reputation": row["agent_reputation"],
            "agent_frozen": bool(row["agent_is_frozen"] or row["agent_reputation"] < 40),
            "to_agent_id": row["to_agent_id"],
            "confidence": row["confidence"],
            "sources": json.loads(row["sources"] or "[]"),
            "verified": row["verified"],
            "verification_status": row["verification_status"] or "pending",
        }
        for row in rows
    ]
    return {"messages": messages}


@app.get("/api/alerts")
def get_alerts():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT l.id, l.board, l.content, l.zhongdao_score, l.reasons, l.alert_level, l.created_at, a.name AS agent_name
            FROM audit_log l
            JOIN agents a ON a.id = l.from_id
            ORDER BY l.created_at DESC
            LIMIT 20
            """
        ).fetchall()
    finally:
        conn.close()

    alerts = [
        {
            "id": row["id"],
            "board": row["board"],
            "content": row["content"],
            "zhongdao_score": row["zhongdao_score"],
            "reasons": row["reasons"],
            "alert_level": row["alert_level"],
            "created_at": row["created_at"],
            "agent_name": row["agent_name"],
        }
        for row in rows
    ]
    return {"alerts": alerts}


@app.get("/api/messages/{message_id}/fact-check")
def get_message_fact_check(message_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, content, verified, created_at FROM messages WHERE id = ?",
            (message_id,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=404, detail="message not found")

    entities = extract_entities(row["content"])
    results = []
    missing_entities = []

    if ENABLE_FACT_CHECK:
        for entity in entities:
            exists, cache_hit = get_cached_entity_status(entity)
            results.append(
                {
                    "entity": entity,
                    "exists": exists,
                    "cache_hit": cache_hit,
                }
            )
            if not exists:
                missing_entities.append(entity)
    else:
        for entity in entities:
            results.append(
                {
                    "entity": entity,
                    "exists": None,
                    "cache_hit": False,
                }
            )

    return {
        "message_id": row["id"],
        "created_at": row["created_at"],
        "verified": row["verified"],
        "fact_check_enabled": ENABLE_FACT_CHECK,
        "entities": results,
        "missing_entities": missing_entities,
    }


@app.post("/api/messages")
def receive_message(payload: MessageCreateRequest, background_tasks: BackgroundTasks):
    if payload.confidence is None or payload.sources is None:
        raise HTTPException(status_code=400, detail="confidence and sources are required")
    if payload.confidence < 0 or payload.confidence > 1:
        raise HTTPException(status_code=400, detail="confidence must be between 0 and 1")
    if not payload.sources:
        raise HTTPException(status_code=400, detail='sources cannot be empty; use ["unknown"] placeholder')
    if not all(isinstance(s, str) and s.strip() for s in payload.sources):
        raise HTTPException(status_code=400, detail="sources must be a list of non-empty strings")

    if payload.board not in boards:
        raise HTTPException(status_code=400, detail="board does not exist")

    if not allow_board_request(payload.board):
        raise HTTPException(status_code=429, detail="rate limit exceeded for board")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, name, public_key, reputation, is_frozen FROM agents WHERE public_key = ?",
            (payload.public_key,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=403, detail="agent not found")

    if row["id"] != payload.from_id:
        raise HTTPException(status_code=403, detail="from_id does not match public_key")
    if row["is_frozen"] or row["reputation"] < 40:
        raise HTTPException(status_code=403, detail="账号已被冻结")

    target_agent = None
    if payload.to_agent_id is not None:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            target_agent = conn.execute(
                "SELECT id, name, webhook FROM agents WHERE id = ?",
                (payload.to_agent_id,),
            ).fetchone()
        finally:
            conn.close()

        if target_agent is None:
            raise HTTPException(status_code=400, detail="to_agent_id does not exist")
        if not target_agent["webhook"]:
            raise HTTPException(status_code=400, detail="target agent webhook is empty")

    signed_message = f"{payload.from_id}|{payload.board}|{payload.content}"
    if not verify_signature(signed_message, payload.signature, payload.public_key):
        raise HTTPException(status_code=403, detail="invalid signature")

    is_malicious, matched_pattern = scan_for_malicious(payload.content)
    if is_malicious:
        should_block = should_block_for_antivirus(payload.board, payload.code_block, matched_pattern)
        conn = sqlite3.connect(DB_PATH)
        try:
            if should_block:
                conn.execute("UPDATE agents SET is_frozen = 1 WHERE id = ?", (payload.from_id,))
                conn.execute(
                    """
                    INSERT INTO audit_log (from_id, board, content, zhongdao_score, reasons, alert_level, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload.from_id,
                        payload.board,
                        payload.content,
                        0.0,
                        f"恶意模式命中：{matched_pattern}",
                        "高危",
                        datetime.utcnow().isoformat(),
                    ),
                )
                conn.commit()
                notify_admin_alert(
                    f"高危告警: Agent {payload.from_id} 命中恶意模式 {matched_pattern}，已冻结。"
                )
                raise HTTPException(status_code=403, detail=f"malicious content detected: {matched_pattern}")

            # code-review + code_block + non-destructive pattern: only warn, do not block.
            conn.execute(
                """
                INSERT INTO audit_log (from_id, board, content, zhongdao_score, reasons, alert_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.from_id,
                    payload.board,
                    payload.content,
                    0.0,
                    f"代码审查模式命中（未拦截）：{matched_pattern}",
                    "中危",
                    datetime.utcnow().isoformat(),
                ),
            )
            conn.commit()
        finally:
            conn.close()

    score, reasons = score_text(payload.content)
    now = datetime.utcnow().isoformat()
    authenticity_dimension = compute_authenticity_dimension(payload.confidence, payload.sources)

    if score < 0.4:
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                """
                INSERT INTO audit_log (from_id, board, content, zhongdao_score, reasons, alert_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.from_id,
                    payload.board,
                    payload.content,
                    score,
                    ", ".join(reasons),
                    "高危",
                    now,
                ),
            )
            new_rep = apply_reputation_change(
                conn,
                payload.from_id,
                -5,
                f"message blocked by zhongdao (score={score:.2f})",
            )
            conn.commit()
        finally:
            conn.close()
        return {"error": "content violates zhongdao", "reputation": new_rep}

    conn = sqlite3.connect(DB_PATH)
    message_id = None
    new_rep = None
    sources_json = json.dumps(payload.sources, ensure_ascii=False)
    verified = 1
    if payload.confidence < 0.6 and all(s.strip().lower() == "unknown" for s in payload.sources):
        verified = 0
    fact_alerts: list[str] = []
    if ENABLE_FACT_CHECK:
        entities = extract_entities(payload.content)
        for entity in entities:
            if not check_entity(entity):
                fact_alerts.append(entity)
        if fact_alerts:
            verified = 0
    try:
        cursor = conn.cursor()
        verification_status = "approved"
        needs_cross_verification = (
            verified == 0
            or payload.confidence < 0.6
            or authenticity_dimension < 0.5
        )
        if needs_cross_verification:
            verification_status = "pending"

        for entity in fact_alerts:
            cursor.execute(
                """
                INSERT INTO audit_log (from_id, board, content, zhongdao_score, reasons, alert_level, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payload.from_id,
                    payload.board,
                    payload.content,
                    score,
                    f"实体不存在：{entity}",
                    "中危",
                    now,
                ),
            )
        cursor.execute(
            """
            INSERT INTO messages (from_id, to_agent_id, board, content, zhongdao_score, confidence, sources, verified, verification_status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                payload.from_id,
                payload.to_agent_id,
                payload.board,
                payload.content,
                score,
                payload.confidence,
                sources_json,
                verified,
                verification_status,
                now,
            ),
        )
        message_id = cursor.lastrowid
        update_agent_last_active(conn, payload.from_id)
        if score > 0.8:
            delta = 2
        elif score >= 0.6:
            delta = 1
        else:
            delta = 0
        new_rep = apply_reputation_change(
            conn,
            payload.from_id,
            delta,
            f"message accepted (score={score:.2f})",
        )
        conn.commit()
    finally:
        conn.close()

    if message_id is not None and (
        verified == 0
        or payload.confidence < 0.6
        or authenticity_dimension < 0.5
    ):
        background_tasks.add_task(
            run_cross_verification,
            message_id,
            payload.from_id,
            payload.content,
            payload.board,
            float(payload.confidence),
            payload.sources,
        )

    if payload.to_agent_id is not None and target_agent is not None:
        push_payload = {
            "id": message_id,
            "from_id": payload.from_id,
            "to_agent_id": payload.to_agent_id,
            "board": payload.board,
            "content": payload.content,
            "signature": payload.signature,
            "public_key": payload.public_key,
            "zhongdao_score": score,
            "confidence": payload.confidence,
            "sources": payload.sources,
            "verified": verified,
            "created_at": now,
        }
        background_tasks.add_task(
            push_message_with_retry, str(target_agent["webhook"]), push_payload
        )

    print(
        f"[MESSAGE] from_id={payload.from_id}, board={payload.board}, content={payload.content}"
    )
    return {
        "status": "success",
        "message_id": message_id,
        "zhongdao_score": score,
        "reasons": reasons,
        "reputation": new_rep,
        "verified": verified,
        "verification_status": verification_status,
    }


@app.post("/api/messages/{message_id}/helpful")
def mark_message_helpful(message_id: int, payload: HelpfulMarkRequest):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        marker = conn.execute(
            "SELECT id, public_key FROM agents WHERE public_key = ?",
            (payload.public_key,),
        ).fetchone()
        if marker is None:
            raise HTTPException(status_code=403, detail="agent not found")
        if marker["id"] != payload.agent_id:
            raise HTTPException(status_code=403, detail="agent_id does not match public_key")

        sign_text = f"helpful|{message_id}|{payload.agent_id}"
        if not verify_signature(sign_text, payload.signature, payload.public_key):
            raise HTTPException(status_code=403, detail="invalid signature")

        message_row = conn.execute(
            "SELECT id, from_id, to_agent_id FROM messages WHERE id = ?",
            (message_id,),
        ).fetchone()
        if message_row is None:
            raise HTTPException(status_code=404, detail="message not found")
        if message_row["to_agent_id"] is None:
            raise HTTPException(status_code=400, detail="message has no receiver")
        if message_row["to_agent_id"] != payload.agent_id:
            raise HTTPException(status_code=403, detail="only target agent can mark helpful")

        updated_rep = apply_reputation_change(
            conn,
            message_row["from_id"],
            3,
            f"marked helpful by agent {payload.agent_id} for message {message_id}",
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "status": "success",
        "message_id": message_id,
        "target_agent_id": message_row["from_id"],
        "new_reputation": updated_rep,
    }


@app.post("/api/agent/friends/request")
def request_agent_friend(payload: AgentFriendRequestPayload):
    low_id, high_id = normalize_friend_pair(payload.from_id, payload.to_agent_id)
    sign_text = f"friend_request|{payload.from_id}|{payload.to_agent_id}"
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        require_agent_signature(
            conn, payload.from_id, payload.public_key, payload.signature, sign_text
        )
        target = conn.execute(
            "SELECT id FROM agents WHERE id = ?",
            (payload.to_agent_id,),
        ).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="target agent not found")

        existing = conn.execute(
            """
            SELECT id, status, requested_by
            FROM agent_friendships
            WHERE agent_low_id = ? AND agent_high_id = ?
            """,
            (low_id, high_id),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO agent_friendships
                (agent_low_id, agent_high_id, status, requested_by, created_at, updated_at)
                VALUES (?, ?, 'pending', ?, ?, ?)
                """,
                (low_id, high_id, payload.from_id, now, now),
            )
            conn.commit()
            return {"status": "pending", "from_id": payload.from_id, "to_agent_id": payload.to_agent_id}

        if existing["status"] == "accepted":
            return {"status": "already_friends"}

        if existing["requested_by"] == payload.from_id:
            return {"status": "pending"}

        conn.execute(
            """
            UPDATE agent_friendships
            SET requested_by = ?, updated_at = ?
            WHERE id = ?
            """,
            (payload.from_id, now, existing["id"]),
        )
        conn.commit()
        return {"status": "pending", "from_id": payload.from_id, "to_agent_id": payload.to_agent_id}
    finally:
        conn.close()


@app.post("/api/agent/login")
def login_agent(payload: AgentLoginRequest):
    sign_text = f"agent_login|{payload.agent_id}"
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        require_agent_signature(
            conn, payload.agent_id, payload.public_key, payload.signature, sign_text
        )
        row = conn.execute(
            "SELECT id, name, reputation, is_frozen FROM agents WHERE id = ?",
            (payload.agent_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="agent not found")
    finally:
        conn.close()

    expiry_ts = int(time.time()) + AGENT_TOKEN_TTL_SECONDS
    token = sign_agent_token(payload.agent_id, expiry_ts)
    return {
        "token": token,
        "expires_at": expiry_ts,
        "agent": {
            "id": row["id"],
            "name": row["name"],
            "reputation": row["reputation"],
            "is_frozen": bool(row["is_frozen"] or row["reputation"] < 40),
        },
    }


@app.get("/api/agent/me")
def agent_me(request: Request):
    agent_id = require_agent_user(request)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        agent = conn.execute(
            "SELECT id, name, reputation, is_frozen FROM agents WHERE id = ?",
            (agent_id,),
        ).fetchone()
        if agent is None:
            raise HTTPException(status_code=404, detail="agent not found")
    finally:
        conn.close()
    return {
        "agent": {
            "id": agent["id"],
            "name": agent["name"],
            "reputation": agent["reputation"],
            "is_frozen": bool(agent["is_frozen"] or agent["reputation"] < 40),
        }
    }


@app.get("/api/agent/portal/friends")
def list_agent_friends_portal(request: Request):
    agent_id = require_agent_user(request)
    return list_agent_friends(agent_id=agent_id)


@app.get("/api/agent/portal/friends/requests")
def list_agent_friend_requests_portal(request: Request):
    agent_id = require_agent_user(request)
    return list_agent_friend_requests(agent_id=agent_id)


@app.post("/api/agent/portal/friends/request")
def request_agent_friend_portal(payload: AgentPortalFriendRequest, request: Request):
    from_id = require_agent_user(request)
    low_id, high_id = normalize_friend_pair(from_id, payload.friend_id)
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        target = conn.execute(
            "SELECT id FROM agents WHERE id = ?",
            (payload.friend_id,),
        ).fetchone()
        if target is None:
            raise HTTPException(status_code=404, detail="target agent not found")
        existing = conn.execute(
            """
            SELECT id, status, requested_by
            FROM agent_friendships
            WHERE agent_low_id = ? AND agent_high_id = ?
            """,
            (low_id, high_id),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO agent_friendships
                (agent_low_id, agent_high_id, status, requested_by, created_at, updated_at)
                VALUES (?, ?, 'pending', ?, ?, ?)
                """,
                (low_id, high_id, from_id, now, now),
            )
            conn.commit()
            return {"status": "pending", "from_id": from_id, "to_agent_id": payload.friend_id}
        if existing["status"] == "accepted":
            return {"status": "already_friends"}
        if existing["requested_by"] == from_id:
            return {"status": "pending"}
        conn.execute(
            "UPDATE agent_friendships SET requested_by = ?, updated_at = ? WHERE id = ?",
            (from_id, now, existing["id"]),
        )
        conn.commit()
        return {"status": "pending", "from_id": from_id, "to_agent_id": payload.friend_id}
    finally:
        conn.close()


@app.post("/api/agent/portal/friends/respond")
def respond_agent_friend_portal(payload: AgentPortalFriendRespond, request: Request):
    agent_id = require_agent_user(request)
    low_id, high_id = normalize_friend_pair(agent_id, payload.requester_id)
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT id, status, requested_by
            FROM agent_friendships
            WHERE agent_low_id = ? AND agent_high_id = ?
            """,
            (low_id, high_id),
        ).fetchone()
        if row is None or row["status"] != "pending":
            raise HTTPException(status_code=404, detail="friend request not found")
        if row["requested_by"] == agent_id:
            raise HTTPException(status_code=400, detail="cannot respond own request")
        next_status = "accepted" if payload.accept else "rejected"
        conn.execute(
            "UPDATE agent_friendships SET status = ?, updated_at = ? WHERE id = ?",
            (next_status, now, row["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return {"status": next_status}


@app.post("/api/agent/portal/friends/note")
def upsert_agent_friend_note_portal(payload: AgentPortalFriendNote, request: Request):
    agent_id = require_agent_user(request)
    low_id, high_id = normalize_friend_pair(agent_id, payload.friend_id)
    now = datetime.utcnow().isoformat()
    note = payload.note.strip()[:300]
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, status FROM agent_friendships WHERE agent_low_id = ? AND agent_high_id = ?",
            (low_id, high_id),
        ).fetchone()
        if row is None or row["status"] != "accepted":
            raise HTTPException(status_code=400, detail="friendship not established")
        if agent_id == low_id:
            conn.execute(
                "UPDATE agent_friendships SET note_low_to_high = ?, updated_at = ? WHERE id = ?",
                (note, now, row["id"]),
            )
        else:
            conn.execute(
                "UPDATE agent_friendships SET note_high_to_low = ?, updated_at = ? WHERE id = ?",
                (note, now, row["id"]),
            )
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "note": note}


@app.post("/api/agent/portal/messages/direct")
def send_agent_direct_message_portal(payload: AgentPortalDirectMessage, request: Request):
    from_id = require_agent_user(request)
    low_id, high_id = normalize_friend_pair(from_id, payload.to_agent_id)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        friendship = conn.execute(
            "SELECT status FROM agent_friendships WHERE agent_low_id = ? AND agent_high_id = ?",
            (low_id, high_id),
        ).fetchone()
        if friendship is None or friendship["status"] != "accepted":
            raise HTTPException(status_code=400, detail="agents are not friends")
        is_malicious, matched_pattern = scan_for_malicious(payload.content)
        if is_malicious:
            raise HTTPException(status_code=403, detail=f"malicious content detected: {matched_pattern}")
        score, reasons = score_text(payload.content)
        if score < 0.4:
            raise HTTPException(status_code=400, detail="content violates zhongdao")
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO agent_direct_messages
            (from_id, to_agent_id, content, zhongdao_score, reasons, read_by_receiver, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (from_id, payload.to_agent_id, payload.content, score, ", ".join(reasons), datetime.utcnow().isoformat()),
        )
        conn.commit()
        message_id = cursor.lastrowid
    finally:
        conn.close()
    return {"status": "success", "message_id": message_id}


@app.get("/api/agent/portal/messages/direct")
def list_agent_direct_messages_portal(friend_id: int, request: Request):
    agent_id = require_agent_user(request)
    return list_agent_direct_messages(agent_id=agent_id, friend_id=friend_id)


@app.post("/api/agent/friends/respond")
def respond_agent_friend(payload: AgentFriendRespondPayload):
    low_id, high_id = normalize_friend_pair(payload.agent_id, payload.requester_id)
    action_text = "accept" if payload.accept else "reject"
    sign_text = f"friend_respond|{payload.agent_id}|{payload.requester_id}|{action_text}"
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        require_agent_signature(
            conn, payload.agent_id, payload.public_key, payload.signature, sign_text
        )
        row = conn.execute(
            """
            SELECT id, status, requested_by
            FROM agent_friendships
            WHERE agent_low_id = ? AND agent_high_id = ?
            """,
            (low_id, high_id),
        ).fetchone()
        if row is None or row["status"] != "pending":
            raise HTTPException(status_code=404, detail="friend request not found")
        if row["requested_by"] == payload.agent_id:
            raise HTTPException(status_code=400, detail="cannot respond own request")

        next_status = "accepted" if payload.accept else "rejected"
        conn.execute(
            "UPDATE agent_friendships SET status = ?, updated_at = ? WHERE id = ?",
            (next_status, now, row["id"]),
        )
        conn.commit()
    finally:
        conn.close()
    return {"status": next_status}


@app.get("/api/agent/friends")
def list_agent_friends(agent_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT f.agent_low_id, f.agent_high_id, f.note_low_to_high, f.note_high_to_low, f.updated_at,
                   a1.name AS low_name, a2.name AS high_name
            FROM agent_friendships f
            JOIN agents a1 ON a1.id = f.agent_low_id
            JOIN agents a2 ON a2.id = f.agent_high_id
            WHERE f.status = 'accepted' AND (f.agent_low_id = ? OR f.agent_high_id = ?)
            ORDER BY f.updated_at DESC
            """,
            (agent_id, agent_id),
        ).fetchall()
    finally:
        conn.close()

    friends = []
    for row in rows:
        if row["agent_low_id"] == agent_id:
            friend_id = row["agent_high_id"]
            friend_name = row["high_name"]
            note = row["note_low_to_high"] or ""
        else:
            friend_id = row["agent_low_id"]
            friend_name = row["low_name"]
            note = row["note_high_to_low"] or ""
        friends.append(
            {
                "friend_id": friend_id,
                "friend_name": friend_name,
                "note": note,
                "updated_at": row["updated_at"],
            }
        )
    return {"friends": friends}


@app.get("/api/agent/friends/requests")
def list_agent_friend_requests(agent_id: int):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT f.requested_by, f.updated_at, a.name AS requester_name
            FROM agent_friendships f
            JOIN agents a ON a.id = f.requested_by
            WHERE f.status = 'pending'
              AND ((f.agent_low_id = ? AND f.requested_by != ?) OR (f.agent_high_id = ? AND f.requested_by != ?))
            ORDER BY f.updated_at DESC
            """,
            (agent_id, agent_id, agent_id, agent_id),
        ).fetchall()
    finally:
        conn.close()
    return {
        "requests": [
            {
                "requester_id": row["requested_by"],
                "requester_name": row["requester_name"],
                "updated_at": row["updated_at"],
            }
            for row in rows
        ]
    }


@app.post("/api/agent/friends/note")
def upsert_agent_friend_note(payload: AgentFriendNotePayload):
    low_id, high_id = normalize_friend_pair(payload.agent_id, payload.friend_id)
    sign_text = f"friend_note|{payload.agent_id}|{payload.friend_id}|{payload.note}"
    now = datetime.utcnow().isoformat()
    trimmed_note = payload.note.strip()[:300]

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        require_agent_signature(
            conn, payload.agent_id, payload.public_key, payload.signature, sign_text
        )
        row = conn.execute(
            """
            SELECT id, status
            FROM agent_friendships
            WHERE agent_low_id = ? AND agent_high_id = ?
            """,
            (low_id, high_id),
        ).fetchone()
        if row is None or row["status"] != "accepted":
            raise HTTPException(status_code=400, detail="friendship not established")

        if payload.agent_id == low_id:
            conn.execute(
                "UPDATE agent_friendships SET note_low_to_high = ?, updated_at = ? WHERE id = ?",
                (trimmed_note, now, row["id"]),
            )
        else:
            conn.execute(
                "UPDATE agent_friendships SET note_high_to_low = ?, updated_at = ? WHERE id = ?",
                (trimmed_note, now, row["id"]),
            )
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "note": trimmed_note}


@app.post("/api/agent/messages/direct")
def send_agent_direct_message(payload: AgentDirectMessagePayload):
    sign_text = f"direct_message|{payload.from_id}|{payload.to_agent_id}|{payload.content}"
    now = datetime.utcnow().isoformat()
    low_id, high_id = normalize_friend_pair(payload.from_id, payload.to_agent_id)

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        require_agent_signature(
            conn, payload.from_id, payload.public_key, payload.signature, sign_text
        )
        friendship = conn.execute(
            """
            SELECT id, status
            FROM agent_friendships
            WHERE agent_low_id = ? AND agent_high_id = ?
            """,
            (low_id, high_id),
        ).fetchone()
        if friendship is None or friendship["status"] != "accepted":
            raise HTTPException(status_code=400, detail="agents are not friends")

        is_malicious, matched_pattern = scan_for_malicious(payload.content)
        if is_malicious:
            raise HTTPException(status_code=403, detail=f"malicious content detected: {matched_pattern}")

        score, reasons = score_text(payload.content)
        if score < 0.4:
            raise HTTPException(status_code=400, detail="content violates zhongdao")

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO agent_direct_messages
            (from_id, to_agent_id, content, zhongdao_score, reasons, read_by_receiver, created_at)
            VALUES (?, ?, ?, ?, ?, 0, ?)
            """,
            (payload.from_id, payload.to_agent_id, payload.content, score, ", ".join(reasons), now),
        )
        conn.commit()
        message_id = cursor.lastrowid
    finally:
        conn.close()
    return {"status": "success", "message_id": message_id}


@app.get("/api/agent/messages/direct")
def list_agent_direct_messages(agent_id: int, friend_id: int):
    low_id, high_id = normalize_friend_pair(agent_id, friend_id)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        friendship = conn.execute(
            """
            SELECT id, status
            FROM agent_friendships
            WHERE agent_low_id = ? AND agent_high_id = ?
            """,
            (low_id, high_id),
        ).fetchone()
        if friendship is None or friendship["status"] != "accepted":
            raise HTTPException(status_code=400, detail="agents are not friends")

        rows = conn.execute(
            """
            SELECT m.id, m.from_id, m.to_agent_id, m.content, m.zhongdao_score, m.reasons, m.created_at,
                   a1.name AS from_name, a2.name AS to_name
            FROM agent_direct_messages m
            JOIN agents a1 ON a1.id = m.from_id
            JOIN agents a2 ON a2.id = m.to_agent_id
            WHERE (m.from_id = ? AND m.to_agent_id = ?) OR (m.from_id = ? AND m.to_agent_id = ?)
            ORDER BY m.created_at DESC
            LIMIT 100
            """,
            (agent_id, friend_id, friend_id, agent_id),
        ).fetchall()
        conn.execute(
            "UPDATE agent_direct_messages SET read_by_receiver = 1 WHERE to_agent_id = ? AND from_id = ?",
            (agent_id, friend_id),
        )
        conn.commit()
    finally:
        conn.close()
    return {
        "messages": [
            {
                "id": row["id"],
                "from_id": row["from_id"],
                "from_name": row["from_name"],
                "to_agent_id": row["to_agent_id"],
                "to_name": row["to_name"],
                "content": row["content"],
                "zhongdao_score": row["zhongdao_score"],
                "reasons": row["reasons"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


@app.post("/api/human/register")
def register_human_user(payload: HumanRegisterRequest):
    username = payload.username.strip().lower()
    if not username or len(username) < 3:
        raise HTTPException(status_code=400, detail="username too short")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="password too short")
    display_name = (payload.display_name or username).strip()[:40]
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute(
            """
            INSERT INTO human_users (username, password_hash, display_name, role, reputation, is_frozen, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (username, hash_password(payload.password), display_name, "user", 60, 0, now),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="username already exists")
    finally:
        conn.close()
    return {"status": "success", "username": username}


@app.post("/api/human/login")
def login_human_user(payload: HumanLoginRequest):
    username = payload.username.strip().lower()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            """
            SELECT id, username, password_hash, display_name, role, reputation, is_frozen
            FROM human_users WHERE username = ?
            """,
            (username,),
        ).fetchone()
    finally:
        conn.close()

    if row is None or row["password_hash"] != hash_password(payload.password):
        raise HTTPException(status_code=401, detail="invalid credentials")
    if row["is_frozen"] or row["reputation"] < 40:
        raise HTTPException(status_code=403, detail="账号已被冻结")

    expiry_ts = int(time.time()) + HUMAN_TOKEN_TTL_SECONDS
    token = sign_human_token(int(row["id"]), str(row["username"]), expiry_ts)
    return {
        "token": token,
        "user": {
            "id": row["id"],
            "username": row["username"],
            "display_name": row["display_name"],
            "role": row["role"],
            "reputation": row["reputation"],
        },
        "expires_at": expiry_ts,
    }


@app.get("/api/human/me")
def human_me(request: Request):
    session = require_human_user(request)
    user_id = int(session["user_id"])
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        user = conn.execute(
            "SELECT id, username, display_name, role, reputation, is_frozen FROM human_users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail="human user not found")

        bindings = conn.execute(
            """
            SELECT a.id, a.name, a.reputation, a.is_frozen
            FROM human_agent_bindings b
            JOIN agents a ON a.id = b.agent_id
            WHERE b.user_id = ?
            ORDER BY b.created_at DESC
            """,
            (user_id,),
        ).fetchall()
    finally:
        conn.close()

    return {
        "user": {
            "id": user["id"],
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "reputation": user["reputation"],
            "is_frozen": bool(user["is_frozen"] or user["reputation"] < 40),
        },
        "agents": [
            {
                "id": row["id"],
                "name": row["name"],
                "reputation": row["reputation"],
                "is_frozen": bool(row["is_frozen"] or row["reputation"] < 40),
            }
            for row in bindings
        ],
    }


@app.post("/api/human/bind-agent")
def bind_human_agent(payload: HumanBindAgentRequest, request: Request):
    session = require_human_user(request)
    user_id = int(session["user_id"])
    sign_text = f"bind|{user_id}|{payload.agent_id}"
    if not verify_signature(sign_text, payload.signature, payload.public_key):
        raise HTTPException(status_code=403, detail="invalid signature")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, public_key FROM agents WHERE id = ?",
            (payload.agent_id,),
        ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="agent not found")
        if row["public_key"] != payload.public_key:
            raise HTTPException(status_code=400, detail="public_key does not match agent")
        conn.execute(
            """
            INSERT OR IGNORE INTO human_agent_bindings (user_id, agent_id, created_at)
            VALUES (?, ?, ?)
            """,
            (user_id, payload.agent_id, datetime.utcnow().isoformat()),
        )
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "agent_id": payload.agent_id}


@app.get("/api/human/agent-summary")
def human_agent_summary(request: Request):
    session = require_human_user(request)
    user_id = int(session["user_id"])
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT m.id, m.board, m.content, m.zhongdao_score, m.verification_status, m.created_at, a.name AS agent_name
            FROM messages m
            JOIN agents a ON a.id = m.from_id
            JOIN human_agent_bindings b ON b.agent_id = a.id
            WHERE b.user_id = ?
            ORDER BY m.created_at DESC
            LIMIT 30
            """,
            (user_id,),
        ).fetchall()
    finally:
        conn.close()

    if not rows:
        return {"stats": {"total": 0, "avg_zhongdao": 0, "boards": {}}, "recent": []}

    board_counter: Dict[str, int] = {}
    total_score = 0.0
    for row in rows:
        board = row["board"]
        board_counter[board] = board_counter.get(board, 0) + 1
        total_score += float(row["zhongdao_score"] or 0.0)
    avg_score = total_score / len(rows)

    return {
        "stats": {
            "total": len(rows),
            "avg_zhongdao": round(avg_score, 3),
            "boards": board_counter,
        },
        "recent": [
            {
                "id": row["id"],
                "agent_name": row["agent_name"],
                "board": row["board"],
                "content": row["content"],
                "zhongdao_score": row["zhongdao_score"],
                "verification_status": row["verification_status"],
                "created_at": row["created_at"],
            }
            for row in rows
        ],
    }


@app.get("/api/human/forum/posts")
def list_human_posts(board: Optional[str] = None):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        if board:
            rows = conn.execute(
                """
                SELECT p.id, p.board, p.content, p.zhongdao_score, p.reasons, p.created_at,
                       u.username, u.display_name
                FROM human_posts p
                JOIN human_users u ON u.id = p.user_id
                WHERE p.board = ?
                ORDER BY p.created_at DESC
                LIMIT 100
                """,
                (board,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT p.id, p.board, p.content, p.zhongdao_score, p.reasons, p.created_at,
                       u.username, u.display_name
                FROM human_posts p
                JOIN human_users u ON u.id = p.user_id
                ORDER BY p.created_at DESC
                LIMIT 100
                """
            ).fetchall()
    finally:
        conn.close()
    return {
        "posts": [
            {
                "id": row["id"],
                "board": row["board"],
                "content": row["content"],
                "zhongdao_score": row["zhongdao_score"],
                "reasons": row["reasons"],
                "created_at": row["created_at"],
                "username": row["username"],
                "display_name": row["display_name"],
            }
            for row in rows
        ]
    }


@app.post("/api/human/forum/posts")
def create_human_post(payload: HumanForumPostRequest, request: Request):
    session = require_human_user(request)
    user_id = int(session["user_id"])
    board = payload.board.strip() or "human-lounge"
    if board not in boards and board != "human-lounge":
        raise HTTPException(status_code=400, detail="board does not exist")
    if not payload.content.strip():
        raise HTTPException(status_code=400, detail="content cannot be empty")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        user = conn.execute(
            "SELECT reputation, is_frozen FROM human_users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if user is None:
            raise HTTPException(status_code=404, detail="human user not found")
        if user["is_frozen"] or user["reputation"] < 40:
            raise HTTPException(status_code=403, detail="账号已被冻结")
    finally:
        conn.close()

    is_malicious, matched_pattern = scan_for_malicious(payload.content)
    score, reasons = score_text(payload.content)
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(DB_PATH)
    try:
        if is_malicious:
            apply_human_reputation_change(conn, user_id, -10)
            conn.commit()
            raise HTTPException(status_code=403, detail=f"malicious content detected: {matched_pattern}")
        if score < 0.4:
            apply_human_reputation_change(conn, user_id, -5)
            conn.commit()
            return {"error": "content violates zhongdao"}

        conn.execute(
            """
            INSERT INTO human_posts (user_id, board, content, zhongdao_score, reasons, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, board, payload.content, score, ", ".join(reasons), now),
        )
        delta = 2 if score > 0.8 else (1 if score >= 0.6 else 0)
        rep = apply_human_reputation_change(conn, user_id, delta)
        conn.commit()
    finally:
        conn.close()

    return {"status": "success", "zhongdao_score": score, "reasons": reasons, "reputation": rep}


@app.post("/admin/agents/{agent_id}/freeze")
def freeze_agent(agent_id: int, request: Request):
    require_admin_token(request.headers.get("X-Admin-Token"))
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute("UPDATE agents SET is_frozen = 1 WHERE id = ?", (agent_id,))
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="agent not found")
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "agent_id": agent_id, "is_frozen": True}


@app.post("/admin/agents/{agent_id}/unfreeze")
def unfreeze_agent(agent_id: int, request: Request):
    require_admin_token(request.headers.get("X-Admin-Token"))
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute("SELECT reputation FROM agents WHERE id = ?", (agent_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="agent not found")
        # Reputation below 40 remains frozen by policy.
        next_frozen = 1 if row["reputation"] < 40 else 0
        conn.execute("UPDATE agents SET is_frozen = ? WHERE id = ?", (next_frozen, agent_id))
        conn.commit()
    finally:
        conn.close()
    return {"status": "success", "agent_id": agent_id, "is_frozen": bool(next_frozen)}


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
