import sqlite3
import threading
import time
import json
import hashlib
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


app = FastAPI(title="Beginner FastAPI Demo")

DB_PATH = "forum.db"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
boards: Dict[str, int] = {"code-review": 10, "general": 20, "sandbox": 5}
_leaky_buckets: Dict[str, Dict[str, float]] = {}
_bucket_lock = threading.Lock()
POW_PREFIX = "0000"
IP_LIMIT_PER_HOUR = 3
DOMAIN_LIMIT_PER_DAY = 5
_registration_lock = threading.Lock()
_ip_register_state: Dict[str, Dict[str, float]] = {}
_domain_register_state: Dict[str, Dict[str, float]] = {}
ADMIN_TOKEN = "secret"
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


@app.get("/")
def health_check():
    return {"status": "ok"}


@app.get("/admin")
def admin_panel():
    return FileResponse(STATIC_DIR / "index.html")


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
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def on_startup():
    init_db()
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
