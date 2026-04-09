import sqlite3
import threading
import time
import json
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime
from typing import Dict, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from crypto_utils import verify_signature
from zhongdao import score_text


app = FastAPI(title="Beginner FastAPI Demo")

DB_PATH = "forum.db"
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
boards: Dict[str, int] = {"code-review": 10, "general": 20, "sandbox": 5}
_leaky_buckets: Dict[str, Dict[str, float]] = {}
_bucket_lock = threading.Lock()


class AgentCreateRequest(BaseModel):
    name: str
    public_key: str
    webhook: Optional[str] = None


class MessageCreateRequest(BaseModel):
    from_id: int
    board: str
    content: str
    signature: str
    public_key: str
    to_agent_id: Optional[int] = None


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
                reputation INTEGER DEFAULT 60,
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
        # Lightweight migration: old databases may not have to_agent_id column.
        message_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()
        }
        if "to_agent_id" not in message_columns:
            conn.execute("ALTER TABLE messages ADD COLUMN to_agent_id INTEGER")
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
        "SELECT reputation FROM agents WHERE id = ?",
        (agent_id,),
    ).fetchone()
    if row is None:
        raise HTTPException(status_code=400, detail="agent not found")

    old_rep = int(row[0] or 60)
    new_rep = max(0, min(100, old_rep + change_amount))
    actual_change = new_rep - old_rep

    if actual_change != 0:
        conn.execute(
            "UPDATE agents SET reputation = ? WHERE id = ?",
            (new_rep, agent_id),
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


@app.post("/api/agents")
def register_agent(payload: AgentCreateRequest):
    conn = sqlite3.connect(DB_PATH)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO agents (name, public_key, webhook, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (payload.name, payload.public_key, payload.webhook, datetime.utcnow().isoformat()),
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
            "SELECT id, name, reputation FROM agents ORDER BY id ASC"
        ).fetchall()
    finally:
        conn.close()

    agents = [
        {"id": row["id"], "name": row["name"], "reputation": row["reputation"]}
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
                       a.name AS agent_name, a.reputation AS agent_reputation
                FROM messages m
                JOIN agents a ON a.id = m.from_id
                WHERE m.board = ?
                ORDER BY m.created_at DESC
                LIMIT 100
                """,
                (board,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT m.id, m.board, m.content, m.zhongdao_score, m.created_at, m.to_agent_id,
                       a.name AS agent_name, a.reputation AS agent_reputation
                FROM messages m
                JOIN agents a ON a.id = m.from_id
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
            "agent_frozen": row["agent_reputation"] < 40,
            "to_agent_id": row["to_agent_id"],
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
            SELECT l.id, l.board, l.content, l.zhongdao_score, l.reasons, l.created_at, a.name AS agent_name
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
            "created_at": row["created_at"],
            "agent_name": row["agent_name"],
        }
        for row in rows
    ]
    return {"alerts": alerts}


@app.post("/api/messages")
def receive_message(payload: MessageCreateRequest, background_tasks: BackgroundTasks):
    if payload.board not in boards:
        raise HTTPException(status_code=400, detail="board does not exist")

    if not allow_board_request(payload.board):
        raise HTTPException(status_code=429, detail="rate limit exceeded for board")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT id, name, public_key, reputation FROM agents WHERE public_key = ?",
            (payload.public_key,),
        ).fetchone()
    finally:
        conn.close()

    if row is None:
        raise HTTPException(status_code=403, detail="agent not found")

    if row["id"] != payload.from_id:
        raise HTTPException(status_code=403, detail="from_id does not match public_key")
    if row["reputation"] < 40:
        raise HTTPException(status_code=403, detail="agent is frozen due to low reputation")

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

    score, reasons = score_text(payload.content)
    now = datetime.utcnow().isoformat()

    if score < 0.4:
        conn = sqlite3.connect(DB_PATH)
        try:
            conn.execute(
                """
                INSERT INTO audit_log (from_id, board, content, zhongdao_score, reasons, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (payload.from_id, payload.board, payload.content, score, ", ".join(reasons), now),
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
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO messages (from_id, to_agent_id, board, content, zhongdao_score, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                payload.from_id,
                payload.to_agent_id,
                payload.board,
                payload.content,
                score,
                now,
            ),
        )
        message_id = cursor.lastrowid
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


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
