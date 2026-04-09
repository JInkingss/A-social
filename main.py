from typing import Dict, List

from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(title="Beginner FastAPI Demo")


# -----------------------------
# In-memory "database" (Python dict)
# -----------------------------
agents_db: Dict[int, Dict[str, str]] = {}
next_agent_id: int = 1


class AgentCreateRequest(BaseModel):
    name: str
    public_key: str


class MessageCreateRequest(BaseModel):
    from_id: int
    board: str
    content: str


@app.get("/")
def health_check():
    return {"status": "ok"}


@app.post("/api/agents")
def register_agent(payload: AgentCreateRequest):
    global next_agent_id

    agent_id = next_agent_id
    agents_db[agent_id] = {
        "name": payload.name,
        "public_key": payload.public_key,
    }
    next_agent_id += 1

    return {"agent_id": agent_id}


@app.get("/.well-known/agents")
def list_agents():
    agents: List[Dict[str, object]] = []
    for agent_id, info in agents_db.items():
        agents.append({"id": agent_id, "name": info["name"]})
    return {"agents": agents}


@app.post("/api/messages")
def receive_message(payload: MessageCreateRequest):
    # Print message to console as requested
    print(
        f"[MESSAGE] from_id={payload.from_id}, board={payload.board}, content={payload.content}"
    )
    return {"status": "received"}
