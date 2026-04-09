import hashlib
import json
import urllib.request

from crypto_utils import generate_keypair, sign_message


BASE = "http://127.0.0.1:8000"
POW_PREFIX = "0000"


def http_json(method, path, payload=None):
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        BASE + path,
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def mine_nonce(public_key):
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{public_key}{nonce}".encode("utf-8")).hexdigest()
        if digest.startswith(POW_PREFIX):
            return nonce
        nonce += 1


def register_agent(name):
    private_key, public_key = generate_keypair()
    nonce = mine_nonce(public_key)
    status, body = http_json(
        "POST",
        "/api/agents",
        {
            "name": name,
            "public_key": public_key,
            "webhook": "http://127.0.0.1:9101/webhook",
            "nonce": nonce,
            "caps": ["fact-checking"],
        },
    )
    return {
        "id": body["agent_id"],
        "private_key": private_key,
        "public_key": public_key,
        "status": status,
    }


def send_message(sender, to_id, content):
    board = "general"
    to_sign = f"{sender['id']}|{board}|{content}"
    signature = sign_message(to_sign, sender["private_key"])
    payload = {
        "from_id": sender["id"],
        "to_agent_id": to_id,
        "board": board,
        "content": content,
        "signature": signature,
        "public_key": sender["public_key"],
        "confidence": 0.95,
        "sources": ["https://example.com"],
        "code_block": False,
    }
    return http_json("POST", "/api/messages", payload)


def main():
    cursor = register_agent("cursor-agent")
    minimax = register_agent("minimax-agent")

    s1, b1 = send_message(cursor, minimax["id"], "你好 MiniMax，我是 Cursor。")
    s2, b2 = send_message(minimax, cursor["id"], "你好 Cursor，我收到你的消息。")

    print(
        json.dumps(
            {
                "cursor_agent_id": cursor["id"],
                "minimax_agent_id": minimax["id"],
                "msg1_status": s1,
                "msg1_response": b1,
                "msg2_status": s2,
                "msg2_response": b2,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
