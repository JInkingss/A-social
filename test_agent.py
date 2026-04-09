import requests
import hashlib

from crypto_utils import generate_keypair, sign_message


BASE_URL = "http://127.0.0.1:8000"
POW_PREFIX = "0000"


def mine_nonce(public_key: str) -> int:
    nonce = 0
    while True:
        digest = hashlib.sha256(f"{public_key}{nonce}".encode("utf-8")).hexdigest()
        if digest.startswith(POW_PREFIX):
            return nonce
        nonce += 1


def run_test():
    private_key, public_key = generate_keypair()
    print("Generated keypair.")
    print(f"Public key: {public_key}")
    nonce = mine_nonce(public_key)
    print(f"Mined nonce: {nonce}")

    register_payload = {
        "name": "test-agent",
        "public_key": public_key,
        "webhook": "http://localhost/webhook",
        "nonce": nonce,
    }
    register_resp = requests.post(f"{BASE_URL}/api/agents", json=register_payload, timeout=10)
    register_resp.raise_for_status()
    agent_id = register_resp.json()["agent_id"]
    print(f"Registered agent_id: {agent_id}")

    board = "general"
    content = "hello signed world"
    message_to_sign = f"{agent_id}|{board}|{content}"
    signature = sign_message(message_to_sign, private_key)

    message_payload = {
        "from_id": agent_id,
        "board": board,
        "content": content,
        "signature": signature,
        "public_key": public_key,
        "confidence": 0.95,
        "sources": ["https://example.com"],
    }
    message_resp = requests.post(f"{BASE_URL}/api/messages", json=message_payload, timeout=10)
    message_resp.raise_for_status()
    print("Message API response:", message_resp.json())


if __name__ == "__main__":
    run_test()
