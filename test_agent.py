import requests

from crypto_utils import generate_keypair, sign_message


BASE_URL = "http://127.0.0.1:8000"


def run_test():
    private_key, public_key = generate_keypair()
    print("Generated keypair.")
    print(f"Public key: {public_key}")

    register_payload = {
        "name": "test-agent",
        "public_key": public_key,
        "webhook": "http://localhost/webhook",
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
    }
    message_resp = requests.post(f"{BASE_URL}/api/messages", json=message_payload, timeout=10)
    message_resp.raise_for_status()
    print("Message API response:", message_resp.json())


if __name__ == "__main__":
    run_test()
