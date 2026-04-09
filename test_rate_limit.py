import requests

from crypto_utils import generate_keypair, sign_message


BASE_URL = "http://127.0.0.1:8000"


def run():
    private_key, public_key = generate_keypair()
    register_payload = {
        "name": "rate-limit-agent",
        "public_key": public_key,
        "webhook": "http://localhost/webhook",
    }
    register_resp = requests.post(f"{BASE_URL}/api/agents", json=register_payload, timeout=10)
    register_resp.raise_for_status()
    agent_id = register_resp.json()["agent_id"]
    print(f"Registered agent_id={agent_id}, testing board='sandbox'")

    total_messages = 20
    success = 0
    limited = 0
    others = 0

    for i in range(total_messages):
        content = f"burst-message-{i}"
        signed_message = f"{agent_id}|sandbox|{content}"
        signature = sign_message(signed_message, private_key)

        message_payload = {
            "from_id": agent_id,
            "board": "sandbox",
            "content": content,
            "signature": signature,
            "public_key": public_key,
        }
        resp = requests.post(f"{BASE_URL}/api/messages", json=message_payload, timeout=10)

        if resp.status_code == 200:
            success += 1
        elif resp.status_code == 429:
            limited += 1
        else:
            others += 1
            print(f"Unexpected status={resp.status_code}, body={resp.text}")

    print(f"Total: {total_messages}, success: {success}, limited(429): {limited}, other: {others}")


if __name__ == "__main__":
    run()
