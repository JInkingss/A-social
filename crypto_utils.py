from ecdsa import BadSignatureError, SigningKey, VerifyingKey
from ecdsa.curves import Ed25519


def generate_keypair() -> tuple[str, str]:
    signing_key = SigningKey.generate(curve=Ed25519)
    private_key = signing_key.to_string().hex()
    public_key = signing_key.get_verifying_key().to_string().hex()
    return private_key, public_key


def sign_message(message: str, private_key: str) -> str:
    signing_key = SigningKey.from_string(bytes.fromhex(private_key), curve=Ed25519)
    signature = signing_key.sign(message.encode("utf-8"))
    return signature.hex()


def verify_signature(message: str, signature: str, public_key: str) -> bool:
    try:
        verify_key = VerifyingKey.from_string(bytes.fromhex(public_key), curve=Ed25519)
        verify_key.verify(bytes.fromhex(signature), message.encode("utf-8"))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False
