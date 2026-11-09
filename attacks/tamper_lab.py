"""Offline AES-GCM tampering demonstration; no network traffic is generated."""
from dataclasses import dataclass
import json
import os

from cryptography.exceptions import InvalidTag
from qshield.crypto.aead import AES256GCM, EncryptedMessage


@dataclass(frozen=True, slots=True)
class TamperDemoResult:
    original_round_trip_succeeded: bool
    ciphertext_tampering_rejected: bool
    associated_data_tampering_rejected: bool

    def to_dict(self) -> dict[str, bool]:
        return {
            "original_round_trip_succeeded": self.original_round_trip_succeeded,
            "ciphertext_tampering_rejected": self.ciphertext_tampering_rejected,
            "associated_data_tampering_rejected": self.associated_data_tampering_rejected,
        }


def run_tamper_demo() -> TamperDemoResult:
    """Modify encrypted bytes and AAD to demonstrate GCM authentication."""
    key, aad = os.urandom(32), b"qshield-demo-session"
    encrypted = AES256GCM.encrypt(key, b"confidential test message", aad)
    original_ok = AES256GCM.decrypt(key, encrypted, aad) == b"confidential test message"
    changed = bytearray(encrypted.ciphertext)
    changed[0] ^= 1
    ciphertext_rejected = False
    try:
        AES256GCM.decrypt(key, EncryptedMessage(encrypted.nonce, bytes(changed)), aad)
    except InvalidTag:
        ciphertext_rejected = True
    aad_rejected = False
    try:
        AES256GCM.decrypt(key, encrypted, aad + b"-modified")
    except InvalidTag:
        aad_rejected = True
    return TamperDemoResult(original_ok, ciphertext_rejected, aad_rejected)


def main() -> None:
    print(json.dumps(run_tamper_demo().to_dict(), indent=2))


if __name__ == "__main__":
    main()
