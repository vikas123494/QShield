"""Authenticated encryption using AES-256-GCM."""
from dataclasses import dataclass
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16
WIRE_MAGIC = b"QSA1"


@dataclass(frozen=True, slots=True)
class EncryptedMessage:
    """AES-GCM nonce and ciphertext (which includes the authentication tag)."""
    nonce: bytes
    ciphertext: bytes

    def to_bytes(self) -> bytes:
        """Serialize as magic || nonce || ciphertext."""
        if len(self.nonce) != NONCE_SIZE:
            raise ValueError("nonce must be exactly 12 bytes")
        if len(self.ciphertext) < TAG_SIZE:
            raise ValueError("ciphertext is too short to contain a GCM tag")
        return WIRE_MAGIC + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, value: bytes) -> "EncryptedMessage":
        if not isinstance(value, bytes):
            raise TypeError("value must be bytes")
        minimum = len(WIRE_MAGIC) + NONCE_SIZE + TAG_SIZE
        if len(value) < minimum or not value.startswith(WIRE_MAGIC):
            raise ValueError("invalid QShield encrypted-message encoding")
        offset = len(WIRE_MAGIC)
        return cls(value[offset:offset + NONCE_SIZE], value[offset + NONCE_SIZE:])


class AES256GCM:
    """Strict wrapper around the cryptography AESGCM implementation."""

    @staticmethod
    def _validate_key(key: bytes) -> None:
        if not isinstance(key, bytes):
            raise TypeError("key must be bytes")
        if len(key) != KEY_SIZE:
            raise ValueError("AES-256-GCM key must be exactly 32 bytes")

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> EncryptedMessage:
        """Encrypt bytes and authenticate optional public metadata as AAD."""
        AES256GCM._validate_key(key)
        if not isinstance(plaintext, bytes):
            raise TypeError("plaintext must be bytes")
        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be bytes")
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, associated_data or None)
        return EncryptedMessage(nonce=nonce, ciphertext=ciphertext)

    @staticmethod
    def decrypt(key: bytes, encrypted: EncryptedMessage, associated_data: bytes = b"") -> bytes:
        """Authenticate and decrypt; changed ciphertext or AAD raises InvalidTag."""
        AES256GCM._validate_key(key)
        if not isinstance(encrypted, EncryptedMessage):
            raise TypeError("encrypted must be an EncryptedMessage")
        if not isinstance(associated_data, bytes):
            raise TypeError("associated_data must be bytes")
        if len(encrypted.nonce) != NONCE_SIZE:
            raise ValueError("nonce must be exactly 12 bytes")
        if len(encrypted.ciphertext) < TAG_SIZE:
            raise ValueError("ciphertext is too short")
        return AESGCM(key).decrypt(encrypted.nonce, encrypted.ciphertext, associated_data or None)


__all__ = ["AES256GCM", "EncryptedMessage"]
