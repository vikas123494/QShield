"""Tests for AES-256-GCM authenticated encryption."""
from dataclasses import replace
import pytest
from cryptography.exceptions import InvalidTag
from qshield.crypto.aead import AES256GCM, EncryptedMessage


def test_aes_gcm_encrypt_decrypt_round_trip():
    key = b"K" * 32
    message = AES256GCM.encrypt(key, b"QShield secret", b"session-123")
    assert AES256GCM.decrypt(key, message, b"session-123") == b"QShield secret"
    assert EncryptedMessage.from_bytes(message.to_bytes()) == message


def test_aes_gcm_detects_ciphertext_tampering():
    key = b"K" * 32
    encrypted = AES256GCM.encrypt(key, b"do not modify")
    changed = bytearray(encrypted.ciphertext)
    changed[0] ^= 1
    with pytest.raises(InvalidTag):
        AES256GCM.decrypt(key, replace(encrypted, ciphertext=bytes(changed)))


def test_aes_gcm_authenticates_associated_data():
    key = b"K" * 32
    encrypted = AES256GCM.encrypt(key, b"payload", b"metadata-A")
    with pytest.raises(InvalidTag):
        AES256GCM.decrypt(key, encrypted, b"metadata-B")


def test_aes_gcm_rejects_wrong_key_size():
    with pytest.raises(ValueError, match="32 bytes"):
        AES256GCM.encrypt(b"short", b"message")
