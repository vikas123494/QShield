"""Tests for password-encrypted private-key storage."""
import json
import pytest
from qshield.crypto.keystore import KeyStore, KeyStoreError


def test_keystore_round_trip(tmp_path):
    path = tmp_path / "keys" / "identity.qsk"
    private_key = b"example-private-key-material"
    KeyStore.save_private_key(path, private_key, "a-long-demo-password", algorithm="ML-DSA-65")
    loaded = KeyStore.load_private_key(path, "a-long-demo-password", expected_algorithm="ML-DSA-65")
    assert loaded == private_key
    assert private_key not in path.read_bytes()


def test_keystore_rejects_wrong_password(tmp_path):
    path = tmp_path / "identity.qsk"
    KeyStore.save_private_key(path, b"private", "correct", algorithm="ML-KEM-768")
    with pytest.raises(KeyStoreError, match="wrong password or tampering"):
        KeyStore.load_private_key(path, "incorrect")


def test_keystore_rejects_algorithm_mismatch(tmp_path):
    path = tmp_path / "identity.qsk"
    KeyStore.save_private_key(path, b"private", "password", algorithm="ML-KEM-768")
    with pytest.raises(KeyStoreError, match="algorithm"):
        KeyStore.load_private_key(path, "password", expected_algorithm="ML-DSA-65")


def test_keystore_rejects_tampered_header(tmp_path):
    path = tmp_path / "identity.qsk"
    KeyStore.save_private_key(path, b"private", "password", algorithm="ML-DSA-65")
    document = json.loads(path.read_text(encoding="utf-8"))
    document["header"]["algorithm"] = "ML-KEM-768"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(KeyStoreError):
        KeyStore.load_private_key(path, "password")
