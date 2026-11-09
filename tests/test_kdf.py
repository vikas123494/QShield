"""Tests for HKDF-SHA256 key derivation."""
import pytest
from qshield.crypto.kdf import derive_key


def test_hkdf_is_deterministic_for_same_inputs():
    args = {"salt": b"test-salt", "info": b"qshield test context"}
    first = derive_key(b"input key material", **args)
    assert first == derive_key(b"input key material", **args)
    assert len(first) == 32


def test_hkdf_separates_different_contexts():
    key_a = derive_key(b"shared secret", salt=b"salt", info=b"client")
    key_b = derive_key(b"shared secret", salt=b"salt", info=b"server")
    assert key_a != key_b


def test_hkdf_supports_requested_length():
    assert len(derive_key(b"secret", salt=b"", info=b"", length=64)) == 64


@pytest.mark.parametrize("length", [0, -1, 8161])
def test_hkdf_rejects_invalid_length(length):
    with pytest.raises(ValueError):
        derive_key(b"secret", salt=b"", info=b"", length=length)
