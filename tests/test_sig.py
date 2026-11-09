"""Functional and validation tests for the ML-DSA-65 adapter."""

import pytest

from qshield.crypto.sig import MLDSA65


def test_ml_dsa_65_sign_and_verify_round_trip():
    signer = MLDSA65()
    key_pair = signer.generate_keypair()
    message = b"QShield authenticated handshake transcript"

    signature = signer.sign(key_pair.secret_key, message)

    # Verification uses only the public key, not the signer's private key.
    verifier = MLDSA65()
    assert verifier.verify(key_pair.public_key, message, signature) is True


def test_modified_message_fails_verification():
    signer = MLDSA65()
    key_pair = signer.generate_keypair()
    message = b"original QShield message"
    signature = signer.sign(key_pair.secret_key, message)

    assert signer.verify(key_pair.public_key, message + b"!", signature) is False


def test_modified_signature_fails_verification():
    signer = MLDSA65()
    key_pair = signer.generate_keypair()
    message = b"QShield signature tamper test"
    signature = bytearray(signer.sign(key_pair.secret_key, message))
    signature[0] ^= 0x01

    assert signer.verify(key_pair.public_key, message, bytes(signature)) is False


def test_sign_rejects_empty_secret_key():
    signer = MLDSA65()

    with pytest.raises(ValueError, match="secret_key must not be empty"):
        signer.sign(b"", b"message")


def test_verify_rejects_wrong_public_key_length():
    signer = MLDSA65()

    with pytest.raises(ValueError, match="public_key must be exactly"):
        signer.verify(b"bad-key", b"message", b"bad-signature")


def test_empty_message_can_be_signed_and_verified():
    signer = MLDSA65()
    key_pair = signer.generate_keypair()
    signature = signer.sign(key_pair.secret_key, b"")

    assert signer.verify(key_pair.public_key, b"", signature) is True
