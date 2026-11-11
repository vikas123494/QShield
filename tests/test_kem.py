"""Functional and input-validation tests for the ML-KEM-768 adapter."""

import pytest

from qshield.crypto.kem import MLKEM768


def test_ml_kem_768_encapsulation_round_trip():
    kem = MLKEM768()
    key_pair = kem.generate_keypair()

    encapsulated = kem.encapsulate(key_pair.public_key)
    recovered_secret = kem.decapsulate(
        key_pair.secret_key, encapsulated.ciphertext
    )

    assert encapsulated.shared_secret == recovered_secret
    assert len(recovered_secret) == 32


def test_encapsulate_rejects_empty_public_key():
    kem = MLKEM768()

    with pytest.raises(ValueError, match='public_key must not be empty'):
        kem.encapsulate(b'')


def test_encapsulate_rejects_wrong_public_key_length():
    kem = MLKEM768()

    with pytest.raises(ValueError, match='public_key must be exactly'):
        kem.encapsulate(b'not-a-valid-ml-kem-public-key')


def test_decapsulate_rejects_empty_inputs():
    kem = MLKEM768()

    with pytest.raises(ValueError, match='secret_key must not be empty'):
        kem.decapsulate(b'', b'ciphertext')

    with pytest.raises(ValueError, match='ciphertext must not be empty'):
        kem.decapsulate(b'secret-key', b'')
