"""Tests for the configured QShield post-quantum backend."""

from qshield.crypto.backend import (
    KEM_ALGORITHM,
    SIGNATURE_ALGORITHM,
    backend_info,
    get_oqs,
)


def test_required_algorithms_are_enabled():
    oqs = get_oqs()

    assert KEM_ALGORITHM in oqs.get_enabled_kem_mechanisms()
    assert SIGNATURE_ALGORITHM in oqs.get_enabled_sig_mechanisms()


def test_backend_info_reports_expected_provider():
    info = backend_info()

    assert info["provider"] == "liboqs-python"
    assert info["version"]
    assert info["kem"] == KEM_ALGORITHM
    assert info["signature"] == SIGNATURE_ALGORITHM
    assert info["status"] == "available"
