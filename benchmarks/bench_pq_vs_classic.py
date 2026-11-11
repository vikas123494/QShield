"""Measure QShield post-quantum primitives against classical P-256 baselines.

All timings are measured on the machine running this script. They are not
portable performance claims and should be regenerated for each demo machine.
"""
import argparse
import json
from pathlib import Path
import statistics
import time
from typing import Callable, TypeVar

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from qshield.crypto.kem import MLKEM768
from qshield.crypto.sig import MLDSA65

T = TypeVar("T")
MESSAGE = b"QShield local benchmark message"


def _measure_ms(operation: Callable[[], T]) -> tuple[float, T]:
    started = time.perf_counter_ns()
    result = operation()
    return (time.perf_counter_ns() - started) / 1_000_000, result


def _public_key_size(key: ec.EllipticCurvePublicKey) -> int:
    return len(key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint))


def run_benchmarks(iterations: int = 10) -> list[dict[str, int | float | str]]:
    """Run KEM, ECDH, signature and ECDSA measurements and return JSON rows."""
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
        raise ValueError("iterations must be a positive integer")
    rows: list[dict[str, int | float | str]] = []

    kem = MLKEM768()
    keygen, encaps, decaps = [], [], []
    kem_sizes: dict[str, int] = {}
    for _ in range(iterations):
        elapsed, pair = _measure_ms(kem.generate_keypair)
        keygen.append(elapsed)
        elapsed, encrypted = _measure_ms(lambda: kem.encapsulate(pair.public_key))
        encaps.append(elapsed)
        elapsed, recovered = _measure_ms(lambda: kem.decapsulate(pair.secret_key, encrypted.ciphertext))
        decaps.append(elapsed)
        if recovered != encrypted.shared_secret:
            raise RuntimeError("ML-KEM shared-secret self-check failed")
        kem_sizes = {
            "public_key_bytes": len(pair.public_key),
            "secret_key_bytes": len(pair.secret_key),
            "ciphertext_bytes": len(encrypted.ciphertext),
        }
    rows.append({
        "algorithm": "ML-KEM-768", "family": "post-quantum", "iterations": iterations,
        "keygen_ms": statistics.mean(keygen), "encaps_ms": statistics.mean(encaps),
        "decaps_ms": statistics.mean(decaps), **kem_sizes,
    })

    ecdh_keygen, ecdh_client, ecdh_server = [], [], []
    classical_sizes: dict[str, int] = {}
    for _ in range(iterations):
        elapsed, client_private = _measure_ms(lambda: ec.generate_private_key(ec.SECP256R1()))
        ecdh_keygen.append(elapsed)
        elapsed, server_private = _measure_ms(lambda: ec.generate_private_key(ec.SECP256R1()))
        ecdh_keygen.append(elapsed)
        elapsed, client_secret = _measure_ms(
            lambda: client_private.exchange(ec.ECDH(), server_private.public_key())
        )
        ecdh_client.append(elapsed)
        elapsed, server_secret = _measure_ms(
            lambda: server_private.exchange(ec.ECDH(), client_private.public_key())
        )
        ecdh_server.append(elapsed)
        if client_secret != server_secret:
            raise RuntimeError("ECDH shared-secret self-check failed")
        classical_sizes = {
            "public_key_bytes": _public_key_size(client_private.public_key()),
            "secret_key_bytes": 32, "ciphertext_bytes": 0,
        }
    rows.append({
        "algorithm": "ECDH-P256", "family": "classical", "iterations": iterations,
        "keygen_ms": statistics.mean(ecdh_keygen), "encaps_ms": statistics.mean(ecdh_client),
        "decaps_ms": statistics.mean(ecdh_server), **classical_sizes,
    })

    pq = MLDSA65()
    pq_keygen, pq_sign, pq_verify = [], [], []
    pq_sizes: dict[str, int] = {}
    for _ in range(iterations):
        elapsed, identity = _measure_ms(pq.generate_keypair)
        pq_keygen.append(elapsed)
        elapsed, signature = _measure_ms(lambda: pq.sign(identity.secret_key, MESSAGE))
        pq_sign.append(elapsed)
        elapsed, valid = _measure_ms(lambda: pq.verify(identity.public_key, MESSAGE, signature))
        pq_verify.append(elapsed)
        if not valid:
            raise RuntimeError("ML-DSA signature self-check failed")
        pq_sizes = {
            "public_key_bytes": len(identity.public_key),
            "secret_key_bytes": len(identity.secret_key),
            "signature_bytes": len(signature),
        }
    rows.append({
        "algorithm": "ML-DSA-65", "family": "post-quantum", "iterations": iterations,
        "keygen_ms": statistics.mean(pq_keygen), "sign_ms": statistics.mean(pq_sign),
        "verify_ms": statistics.mean(pq_verify), **pq_sizes,
    })

    ecdsa_keygen, ecdsa_sign, ecdsa_verify = [], [], []
    ecdsa_sizes: dict[str, int] = {}
    for _ in range(iterations):
        elapsed, private = _measure_ms(lambda: ec.generate_private_key(ec.SECP256R1()))
        ecdsa_keygen.append(elapsed)
        elapsed, signature = _measure_ms(lambda: private.sign(MESSAGE, ec.ECDSA(hashes.SHA256())))
        ecdsa_sign.append(elapsed)
        def verify_signature() -> bool:
            try:
                private.public_key().verify(signature, MESSAGE, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception:
                return False
        elapsed, valid = _measure_ms(verify_signature)
        ecdsa_verify.append(elapsed)
        if not valid:
            raise RuntimeError("ECDSA signature self-check failed")
        ecdsa_sizes = {
            "public_key_bytes": _public_key_size(private.public_key()),
            "secret_key_bytes": 32, "signature_bytes": len(signature),
        }
    rows.append({
        "algorithm": "ECDSA-P256", "family": "classical", "iterations": iterations,
        "keygen_ms": statistics.mean(ecdsa_keygen), "sign_ms": statistics.mean(ecdsa_sign),
        "verify_ms": statistics.mean(ecdsa_verify), **ecdsa_sizes,
    })
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=10)
    parser.add_argument("--output", default="data/benchmarks.json")
    args = parser.parse_args()
    results = run_benchmarks(args.iterations)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results, indent=2))
    print(f"Saved measured results to {output}")


if __name__ == "__main__":
    main()
