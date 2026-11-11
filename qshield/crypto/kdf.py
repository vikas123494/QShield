"""HKDF-SHA256 key derivation helpers for QShield sessions."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HASH_LENGTH = 32
MAX_DERIVED_LENGTH = 255 * HASH_LENGTH


def derive_key(input_key_material: bytes, *, salt: bytes, info: bytes, length: int = 32) -> bytes:
    """Derive key material with HKDF-SHA256.

    Use a fresh, context-specific salt and an application-specific info value.
    HKDF is a key-derivation function, not a password-hashing function.
    """
    if not isinstance(input_key_material, bytes) or not input_key_material:
        raise ValueError("input_key_material must be non-empty bytes")
    if not isinstance(salt, bytes):
        raise TypeError("salt must be bytes")
    if not isinstance(info, bytes):
        raise TypeError("info must be bytes")
    if not isinstance(length, int) or isinstance(length, bool):
        raise TypeError("length must be an integer")
    if not 1 <= length <= MAX_DERIVED_LENGTH:
        raise ValueError(f"length must be between 1 and {MAX_DERIVED_LENGTH}")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt or None,
        info=info,
    ).derive(input_key_material)
