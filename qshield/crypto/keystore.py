"""Password-encrypted private-key storage for local QShield development."""
import base64
import json
import os
from pathlib import Path
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

_FORMAT_VERSION = 1
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1
_KEY_LENGTH, _SALT_LENGTH, _NONCE_LENGTH = 32, 16, 12


class KeyStoreError(RuntimeError):
    """Raised when an encrypted key file is invalid or cannot be unlocked."""


def _password_bytes(password: str) -> bytes:
    if not isinstance(password, str):
        raise TypeError("password must be a string")
    if not password:
        raise ValueError("password must not be empty")
    return password.encode("utf-8")


def _canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class KeyStore:
    """Encrypt private-key bytes with Scrypt-derived AES-256-GCM keys.

    This is a local encrypted-file utility, not a hardware-backed keystore.
    Never commit passwords, plaintext private keys, or generated key files.
    """

    @staticmethod
    def save_private_key(path: str | Path, private_key: bytes, password: str, *, algorithm: str) -> None:
        if not isinstance(private_key, bytes) or not private_key:
            raise ValueError("private_key must be non-empty bytes")
        if not isinstance(algorithm, str) or not algorithm.strip():
            raise ValueError("algorithm must be a non-empty string")
        password_raw = _password_bytes(password)
        salt, nonce = os.urandom(_SALT_LENGTH), os.urandom(_NONCE_LENGTH)
        header = {
            "version": _FORMAT_VERSION, "kdf": "scrypt",
            "n": _SCRYPT_N, "r": _SCRYPT_R, "p": _SCRYPT_P,
            "algorithm": algorithm,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
        }
        wrapping_key = Scrypt(
            salt=salt, length=_KEY_LENGTH, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P
        ).derive(password_raw)
        ciphertext = AESGCM(wrapping_key).encrypt(nonce, private_key, _canonical_json(header))
        document = {"header": header, "ciphertext": base64.b64encode(ciphertext).decode("ascii")}

        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary: str | None = None
        try:
            fd, temporary = tempfile.mkstemp(
                prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
            )
            if os.name != "nt":
                os.chmod(temporary, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(document, handle, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            temporary = None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except FileNotFoundError:
                    pass

    @staticmethod
    def load_private_key(path: str | Path, password: str, *, expected_algorithm: str | None = None) -> bytes:
        password_raw = _password_bytes(password)
        try:
            document = json.loads(Path(path).read_text(encoding="utf-8"))
            header = document["header"]
            ciphertext = base64.b64decode(document["ciphertext"], validate=True)
            if header["version"] != _FORMAT_VERSION or header["kdf"] != "scrypt":
                raise KeyStoreError("Unsupported encrypted-key file format")
            if expected_algorithm is not None and header["algorithm"] != expected_algorithm:
                raise KeyStoreError("Encrypted key algorithm does not match expectation")
            salt = base64.b64decode(header["salt"], validate=True)
            nonce = base64.b64decode(header["nonce"], validate=True)
            if len(salt) != _SALT_LENGTH or len(nonce) != _NONCE_LENGTH:
                raise KeyStoreError("Invalid salt or nonce length")
            n, r, p = header["n"], header["r"], header["p"]
            if (n, r, p) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
                raise KeyStoreError("Unsupported Scrypt parameters")
            wrapping_key = Scrypt(salt=salt, length=_KEY_LENGTH, n=n, r=r, p=p).derive(password_raw)
            return AESGCM(wrapping_key).decrypt(nonce, ciphertext, _canonical_json(header))
        except KeyStoreError:
            raise
        except InvalidTag as exc:
            raise KeyStoreError("Unable to unlock key file: wrong password or tampering") from exc
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
            raise KeyStoreError("Encrypted-key file is missing or malformed") from exc


__all__ = ["KeyStore", "KeyStoreError"]
