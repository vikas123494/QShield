"""Authenticated post-quantum QShield handshake state machine.

The server signs its ephemeral ML-KEM public key. The client verifies that
signature against a pre-trusted server key, encapsulates a secret, and signs
the transcript. The server verifies the client against a pre-trusted client
key. Both sides derive the same session key using HKDF-SHA256.

This module handles cryptographic messages, not TCP framing, identity
enrollment, certificates, or network key provisioning. Trust anchors are
expected to be provisioned out of band.
"""
from dataclasses import dataclass, field
import base64
import hashlib
import hmac
import json
import secrets
from threading import Lock

from qshield.crypto.backend import KEM_ALGORITHM, SIGNATURE_ALGORITHM
from qshield.crypto.kdf import derive_key
from qshield.crypto.kem import MLKEM768
from qshield.crypto.sig import MLDSA65, SignatureKeyPair

_HANDSHAKE_VERSION = 1
_NONCE_SIZE = 32


class HandshakeError(RuntimeError):
    """Raised when a peer, transcript, or handshake state is invalid."""


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True, slots=True)
class ServerHello:
    kem_public_key: bytes
    server_nonce: bytes
    signature: bytes
    version: int = _HANDSHAKE_VERSION
    kem_algorithm: str = KEM_ALGORITHM
    signature_algorithm: str = SIGNATURE_ALGORITHM

    def unsigned_payload(self) -> bytes:
        return _canonical({
            "type": "qshield-server-hello", "version": self.version,
            "kem_algorithm": self.kem_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "kem_public_key": _b64(self.kem_public_key),
            "server_nonce": _b64(self.server_nonce),
        })

    def to_bytes(self) -> bytes:
        value = json.loads(self.unsigned_payload())
        value["signature"] = _b64(self.signature)
        return _canonical(value)

    @classmethod
    def from_bytes(cls, value: bytes) -> "ServerHello":
        try:
            data = json.loads(value)
            if data.pop("type") != "qshield-server-hello":
                raise ValueError("unexpected message type")
            return cls(
                kem_public_key=_unb64(data["kem_public_key"]),
                server_nonce=_unb64(data["server_nonce"]),
                signature=_unb64(data["signature"]),
                version=data["version"], kem_algorithm=data["kem_algorithm"],
                signature_algorithm=data["signature_algorithm"],
            )
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise HandshakeError("Malformed server hello") from exc


@dataclass(frozen=True, slots=True)
class ClientFinish:
    kem_ciphertext: bytes
    client_nonce: bytes
    client_identity_public_key: bytes
    signature: bytes
    version: int = _HANDSHAKE_VERSION

    def unsigned_payload(self) -> bytes:
        return _canonical({
            "type": "qshield-client-finish", "version": self.version,
            "kem_ciphertext": _b64(self.kem_ciphertext),
            "client_nonce": _b64(self.client_nonce),
            "client_identity_public_key": _b64(self.client_identity_public_key),
        })

    def to_bytes(self) -> bytes:
        value = json.loads(self.unsigned_payload())
        value["signature"] = _b64(self.signature)
        return _canonical(value)

    @classmethod
    def from_bytes(cls, value: bytes) -> "ClientFinish":
        try:
            data = json.loads(value)
            if data.pop("type") != "qshield-client-finish":
                raise ValueError("unexpected message type")
            return cls(
                kem_ciphertext=_unb64(data["kem_ciphertext"]),
                client_nonce=_unb64(data["client_nonce"]),
                client_identity_public_key=_unb64(data["client_identity_public_key"]),
                signature=_unb64(data["signature"]), version=data["version"],
            )
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise HandshakeError("Malformed client finish") from exc


@dataclass(frozen=True, slots=True)
class ServerFinish:
    transcript_hash: bytes
    verify_data: bytes

    def to_bytes(self) -> bytes:
        return _canonical({
            "type": "qshield-server-finish",
            "transcript_hash": _b64(self.transcript_hash),
            "verify_data": _b64(self.verify_data),
        })

    @classmethod
    def from_bytes(cls, value: bytes) -> "ServerFinish":
        try:
            data = json.loads(value)
            if data["type"] != "qshield-server-finish":
                raise ValueError("unexpected message type")
            return cls(_unb64(data["transcript_hash"]), _unb64(data["verify_data"]))
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise HandshakeError("Malformed server finish") from exc


@dataclass(slots=True)
class ServerHandshakeState:
    hello: ServerHello
    kem_secret_key: bytes = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)


@dataclass(frozen=True, slots=True)
class ClientHandshakeResult:
    client_finish: ClientFinish
    session_key: bytes = field(repr=False)
    transcript_hash: bytes

    def verify_server_finished(self, server_finish: ServerFinish) -> bool:
        expected = hmac.digest(
            self.session_key, b"QSHIELD_SERVER_FINISHED_V1" + self.transcript_hash, "sha256"
        )
        return (
            hmac.compare_digest(server_finish.transcript_hash, self.transcript_hash)
            and hmac.compare_digest(server_finish.verify_data, expected)
        )


@dataclass(frozen=True, slots=True)
class ServerHandshakeResult:
    session_key: bytes = field(repr=False)
    server_finish: ServerFinish


def _validate_server_hello(hello: ServerHello) -> None:
    if hello.version != _HANDSHAKE_VERSION:
        raise HandshakeError("Unsupported handshake version")
    if hello.kem_algorithm != KEM_ALGORITHM:
        raise HandshakeError("Unsupported KEM algorithm")
    if hello.signature_algorithm != SIGNATURE_ALGORITHM:
        raise HandshakeError("Unsupported signature algorithm")
    if len(hello.server_nonce) != _NONCE_SIZE:
        raise HandshakeError("Invalid server nonce length")
    if not hello.kem_public_key or not hello.signature:
        raise HandshakeError("Server hello is missing cryptographic data")


def _client_signing_bytes(hello: ServerHello, finish: ClientFinish) -> bytes:
    return b"QSHIELD_CLIENT_FINISH_V1\x00" + hello.to_bytes() + finish.unsigned_payload()


def _transcript_hash(hello: ServerHello, finish: ClientFinish) -> bytes:
    return hashlib.sha256(
        b"QSHIELD_TRANSCRIPT_V1\x00" + hello.to_bytes() + finish.to_bytes()
    ).digest()


def _derive_session_key(shared_secret: bytes, hello: ServerHello, finish: ClientFinish, digest: bytes) -> bytes:
    salt = hashlib.sha256(hello.server_nonce + finish.client_nonce).digest()
    return derive_key(
        shared_secret, salt=salt,
        info=b"QSHIELD_SESSION_KEY_V1\x00" + digest, length=32,
    )


def begin_server_handshake(server_identity_secret_key: bytes) -> ServerHandshakeState:
    """Create a signed ephemeral KEM offer using the server identity private key."""
    ephemeral = MLKEM768().generate_keypair()
    unsigned = ServerHello(ephemeral.public_key, secrets.token_bytes(_NONCE_SIZE), b"pending")
    signature = MLDSA65().sign(
        server_identity_secret_key,
        b"QSHIELD_SERVER_HELLO_V1\x00" + unsigned.unsigned_payload(),
    )
    hello = ServerHello(ephemeral.public_key, unsigned.server_nonce, signature)
    return ServerHandshakeState(hello=hello, kem_secret_key=ephemeral.secret_key)


def respond_to_server(
    hello: ServerHello, trusted_server_public_key: bytes, client_identity: SignatureKeyPair
) -> ClientHandshakeResult:
    """Verify the server, encapsulate a secret, and sign the client transcript."""
    _validate_server_hello(hello)
    signatures = MLDSA65()
    if not signatures.verify(
        trusted_server_public_key,
        b"QSHIELD_SERVER_HELLO_V1\x00" + hello.unsigned_payload(),
        hello.signature,
    ):
        raise HandshakeError("Server identity signature is invalid")

    encapsulated = MLKEM768().encapsulate(hello.kem_public_key)
    unsigned = ClientFinish(
        encapsulated.ciphertext, secrets.token_bytes(_NONCE_SIZE),
        client_identity.public_key, b"pending",
    )
    signature = signatures.sign(
        client_identity.secret_key, _client_signing_bytes(hello, unsigned)
    )
    finish = ClientFinish(
        unsigned.kem_ciphertext, unsigned.client_nonce,
        unsigned.client_identity_public_key, signature,
    )
    digest = _transcript_hash(hello, finish)
    key = _derive_session_key(encapsulated.shared_secret, hello, finish, digest)
    return ClientHandshakeResult(finish, key, digest)


def finalize_server_handshake(
    state: ServerHandshakeState, client_finish: ClientFinish, trusted_client_public_key: bytes
) -> ServerHandshakeResult:
    """Authenticate the client, decapsulate the secret, and confirm key possession.

    A server handshake state is single-use, including when validation fails.
    Create a new ephemeral state for every connection attempt.
    """
    with state._lock:
        if state._consumed:
            raise HandshakeError("Handshake state has already been consumed")
        state._consumed = True

    if client_finish.version != _HANDSHAKE_VERSION:
        raise HandshakeError("Unsupported client-finish version")
    if len(client_finish.client_nonce) != _NONCE_SIZE:
        raise HandshakeError("Invalid client nonce length")
    if not hmac.compare_digest(client_finish.client_identity_public_key, trusted_client_public_key):
        raise HandshakeError("Client identity key does not match the trusted key")
    if not MLDSA65().verify(
        trusted_client_public_key,
        _client_signing_bytes(state.hello, client_finish),
        client_finish.signature,
    ):
        raise HandshakeError("Client identity signature is invalid")

    try:
        shared_secret = MLKEM768().decapsulate(state.kem_secret_key, client_finish.kem_ciphertext)
    except (TypeError, ValueError, RuntimeError) as exc:
        raise HandshakeError("Unable to decapsulate client KEM ciphertext") from exc

    digest = _transcript_hash(state.hello, client_finish)
    key = _derive_session_key(shared_secret, state.hello, client_finish, digest)
    verify_data = hmac.digest(key, b"QSHIELD_SERVER_FINISHED_V1" + digest, "sha256")
    return ServerHandshakeResult(
        key, ServerFinish(transcript_hash=digest, verify_data=verify_data)
    )


__all__ = [
    "ClientFinish", "ClientHandshakeResult", "HandshakeError", "ServerFinish",
    "ServerHandshakeResult", "ServerHandshakeState", "ServerHello",
    "begin_server_handshake", "finalize_server_handshake", "respond_to_server",
]
