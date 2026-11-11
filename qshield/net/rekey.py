"""Authenticated in-band post-quantum re-key protocol for Q-SHIELD.

The server signs a fresh ML-KEM-768 offer with its ML-DSA-65 identity key.
The client verifies it, encapsulates a new secret and signs the response.
Both derive a replacement AES-256-GCM key with HKDF-SHA256, mixing the old
session key with the new KEM secret. Finished and Commit MACs confirm the
replacement key before either endpoint switches. Trust anchors are provisioned
out of band, as in the initial secure handshake.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import queue
import secrets
import uuid
from dataclasses import dataclass, field
from threading import Lock
from typing import Any

from qshield.crypto.backend import KEM_ALGORITHM, SIGNATURE_ALGORITHM
from qshield.crypto.kdf import derive_key
from qshield.crypto.kem import MLKEM768
from qshield.crypto.sig import MLDSA65, SignatureKeyPair

_VERSION = 1
_NONCE_SIZE = 32
_SESSION_KEY_SIZE = 32
_MAX_GENERATION = (1 << 64) - 1

REKEY_OFFER_PREFIX = "QSHIELD_REKEY_OFFER:"
REKEY_RESPONSE_PREFIX = "QSHIELD_REKEY_RESPONSE:"
REKEY_FINISHED_PREFIX = "QSHIELD_REKEY_FINISHED:"
REKEY_COMMIT_PREFIX = "QSHIELD_REKEY_COMMIT:"
_CONTROL_PREFIXES = {
    REKEY_OFFER_PREFIX, REKEY_RESPONSE_PREFIX,
    REKEY_FINISHED_PREFIX, REKEY_COMMIT_PREFIX,
}

_QUEUE_LOCK = Lock()
_PENDING_REKEYS: dict[str, queue.Queue[dict[str, Any]]] = {}


class RekeyError(RuntimeError):
    """Raised when an authenticated re-key exchange cannot be completed."""


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: Any, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a base64 string")
    return base64.b64decode(value, validate=True)


def _validate_session_key(value: bytes, name: str = "session_key") -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")
    if len(value) != _SESSION_KEY_SIZE:
        raise ValueError(f"{name} must be exactly 32 bytes")


def _validate_generation(value: int) -> None:
    if (
        not isinstance(value, int) or isinstance(value, bool)
        or not 1 <= value <= _MAX_GENERATION
    ):
        raise ValueError("generation must be a positive 64-bit integer")


def make_control_frame(prefix: str, payload: bytes) -> str:
    """Encode a re-key message for the existing send_message() framing."""
    if prefix not in _CONTROL_PREFIXES:
        raise ValueError("unsupported re-key control prefix")
    if not isinstance(payload, bytes) or not payload:
        raise ValueError("control payload must be non-empty bytes")
    return prefix + _b64(payload)


def parse_control_frame(frame: str, expected_prefix: str) -> bytes:
    """Decode a control frame and enforce its expected message type."""
    if expected_prefix not in _CONTROL_PREFIXES:
        raise ValueError("unsupported re-key control prefix")
    if not isinstance(frame, str) or not frame.startswith(expected_prefix):
        raise RekeyError("Unexpected control message during re-key")
    try:
        payload = base64.b64decode(
            frame[len(expected_prefix):].encode("ascii"), validate=True
        )
    except (UnicodeEncodeError, ValueError) as exc:
        raise RekeyError("Malformed re-key control frame") from exc
    if not payload:
        raise RekeyError("Empty re-key control payload")
    return payload


@dataclass(frozen=True, slots=True)
class RekeyOffer:
    rekey_id: str
    generation: int
    kem_public_key: bytes
    previous_key_hash: bytes
    server_nonce: bytes
    signature: bytes
    version: int = _VERSION
    kem_algorithm: str = KEM_ALGORITHM
    signature_algorithm: str = SIGNATURE_ALGORITHM

    def unsigned_payload(self) -> bytes:
        return _canonical({
            "type": "qshield-rekey-offer",
            "version": self.version,
            "rekey_id": self.rekey_id,
            "generation": self.generation,
            "kem_algorithm": self.kem_algorithm,
            "signature_algorithm": self.signature_algorithm,
            "kem_public_key": _b64(self.kem_public_key),
            "previous_key_hash": _b64(self.previous_key_hash),
            "server_nonce": _b64(self.server_nonce),
        })

    def to_bytes(self) -> bytes:
        value = json.loads(self.unsigned_payload())
        value["signature"] = _b64(self.signature)
        return _canonical(value)

    @classmethod
    def from_bytes(cls, payload: bytes) -> "RekeyOffer":
        try:
            value = json.loads(payload.decode("utf-8"))
            if value.pop("type") != "qshield-rekey-offer":
                raise ValueError("wrong message type")
            return cls(
                rekey_id=value["rekey_id"],
                generation=value["generation"],
                kem_public_key=_unb64(value["kem_public_key"], "kem_public_key"),
                previous_key_hash=_unb64(value["previous_key_hash"], "previous_key_hash"),
                server_nonce=_unb64(value["server_nonce"], "server_nonce"),
                signature=_unb64(value["signature"], "signature"),
                version=value["version"],
                kem_algorithm=value["kem_algorithm"],
                signature_algorithm=value["signature_algorithm"],
            )
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RekeyError("Malformed re-key offer") from exc


@dataclass(frozen=True, slots=True)
class RekeyResponse:
    rekey_id: str
    generation: int
    kem_ciphertext: bytes
    client_nonce: bytes
    signature: bytes
    version: int = _VERSION

    def unsigned_payload(self) -> bytes:
        return _canonical({
            "type": "qshield-rekey-response",
            "version": self.version,
            "rekey_id": self.rekey_id,
            "generation": self.generation,
            "kem_ciphertext": _b64(self.kem_ciphertext),
            "client_nonce": _b64(self.client_nonce),
        })

    def to_bytes(self) -> bytes:
        value = json.loads(self.unsigned_payload())
        value["signature"] = _b64(self.signature)
        return _canonical(value)

    @classmethod
    def from_bytes(cls, payload: bytes) -> "RekeyResponse":
        try:
            value = json.loads(payload.decode("utf-8"))
            if value.pop("type") != "qshield-rekey-response":
                raise ValueError("wrong message type")
            return cls(
                rekey_id=value["rekey_id"],
                generation=value["generation"],
                kem_ciphertext=_unb64(value["kem_ciphertext"], "kem_ciphertext"),
                client_nonce=_unb64(value["client_nonce"], "client_nonce"),
                signature=_unb64(value["signature"], "signature"),
                version=value["version"],
            )
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RekeyError("Malformed re-key response") from exc


@dataclass(frozen=True, slots=True)
class RekeyFinished:
    rekey_id: str
    generation: int
    transcript_hash: bytes
    verify_data: bytes

    def to_bytes(self) -> bytes:
        return _canonical({
            "type": "qshield-rekey-finished",
            "rekey_id": self.rekey_id,
            "generation": self.generation,
            "transcript_hash": _b64(self.transcript_hash),
            "verify_data": _b64(self.verify_data),
        })

    @classmethod
    def from_bytes(cls, payload: bytes) -> "RekeyFinished":
        try:
            value = json.loads(payload.decode("utf-8"))
            if value["type"] != "qshield-rekey-finished":
                raise ValueError("wrong message type")
            return cls(
                rekey_id=value["rekey_id"],
                generation=value["generation"],
                transcript_hash=_unb64(value["transcript_hash"], "transcript_hash"),
                verify_data=_unb64(value["verify_data"], "verify_data"),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RekeyError("Malformed re-key Finished message") from exc


@dataclass(frozen=True, slots=True)
class RekeyCommit:
    rekey_id: str
    generation: int
    transcript_hash: bytes
    verify_data: bytes

    def to_bytes(self) -> bytes:
        return _canonical({
            "type": "qshield-rekey-commit",
            "rekey_id": self.rekey_id,
            "generation": self.generation,
            "transcript_hash": _b64(self.transcript_hash),
            "verify_data": _b64(self.verify_data),
        })

    @classmethod
    def from_bytes(cls, payload: bytes) -> "RekeyCommit":
        try:
            value = json.loads(payload.decode("utf-8"))
            if value["type"] != "qshield-rekey-commit":
                raise ValueError("wrong message type")
            return cls(
                rekey_id=value["rekey_id"],
                generation=value["generation"],
                transcript_hash=_unb64(value["transcript_hash"], "transcript_hash"),
                verify_data=_unb64(value["verify_data"], "verify_data"),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RekeyError("Malformed re-key commit") from exc


@dataclass(slots=True)
class ServerRekeyState:
    offer: RekeyOffer
    kem_secret_key: bytes = field(repr=False)
    previous_session_key: bytes = field(repr=False)
    _consumed: bool = field(default=False, init=False, repr=False)
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)


@dataclass(frozen=True, slots=True)
class ClientRekeyResult:
    response: RekeyResponse
    session_key: bytes = field(repr=False)
    transcript_hash: bytes

    def verify_server_finished(self, finished: RekeyFinished) -> bool:
        expected = hmac.digest(
            self.session_key,
            b"QSHIELD_REKEY_SERVER_FINISHED_V1\x00" + self.transcript_hash,
            "sha256",
        )
        return (
            finished.rekey_id == self.response.rekey_id
            and finished.generation == self.response.generation
            and hmac.compare_digest(finished.transcript_hash, self.transcript_hash)
            and hmac.compare_digest(finished.verify_data, expected)
        )

    def create_client_commit(self) -> RekeyCommit:
        verify_data = hmac.digest(
            self.session_key,
            b"QSHIELD_REKEY_CLIENT_COMMIT_V1\x00" + self.transcript_hash,
            "sha256",
        )
        return RekeyCommit(
            self.response.rekey_id,
            self.response.generation,
            self.transcript_hash,
            verify_data,
        )


@dataclass(frozen=True, slots=True)
class ServerRekeyResult:
    session_key: bytes = field(repr=False)
    finished: RekeyFinished

    def verify_client_commit(self, commit: RekeyCommit) -> bool:
        expected = hmac.digest(
            self.session_key,
            b"QSHIELD_REKEY_CLIENT_COMMIT_V1\x00" + self.finished.transcript_hash,
            "sha256",
        )
        return (
            commit.rekey_id == self.finished.rekey_id
            and commit.generation == self.finished.generation
            and hmac.compare_digest(commit.transcript_hash, self.finished.transcript_hash)
            and hmac.compare_digest(commit.verify_data, expected)
        )


def _transcript_hash(offer: RekeyOffer, response: RekeyResponse) -> bytes:
    return hashlib.sha256(
        b"QSHIELD_REKEY_TRANSCRIPT_V1\x00" + offer.to_bytes() + response.to_bytes()
    ).digest()


def _derive_rekey_session_key(
    previous_session_key: bytes,
    kem_shared_secret: bytes,
    offer: RekeyOffer,
    response: RekeyResponse,
    transcript_hash: bytes,
) -> bytes:
    salt = hashlib.sha256(offer.server_nonce + response.client_nonce).digest()
    info = (
        b"QSHIELD_REKEY_SESSION_KEY_V1\x00"
        + offer.generation.to_bytes(8, "big")
        + transcript_hash
    )
    return derive_key(
        previous_session_key + kem_shared_secret,
        salt=salt,
        info=info,
        length=_SESSION_KEY_SIZE,
    )


def begin_server_rekey(
    current_session_key: bytes,
    server_identity_secret_key: bytes,
    *,
    generation: int,
) -> ServerRekeyState:
    """Create a signed ephemeral ML-KEM offer for the next key generation."""
    _validate_session_key(current_session_key, "current_session_key")
    _validate_generation(generation)
    if not isinstance(server_identity_secret_key, bytes) or not server_identity_secret_key:
        raise ValueError("server_identity_secret_key must be non-empty bytes")

    ephemeral = MLKEM768().generate_keypair()
    unsigned = RekeyOffer(
        rekey_id=str(uuid.uuid4()),
        generation=generation,
        kem_public_key=ephemeral.public_key,
        previous_key_hash=hashlib.sha256(current_session_key).digest(),
        server_nonce=secrets.token_bytes(_NONCE_SIZE),
        signature=b"pending",
    )
    signature = MLDSA65().sign(
        server_identity_secret_key,
        b"QSHIELD_REKEY_SERVER_OFFER_V1\x00" + unsigned.unsigned_payload(),
    )
    offer = RekeyOffer(
        rekey_id=unsigned.rekey_id,
        generation=unsigned.generation,
        kem_public_key=unsigned.kem_public_key,
        previous_key_hash=unsigned.previous_key_hash,
        server_nonce=unsigned.server_nonce,
        signature=signature,
    )
    return ServerRekeyState(
        offer=offer,
        kem_secret_key=ephemeral.secret_key,
        previous_session_key=current_session_key,
    )


def respond_to_rekey(
    offer: RekeyOffer,
    current_session_key: bytes,
    trusted_server_public_key: bytes,
    client_identity: SignatureKeyPair,
    *,
    expected_generation: int,
) -> ClientRekeyResult:
    """Verify the offer, encapsulate the new secret and sign the transcript."""
    _validate_session_key(current_session_key, "current_session_key")
    _validate_generation(expected_generation)
    if offer.version != _VERSION or offer.generation != expected_generation:
        raise RekeyError("Unexpected re-key version or generation")
    if offer.kem_algorithm != KEM_ALGORITHM or offer.signature_algorithm != SIGNATURE_ALGORITHM:
        raise RekeyError("Unsupported re-key algorithms")
    if len(offer.server_nonce) != _NONCE_SIZE or len(offer.previous_key_hash) != 32:
        raise RekeyError("Invalid re-key offer metadata")
    if not hmac.compare_digest(
        offer.previous_key_hash, hashlib.sha256(current_session_key).digest()
    ):
        raise RekeyError("Re-key offer is not bound to the current session key")
    if not isinstance(trusted_server_public_key, bytes) or not trusted_server_public_key:
        raise ValueError("trusted_server_public_key must be non-empty bytes")
    if not isinstance(client_identity, SignatureKeyPair):
        raise TypeError("client_identity must be a SignatureKeyPair")

    signatures = MLDSA65()
    valid = signatures.verify(
        trusted_server_public_key,
        b"QSHIELD_REKEY_SERVER_OFFER_V1\x00" + offer.unsigned_payload(),
        offer.signature,
    )
    if not valid:
        raise RekeyError("Server re-key offer signature is invalid")

    encapsulated = MLKEM768().encapsulate(offer.kem_public_key)
    unsigned = RekeyResponse(
        rekey_id=offer.rekey_id,
        generation=offer.generation,
        kem_ciphertext=encapsulated.ciphertext,
        client_nonce=secrets.token_bytes(_NONCE_SIZE),
        signature=b"pending",
    )
    signature = signatures.sign(
        client_identity.secret_key,
        b"QSHIELD_REKEY_CLIENT_RESPONSE_V1\x00"
        + offer.to_bytes()
        + unsigned.unsigned_payload(),
    )
    response = RekeyResponse(
        rekey_id=unsigned.rekey_id,
        generation=unsigned.generation,
        kem_ciphertext=unsigned.kem_ciphertext,
        client_nonce=unsigned.client_nonce,
        signature=signature,
    )
    digest = _transcript_hash(offer, response)
    key = _derive_rekey_session_key(
        current_session_key, encapsulated.shared_secret, offer, response, digest
    )
    return ClientRekeyResult(response, key, digest)


def finalize_server_rekey(
    state: ServerRekeyState,
    response: RekeyResponse,
    trusted_client_public_key: bytes,
) -> ServerRekeyResult:
    """Authenticate the client response and derive the replacement session key.

    Each server re-key state is single-use, including on validation failure.
    """
    with state._lock:
        if state._consumed:
            raise RekeyError("Re-key state has already been consumed")
        state._consumed = True

    try:
        offer = state.offer
        if response.version != _VERSION:
            raise RekeyError("Unsupported re-key protocol version")
        if response.rekey_id != offer.rekey_id or response.generation != offer.generation:
            raise RekeyError("Re-key response does not match the server offer")
        if len(response.client_nonce) != _NONCE_SIZE:
            raise RekeyError("Invalid client re-key nonce")
        if not isinstance(trusted_client_public_key, bytes) or not trusted_client_public_key:
            raise ValueError("trusted_client_public_key must be non-empty bytes")

        valid = MLDSA65().verify(
            trusted_client_public_key,
            b"QSHIELD_REKEY_CLIENT_RESPONSE_V1\x00"
            + offer.to_bytes()
            + response.unsigned_payload(),
            response.signature,
        )
        if not valid:
            raise RekeyError("Client re-key response signature is invalid")

        try:
            shared_secret = MLKEM768().decapsulate(
                state.kem_secret_key, response.kem_ciphertext
            )
        except (TypeError, ValueError, RuntimeError, OSError) as exc:
            raise RekeyError("Unable to decapsulate re-key ciphertext") from exc

        digest = _transcript_hash(offer, response)
        key = _derive_rekey_session_key(
            state.previous_session_key, shared_secret, offer, response, digest
        )
        verify_data = hmac.digest(
            key, b"QSHIELD_REKEY_SERVER_FINISHED_V1\x00" + digest, "sha256"
        )
        return ServerRekeyResult(
            key,
            RekeyFinished(offer.rekey_id, offer.generation, digest, verify_data),
        )
    finally:
        state.kem_secret_key = b""
        state.previous_session_key = b""


def register_rekey_session(session_id: str) -> None:
    """Register a live secure session for dashboard force_rekey requests."""
    if not isinstance(session_id, str) or not session_id.strip():
        raise ValueError("session_id must be non-empty")
    with _QUEUE_LOCK:
        if session_id in _PENDING_REKEYS:
            raise RekeyError("Session already has a re-key queue")
        _PENDING_REKEYS[session_id] = queue.Queue(maxsize=1)


def enqueue_rekey_request(session_id: str, command: dict[str, Any]) -> bool:
    """Queue one re-key request for a registered secure session."""
    if not isinstance(command, dict):
        raise TypeError("command must be a dictionary")
    with _QUEUE_LOCK:
        pending = _PENDING_REKEYS.get(session_id)
        if pending is None:
            return False
        try:
            pending.put_nowait(dict(command))
        except queue.Full:
            return False
        return True


def take_pending_rekey(session_id: str) -> dict[str, Any] | None:
    """Return a dashboard re-key request, if one is waiting."""
    with _QUEUE_LOCK:
        pending = _PENDING_REKEYS.get(session_id)
        if pending is None:
            return None
        try:
            return pending.get_nowait()
        except queue.Empty:
            return None


def unregister_rekey_session(session_id: str) -> list[dict[str, Any]]:
    """Unregister a session and return queued requests that never ran."""
    with _QUEUE_LOCK:
        pending = _PENDING_REKEYS.pop(session_id, None)
        if pending is None:
            return []
        leftovers = []
        while True:
            try:
                leftovers.append(pending.get_nowait())
            except queue.Empty:
                break
        return leftovers


__all__ = [
    "ClientRekeyResult", "REKEY_COMMIT_PREFIX", "REKEY_FINISHED_PREFIX",
    "REKEY_OFFER_PREFIX", "REKEY_RESPONSE_PREFIX", "RekeyCommit",
    "RekeyError", "RekeyFinished", "RekeyOffer", "RekeyResponse",
    "RekeyServerResult", "ServerRekeyState", "begin_server_rekey",
    "enqueue_rekey_request", "finalize_server_rekey", "make_control_frame",
    "parse_control_frame", "register_rekey_session", "respond_to_rekey",
    "take_pending_rekey", "unregister_rekey_session",
]
