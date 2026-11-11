"""Integration tests for the authenticated post-quantum handshake."""
from dataclasses import replace
import pytest

from qshield.crypto.sig import MLDSA65
from qshield.net.handshake import (
    ClientFinish, HandshakeError, ServerFinish, ServerHello,
    begin_server_handshake, finalize_server_handshake, respond_to_server,
)


def _identities():
    signatures = MLDSA65()
    return signatures.generate_keypair(), signatures.generate_keypair()


def test_authenticated_pq_handshake_derives_same_session_key():
    server_identity, client_identity = _identities()
    server_state = begin_server_handshake(server_identity.secret_key)
    received_hello = ServerHello.from_bytes(server_state.hello.to_bytes())
    client_result = respond_to_server(received_hello, server_identity.public_key, client_identity)
    received_finish = ClientFinish.from_bytes(client_result.client_finish.to_bytes())
    server_result = finalize_server_handshake(
        server_state, received_finish, client_identity.public_key
    )
    received_server_finish = ServerFinish.from_bytes(server_result.server_finish.to_bytes())
    assert client_result.session_key == server_result.session_key
    assert client_result.verify_server_finished(received_server_finish) is True


def test_client_rejects_modified_server_hello():
    server_identity, client_identity = _identities()
    state = begin_server_handshake(server_identity.secret_key)
    altered_key = bytearray(state.hello.kem_public_key)
    altered_key[0] ^= 1
    tampered = replace(state.hello, kem_public_key=bytes(altered_key))
    with pytest.raises(HandshakeError, match="signature is invalid"):
        respond_to_server(tampered, server_identity.public_key, client_identity)


def test_server_rejects_untrusted_client_identity():
    server_identity, client_identity = _identities()
    _, attacker_identity = _identities()
    state = begin_server_handshake(server_identity.secret_key)
    client_result = respond_to_server(state.hello, server_identity.public_key, client_identity)
    with pytest.raises(HandshakeError, match="does not match"):
        finalize_server_handshake(state, client_result.client_finish, attacker_identity.public_key)


def test_server_handshake_state_cannot_be_replayed():
    server_identity, client_identity = _identities()
    state = begin_server_handshake(server_identity.secret_key)
    client_result = respond_to_server(state.hello, server_identity.public_key, client_identity)
    finalize_server_handshake(state, client_result.client_finish, client_identity.public_key)
    with pytest.raises(HandshakeError, match="already been consumed"):
        finalize_server_handshake(state, client_result.client_finish, client_identity.public_key)
