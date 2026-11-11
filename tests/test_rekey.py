"""Tests for authenticated in-band re-key and dashboard force_rekey queueing."""
import pytest

from qshield.crypto.sig import MLDSA65
from qshield.net import server as server_module
from qshield.net.rekey import (
    REKEY_OFFER_PREFIX, RekeyError, RekeyOffer,
    begin_server_rekey, enqueue_rekey_request, finalize_server_rekey,
    make_control_frame, parse_control_frame, register_rekey_session,
    respond_to_rekey, take_pending_rekey, unregister_rekey_session,
)


def test_authenticated_rekey_derives_same_key_and_confirms_both_sides():
    signatures = MLDSA65()
    server_identity = signatures.generate_keypair()
    client_identity = signatures.generate_keypair()
    old_key = b"O" * 32
    state = begin_server_rekey(old_key, server_identity.secret_key, generation=1)
    offer = RekeyOffer.from_bytes(state.offer.to_bytes())
    client = respond_to_rekey(
        offer, old_key, server_identity.public_key, client_identity,
        expected_generation=1,
    )
    response = type(client.response).from_bytes(client.response.to_bytes())
    server = finalize_server_rekey(state, response, client_identity.public_key)

    assert client.session_key == server.session_key
    finished = type(server.finished).from_bytes(server.finished.to_bytes())
    assert client.verify_server_finished(finished)
    commit = client.create_client_commit()
    assert server.verify_client_commit(type(commit).from_bytes(commit.to_bytes()))


def test_rekey_rejects_offer_bound_to_different_old_session_key():
    signatures = MLDSA65()
    server_identity = signatures.generate_keypair()
    client_identity = signatures.generate_keypair()
    state = begin_server_rekey(b"A" * 32, server_identity.secret_key, generation=1)
    with pytest.raises(RekeyError, match="not bound"):
        respond_to_rekey(
            state.offer, b"B" * 32, server_identity.public_key,
            client_identity, expected_generation=1,
        )


def test_rekey_rejects_tampered_server_offer():
    signatures = MLDSA65()
    server_identity = signatures.generate_keypair()
    client_identity = signatures.generate_keypair()
    state = begin_server_rekey(b"K" * 32, server_identity.secret_key, generation=1)
    tampered = RekeyOffer(
        rekey_id=state.offer.rekey_id,
        generation=state.offer.generation,
        kem_public_key=state.offer.kem_public_key,
        previous_key_hash=state.offer.previous_key_hash,
        server_nonce=b"N" * 32,
        signature=state.offer.signature,
    )
    with pytest.raises(RekeyError, match="signature is invalid"):
        respond_to_rekey(
            tampered, b"K" * 32, server_identity.public_key,
            client_identity, expected_generation=1,
        )


def test_rekey_rejects_wrong_generation():
    signatures = MLDSA65()
    server_identity = signatures.generate_keypair()
    client_identity = signatures.generate_keypair()
    state = begin_server_rekey(b"K" * 32, server_identity.secret_key, generation=2)
    with pytest.raises(RekeyError, match="generation"):
        respond_to_rekey(
            state.offer, b"K" * 32, server_identity.public_key,
            client_identity, expected_generation=1,
        )


def test_rekey_server_state_is_single_use():
    signatures = MLDSA65()
    server_identity = signatures.generate_keypair()
    client_identity = signatures.generate_keypair()
    state = begin_server_rekey(b"K" * 32, server_identity.secret_key, generation=1)
    client = respond_to_rekey(
        state.offer, b"K" * 32, server_identity.public_key,
        client_identity, expected_generation=1,
    )
    finalize_server_rekey(state, client.response, client_identity.public_key)
    with pytest.raises(RekeyError, match="already been consumed"):
        finalize_server_rekey(state, client.response, client_identity.public_key)


def test_control_frames_validate_prefix_and_payload():
    payload = b'{"type":"sample"}'
    frame = make_control_frame(REKEY_OFFER_PREFIX, payload)
    assert parse_control_frame(frame, REKEY_OFFER_PREFIX) == payload
    with pytest.raises(RekeyError, match="Unexpected control message"):
        parse_control_frame(frame, "QSHIELD_REKEY_RESPONSE:")
    with pytest.raises(ValueError, match="unsupported"):
        make_control_frame("NOT_A_REKEY_FRAME:", payload)


def test_rekey_queue_accepts_one_pending_request_and_cleans_up():
    session_id = "test-secure-session"
    command = {"command_id": "cmd-1", "command": "force_rekey", "session_id": session_id}
    register_rekey_session(session_id)
    try:
        assert enqueue_rekey_request(session_id, command)
        assert not enqueue_rekey_request(session_id, command)
        assert take_pending_rekey(session_id) == command
        assert take_pending_rekey(session_id) is None
    finally:
        assert unregister_rekey_session(session_id) == []


def test_pending_rekey_is_returned_if_session_disconnects():
    session_id = "test-disconnect-session"
    command = {"command_id": "cmd-2", "command": "force_rekey", "session_id": session_id}
    register_rekey_session(session_id)
    enqueue_rekey_request(session_id, command)
    assert unregister_rekey_session(session_id) == [command]


def test_force_rekey_dashboard_command_is_queued_for_active_secure_session(monkeypatch):
    session_id = "test-server-command-session"
    command = {"command_id": "cmd-3", "command": "force_rekey", "session_id": session_id}
    results = []
    register_rekey_session(session_id)
    monkeypatch.setattr(
        server_module, "acknowledge_command",
        lambda cmd, status, message: results.append((status, message)),
    )
    try:
        server_module.execute_command(command)
        assert results and results[0][0] == "queued"
        assert take_pending_rekey(session_id) == command
    finally:
        unregister_rekey_session(session_id)
