import base64
import json
import socket
import threading
import uuid
from datetime import datetime, timezone
from getpass import getpass
from pathlib import Path

from cryptography.exceptions import InvalidTag

from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.keystore import KeyStore
from qshield.monitor.event_bridge import process_event
from qshield.net.handshake import (
    ClientFinish,
    HandshakeError,
    begin_server_handshake,
    finalize_server_handshake,
)
from qshield.net.protocol import receive_message, send_message
from qshield.net.rekey import (
    REKEY_COMMIT_PREFIX,
    REKEY_FINISHED_PREFIX,
    REKEY_OFFER_PREFIX,
    REKEY_RESPONSE_PREFIX,
    RekeyCommit,
    RekeyError,
    RekeyResponse,
    begin_server_rekey,
    finalize_server_rekey,
    make_control_frame,
    parse_control_frame,
    register_rekey_session,
    take_pending_rekey,
    unregister_rekey_session,
)
from qshield.net.server import (
    active_sessions,
    active_sessions_lock,
    check_connection_allowed,
    command_processor,
    command_stop_event,
    update_session,
    acknowledge_command,
)

HOST = "127.0.0.1"
PORT = 5001
AAD = b"QSHIELD_APP_V1"
EVENT_FILE = Path("data/events.jsonl")
EVENT_LOCK = threading.Lock()


def log_event(event_type, outcome, source_ip, session_id,
              severity="INFO", details="", byte_count=0):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": event_type,
        "outcome": outcome,
        "source_ip": source_ip,
        "session_id": session_id,
        "bytes": byte_count,
        "severity": severity,
        "source": "secure_server",
        "details": details,
    }

    EVENT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with EVENT_LOCK:
        with EVENT_FILE.open("a", encoding="utf-8") as file:
            file.write(json.dumps(event, ensure_ascii=False) + "\n")

    try:
        for alert in process_event(event):
            print(f"[IDS ALERT] {alert.severity}: {alert.title}")
    except Exception as exc:
        print(f"[IDS BRIDGE ERROR] {exc}")


def handle_client(conn, address, server_private, trusted_client):
    source_ip = address[0]
    session_id = str(uuid.uuid4())
    handshake_complete = False

    try:
        update_session(
            session_id, "Connected", source_ip,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        with conn:
            conn.settimeout(300)
            log_event("CLIENT_CONNECTED", "SUCCESS", source_ip, session_id)

            state = begin_server_handshake(server_private)
            send_message(conn, state.hello.to_bytes().decode("utf-8"))

            client_finish = ClientFinish.from_bytes(
                receive_message(conn).encode("utf-8")
            )
            result = finalize_server_handshake(
                state, client_finish, trusted_client
            )
            send_message(
                conn, result.server_finish.to_bytes().decode("utf-8")
            )

            handshake_complete = True
            register_rekey_session(session_id)
            with active_sessions_lock:
                active_sessions[session_id] = conn
            session_key = result.session_key
            rekey_generation = 0
            del result
            del state

            update_session(
                session_id, "Active", source_ip,
                user_id="verified-client",
            )
            log_event(
                "HANDSHAKE_SUCCESS", "SUCCESS", source_ip, session_id,
                details="Client identity verified; session key established",
            )
            print(f"[SESSION REGISTERED] {session_id}")

            # One authenticated TCP connection now carries multiple encrypted messages.
            while True:
                encoded = receive_message(conn)
                encrypted_data = EncryptedMessage.from_bytes(
                    base64.b64decode(encoded, validate=True)
                )

                try:
                    plaintext = AES256GCM.decrypt(
                        session_key,
                        encrypted_data,
                        associated_data=AAD,
                    )
                except InvalidTag:
                    log_event(
                        "TAG_FAIL", "FAILED", source_ip, session_id,
                        severity="CRITICAL",
                        details="AES-GCM authentication tag verification failed",
                    )
                    raise

                log_event(
                    "MESSAGE_RECEIVED", "SUCCESS", source_ip, session_id,
                    byte_count=len(plaintext),
                    details="Encrypted application message decrypted",
                )
                message = plaintext.decode("utf-8")
                print(f"[{session_id[:8]}] Client: {message}")

                if message == "/quit":
                    break

                pending_rekey = take_pending_rekey(session_id)
                if pending_rekey is not None:
                    try:
                        next_generation = rekey_generation + 1
                        rekey_state = begin_server_rekey(
                            session_key, server_private, generation=next_generation
                        )
                        send_message(
                            conn,
                            make_control_frame(REKEY_OFFER_PREFIX, rekey_state.offer.to_bytes()),
                        )
                        response_frame = receive_message(conn)
                        rekey_response = RekeyResponse.from_bytes(
                            parse_control_frame(response_frame, REKEY_RESPONSE_PREFIX)
                        )
                        rekey_result = finalize_server_rekey(
                            rekey_state, rekey_response, trusted_client
                        )
                        send_message(
                            conn,
                            make_control_frame(REKEY_FINISHED_PREFIX, rekey_result.finished.to_bytes()),
                        )
                        commit_frame = receive_message(conn)
                        rekey_commit = RekeyCommit.from_bytes(
                            parse_control_frame(commit_frame, REKEY_COMMIT_PREFIX)
                        )
                        if not rekey_result.verify_client_commit(rekey_commit):
                            raise RekeyError("Client key-confirmation MAC is invalid")

                        # Switch only after both peers confirm the replacement key.
                        session_key = rekey_result.session_key
                        rekey_generation = next_generation
                        acknowledge_command(
                            pending_rekey,
                            "executed",
                            f"Authenticated post-quantum re-key completed (generation {rekey_generation})",
                        )
                        log_event(
                            "SESSION_REKEY_SUCCESS", "SUCCESS", source_ip, session_id,
                            details=f"Authenticated ML-KEM re-key generation {rekey_generation} completed",
                        )
                        print(f"[RE-KEY COMPLETE] {session_id[:8]} generation={rekey_generation}")
                    except Exception as exc:
                        acknowledge_command(
                            pending_rekey,
                            "failed",
                            f"Re-key failed; closing session to prevent key desynchronisation: {exc}",
                        )
                        log_event(
                            "SESSION_REKEY_FAILED", "FAILED", source_ip, session_id,
                            severity="CRITICAL", details=str(exc),
                        )
                        raise ConnectionError("Authenticated re-key failed; session closed") from exc

                reply = f"Q-SHIELD received: {message}".encode("utf-8")
                encrypted_reply = AES256GCM.encrypt(
                    session_key, reply, associated_data=AAD
                )
                send_message(
                    conn,
                    base64.b64encode(encrypted_reply.to_bytes()).decode("ascii"),
                )
                log_event(
                    "MESSAGE_SENT", "SUCCESS", source_ip, session_id,
                    byte_count=len(reply),
                    details="Encrypted server reply sent",
                )

    except HandshakeError as exc:
        log_event(
            "HANDSHAKE_FAIL", "FAILED", source_ip, session_id,
            severity="HIGH", details=str(exc),
        )
        print(f"[{session_id[:8]}] Handshake failed: {exc}")
    except InvalidTag:
        print(f"[{session_id[:8]}] Message authentication failed.")
    except (ConnectionError, OSError, ValueError, TimeoutError) as exc:
        if not handshake_complete:
            log_event(
                "HANDSHAKE_FAIL", "FAILED", source_ip, session_id,
                severity="MEDIUM", details=str(exc),
            )
        else:
            print(f"[{session_id[:8]}] Session ended: {exc}")
    finally:
        pending_commands = unregister_rekey_session(session_id)
        for pending_command in pending_commands:
            acknowledge_command(
                pending_command,
                "rejected",
                "Session disconnected before the queued re-key could run",
            )
        with active_sessions_lock:
            active_sessions.pop(session_id, None)
        try:
            update_session(session_id, "Disconnected", source_ip)
        except (OSError, ValueError) as exc:
            print("Unable to update disconnected session:", exc)
        log_event("CLIENT_DISCONNECTED", "SUCCESS", source_ip, session_id)
        print(f"Client disconnected: {address}")


def main():
    password = getpass("Server private-key password: ")
    server_private = KeyStore.load_private_key(
        "keys/server_private.keystore", password,
        expected_algorithm=SIGNATURE_ALGORITHM,
    )
    trusted_client = Path("keys/client_public.bin").read_bytes()
    print("Server identity loaded.")

    command_stop_event.clear()
    command_thread = threading.Thread(
        target=command_processor,
        name="qshield-command-processor",
        daemon=True,
    )
    command_thread.start()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((HOST, PORT))
            server.listen(10)
            print(f"Q-SHIELD secure server listening on {HOST}:{PORT}")
            print("Dashboard command processor is active.")

            while True:
                conn, address = server.accept()
                allowed, reason = check_connection_allowed(address[0])
                if not allowed:
                    print("Connection rejected:", address, "-", reason)
                    conn.close()
                    continue

                worker = threading.Thread(
                    target=handle_client,
                    args=(conn, address, server_private, trusted_client),
                    daemon=True,
                )
                worker.start()
    except KeyboardInterrupt:
        print("\nQ-SHIELD secure server shutting down.")
    finally:
        command_stop_event.set()
        command_thread.join(timeout=2)


if __name__ == "__main__":
    main()

