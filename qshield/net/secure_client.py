import base64
import socket
from getpass import getpass

from qshield.crypto.aead import AES256GCM, EncryptedMessage
from qshield.crypto.backend import SIGNATURE_ALGORITHM
from qshield.crypto.keystore import KeyStore
from qshield.crypto.sig import SignatureKeyPair
from qshield.net.handshake import ServerFinish, ServerHello, respond_to_server
from qshield.net.protocol import receive_message, send_message
from qshield.net.rekey import (
    REKEY_COMMIT_PREFIX,
    REKEY_FINISHED_PREFIX,
    REKEY_OFFER_PREFIX,
    REKEY_RESPONSE_PREFIX,
    RekeyFinished,
    RekeyOffer,
    make_control_frame,
    parse_control_frame,
    respond_to_rekey,
)

HOST = "127.0.0.1"
PORT = 5001
AAD = b"QSHIELD_APP_V1"


def main():
    password = getpass("Client private-key password: ")
    client_private = KeyStore.load_private_key(
        "keys/client_private.keystore", password,
        expected_algorithm=SIGNATURE_ALGORITHM,
    )
    client_public = open("keys/client_public.bin", "rb").read()
    trusted_server = open("keys/server_public.bin", "rb").read()
    client_identity = SignatureKeyPair(
        public_key=client_public,
        secret_key=client_private,
    )

    print("Client identity loaded.")
    with socket.create_connection((HOST, PORT), timeout=60) as conn:
        conn.settimeout(300)
        hello = ServerHello.from_bytes(receive_message(conn).encode("utf-8"))
        result = respond_to_server(hello, trusted_server, client_identity)
        send_message(conn, result.client_finish.to_bytes().decode("utf-8"))
        server_finish = ServerFinish.from_bytes(
            receive_message(conn).encode("utf-8")
        )
        if not result.verify_server_finished(server_finish):
            raise RuntimeError("Server handshake confirmation failed")

        session_key = result.session_key
        rekey_generation = 0
        del result

        print("Post-quantum handshake successful.")
        print("Server identity verified; encrypted session established.")
        print("Type messages. Enter /quit to close the session.")

        while True:
            message = input("You: ")
            encrypted = AES256GCM.encrypt(
                session_key, message.encode("utf-8"),
                associated_data=AAD,
            )
            send_message(conn, base64.b64encode(encrypted.to_bytes()).decode("ascii"))
            if message.strip() == "/quit":
                print("Secure session closed.")
                break

            encoded_reply = receive_message(conn)
            while encoded_reply.startswith(REKEY_OFFER_PREFIX):
                offer = RekeyOffer.from_bytes(
                    parse_control_frame(encoded_reply, REKEY_OFFER_PREFIX)
                )
                client_rekey = respond_to_rekey(
                    offer, session_key, trusted_server, client_identity,
                    expected_generation=rekey_generation + 1,
                )
                send_message(
                    conn,
                    make_control_frame(REKEY_RESPONSE_PREFIX, client_rekey.response.to_bytes()),
                )

                finished_frame = receive_message(conn)
                finished = RekeyFinished.from_bytes(
                    parse_control_frame(finished_frame, REKEY_FINISHED_PREFIX)
                )
                if not client_rekey.verify_server_finished(finished):
                    raise RuntimeError("Server re-key key-confirmation failed")

                send_message(
                    conn,
                    make_control_frame(
                        REKEY_COMMIT_PREFIX,
                        client_rekey.create_client_commit().to_bytes(),
                    ),
                )
                session_key = client_rekey.session_key
                rekey_generation = offer.generation
                print(f"Authenticated post-quantum re-key complete (generation {rekey_generation}).")
                encoded_reply = receive_message(conn)

            encrypted_reply = EncryptedMessage.from_bytes(
                base64.b64decode(encoded_reply, validate=True)
            )
            reply = AES256GCM.decrypt(
                session_key, encrypted_reply, associated_data=AAD
            )
            print("Server:", reply.decode("utf-8"))


if __name__ == "__main__":
    main()
