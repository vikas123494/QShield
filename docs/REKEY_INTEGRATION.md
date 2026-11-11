# Q-SHIELD authenticated in-session re-key

## API

Implementation: qshield/net/rekey.py

- begin_server_rekey(current_session_key, server_identity_secret_key, generation=next_generation) creates a fresh ephemeral ML-KEM-768 keypair and signed offer.
- respond_to_rekey(offer, current_session_key, trusted_server_public_key, client_identity, expected_generation=next_generation) verifies the server ML-DSA-65 signature, encapsulates a KEM secret and signs the response.
- finalize_server_rekey(state, response, trusted_client_public_key) verifies the client signature, decapsulates the KEM ciphertext and derives the replacement key.
- ClientRekeyResult.verify_server_finished(finished) validates the server MAC under the new key.
- ClientRekeyResult.create_client_commit() produces the client's final key-confirmation message.
- ServerRekeyResult.verify_client_commit(commit) validates the client's final confirmation.
- make_control_frame(prefix, payload) and parse_control_frame(frame, expected_prefix) transport re-key messages over the existing length-prefixed TCP protocol.

The active key must not be replaced until both Finished and Commit checks succeed. On an error, close the session rather than continuing with uncertain key state.

## Control message format

Each message is a string consisting of a message prefix followed by base64-encoded canonical JSON bytes:

1. QSHIELD_REKEY_OFFER: type, version, rekey_id, generation, kem_algorithm, signature_algorithm, kem_public_key, previous_key_hash, server_nonce, signature.
2. QSHIELD_REKEY_RESPONSE: type, version, rekey_id, generation, kem_ciphertext, client_nonce, signature.
3. QSHIELD_REKEY_FINISHED: type, rekey_id, generation, transcript_hash, verify_data.
4. QSHIELD_REKEY_COMMIT: type, rekey_id, generation, transcript_hash, verify_data.

All byte fields are base64 strings. ML-DSA-65 authenticates the signed offer and response using pre-trusted long-term identity keys. previous_key_hash binds the signed offer to the current session. HKDF derives a new 32-byte AES key from the prior session key plus the fresh ML-KEM shared secret and transcript context. Finished and Commit are HMAC-SHA256 key confirmations under the new key.

## Dashboard force_rekey behavior

The command processor accepts force_rekey only for a live secure session. It records queued when accepted. The secure server performs the exchange at the next client-message boundary and records executed only after both key confirmations pass. It records failed if the exchange fails and closes the connection, or rejected if the session disconnects before the exchange starts.

This is message-boundary re-keying. An idle client waiting at the keyboard will not receive an immediate push; the queued request runs when the client next sends an application message. The secure client transparently handles the control frames before reading the encrypted application reply.

## Integration

secure_server.py registers each authenticated session with the re-key queue. server.py routes dashboard force_rekey requests to that queue. secure_client.py recognizes the control frames and updates its session key only after server Finished verification and sending Client Commit.

## Cryptographic benchmark JSON

Run benchmarks/run_benchmarks.bat on Windows or execute:

python -m benchmarks.bench_pq_vs_classic --iterations 20 --output data/benchmarks.json

This produces the JSON list consumed by the dashboard, with measured ML-KEM-768, ECDH-P256, ML-DSA-65 and ECDSA-P256 timings and key/signature sizes. Measurements are machine-specific; generate them on the computer used for the demo. The data/benchmarks.json ignore rule has been removed so the measured file can be committed.
