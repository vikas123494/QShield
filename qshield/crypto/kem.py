"""ML-KEM-768 key generation, encapsulation, and decapsulation."""

from dataclasses import dataclass, field

from qshield.crypto.backend import KEM_ALGORITHM, get_oqs


@dataclass(frozen=True, slots=True)
class KEMKeyPair:
    """ML-KEM key material; repr intentionally hides the private key."""

    public_key: bytes
    secret_key: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class EncapsulationResult:
    """Ciphertext to send to the key owner and the local shared secret."""

    ciphertext: bytes
    shared_secret: bytes = field(repr=False)


class MLKEM768:
    """Small QShield adapter around liboqs-python's ML-KEM-768 API.

    The key owner generates a key pair and shares the public key. A peer
    encapsulates to that public key and sends the returned ciphertext back.
    The key owner decapsulates the ciphertext with its private key.

    ML-KEM establishes a shared secret; it does not authenticate the peer or
    the public key. The handshake must authenticate identities and transcript
    data separately, for example with ML-DSA signatures.
    """

    algorithm = KEM_ALGORITHM

    def __init__(self) -> None:
        self._oqs = get_oqs()

    @staticmethod
    def _require_bytes(value: bytes, name: str) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")
        if not value:
            raise ValueError(f"{name} must not be empty")

    def generate_keypair(self) -> KEMKeyPair:
        """Generate a fresh ML-KEM-768 key pair using the library RNG."""
        with self._oqs.KeyEncapsulation(self.algorithm) as kem:
            public_key = bytes(kem.generate_keypair())
            secret_key = bytes(kem.export_secret_key())

            details = kem.details
            if len(public_key) != details["length_public_key"]:
                raise RuntimeError("liboqs returned an unexpected public-key length")
            if len(secret_key) != details["length_secret_key"]:
                raise RuntimeError("liboqs returned an unexpected secret-key length")

        return KEMKeyPair(public_key=public_key, secret_key=secret_key)

    def encapsulate(self, public_key: bytes) -> EncapsulationResult:
        """Encapsulate to a peer public key; return ciphertext and shared secret."""
        self._require_bytes(public_key, "public_key")

        with self._oqs.KeyEncapsulation(self.algorithm) as kem:
            expected_length = kem.details["length_public_key"]
            if len(public_key) != expected_length:
                raise ValueError(f"public_key must be exactly {expected_length} bytes")

            ciphertext, shared_secret = kem.encap_secret(public_key)
            ciphertext = bytes(ciphertext)
            shared_secret = bytes(shared_secret)

            if len(ciphertext) != kem.details["length_ciphertext"]:
                raise RuntimeError("liboqs returned an unexpected ciphertext length")
            if len(shared_secret) != kem.details["length_shared_secret"]:
                raise RuntimeError("liboqs returned an unexpected shared-secret length")

        return EncapsulationResult(
            ciphertext=ciphertext,
            shared_secret=shared_secret,
        )

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret using the recipient private key."""
        self._require_bytes(secret_key, "secret_key")
        self._require_bytes(ciphertext, "ciphertext")

        # liboqs-python validates the secret-key length in this constructor.
        with self._oqs.KeyEncapsulation(
            self.algorithm, secret_key=secret_key
        ) as kem:
            expected_length = kem.details["length_ciphertext"]
            if len(ciphertext) != expected_length:
                raise ValueError(f"ciphertext must be exactly {expected_length} bytes")

            shared_secret = bytes(kem.decap_secret(ciphertext))
            if len(shared_secret) != kem.details["length_shared_secret"]:
                raise RuntimeError("liboqs returned an unexpected shared-secret length")

        return shared_secret
