"""ML-DSA-65 signing and signature-verification adapter."""

from dataclasses import dataclass, field

from qshield.crypto.backend import SIGNATURE_ALGORITHM, get_oqs


@dataclass(frozen=True, slots=True)
class SignatureKeyPair:
    """ML-DSA key material; repr intentionally hides the private key."""

    public_key: bytes
    secret_key: bytes = field(repr=False)


class MLDSA65:
    """QShield adapter for the stateless ML-DSA-65 signature algorithm.

    Keep the secret key private to the signer. Distribute the public key
    through an authenticated channel so recipients can verify signatures.
    """

    algorithm = SIGNATURE_ALGORITHM

    def __init__(self) -> None:
        self._oqs = get_oqs()

    @staticmethod
    def _require_bytes(value: bytes, name: str, *, allow_empty: bool = False) -> None:
        if not isinstance(value, bytes):
            raise TypeError(f"{name} must be bytes")
        if not allow_empty and not value:
            raise ValueError(f"{name} must not be empty")

    def generate_keypair(self) -> SignatureKeyPair:
        """Generate a fresh ML-DSA-65 key pair using liboqs' secure RNG."""
        with self._oqs.Signature(self.algorithm) as signer:
            public_key = bytes(signer.generate_keypair())
            secret_key = bytes(signer.export_secret_key())
            details = signer.details

            if len(public_key) != details["length_public_key"]:
                raise RuntimeError("liboqs returned an unexpected public-key length")
            if len(secret_key) != details["length_secret_key"]:
                raise RuntimeError("liboqs returned an unexpected secret-key length")

        return SignatureKeyPair(public_key=public_key, secret_key=secret_key)

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign message bytes with the provided ML-DSA-65 private key."""
        self._require_bytes(secret_key, "secret_key")
        self._require_bytes(message, "message", allow_empty=True)

        # The library copies and validates the supplied private-key length.
        with self._oqs.Signature(self.algorithm, secret_key=secret_key) as signer:
            signature = bytes(signer.sign(message))
            maximum_length = signer.details["length_signature"]
            if not signature or len(signature) > maximum_length:
                raise RuntimeError("liboqs returned an invalid signature length")

        return signature

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature using only the signer's public key.

        Returns False when the signature is cryptographically invalid. Invalid
        input types, empty public keys, and impossible encoded lengths raise errors.
        """
        self._require_bytes(public_key, "public_key")
        self._require_bytes(message, "message", allow_empty=True)
        self._require_bytes(signature, "signature")

        # Use a separate verifier with no private key loaded.
        with self._oqs.Signature(self.algorithm) as verifier:
            details = verifier.details
            public_key_length = details["length_public_key"]
            signature_length = details["length_signature"]

            if len(public_key) != public_key_length:
                raise ValueError(
                    f"public_key must be exactly {public_key_length} bytes"
                )
            if len(signature) > signature_length:
                raise ValueError(
                    f"signature must be at most {signature_length} bytes"
                )

            return bool(verifier.verify(message, signature, public_key))
