"""Central access and validation for QShield's liboqs backend.

This module keeps algorithm names and backend checks in one place so that
other QShield modules do not each implement their own OQS availability logic.
"""

from importlib import import_module, metadata
from types import ModuleType

KEM_ALGORITHM = "ML-KEM-768"
SIGNATURE_ALGORITHM = "ML-DSA-65"


class BackendUnavailableError(RuntimeError):
    """Raised when the required post-quantum backend is unavailable."""


def get_oqs() -> ModuleType:
    """Import liboqs-python and verify QShield's required algorithms.

    Returns:
        The imported oqs module.

    Raises:
        BackendUnavailableError: If the binding cannot load or either
            configured algorithm is not enabled in the native liboqs build.
    """
    try:
        oqs = import_module("oqs")
    except (ImportError, OSError, RuntimeError) as exc:
        raise BackendUnavailableError(
            "Unable to load liboqs-python. Install the package and ensure "
            "the native liboqs shared library is available."
        ) from exc

    try:
        enabled_kems = oqs.get_enabled_kem_mechanisms()
        enabled_signatures = oqs.get_enabled_sig_mechanisms()
    except (AttributeError, OSError, RuntimeError) as exc:
        raise BackendUnavailableError(
            "The loaded OQS binding does not expose the expected algorithm "
            "discovery API."
        ) from exc

    missing = []
    if KEM_ALGORITHM not in enabled_kems:
        missing.append(KEM_ALGORITHM)
    if SIGNATURE_ALGORITHM not in enabled_signatures:
        missing.append(SIGNATURE_ALGORITHM)

    if missing:
        raise BackendUnavailableError(
            "Required algorithms are not enabled in liboqs: "
            + ", ".join(missing)
        )

    return oqs


def backend_info() -> dict[str, str]:
    """Return the provider version and QShield's required algorithm names."""
    get_oqs()  # Fail early if the native backend or algorithms are unavailable.

    try:
        version = metadata.version("liboqs-python")
    except metadata.PackageNotFoundError as exc:
        raise BackendUnavailableError(
            "The liboqs-python package metadata is not installed."
        ) from exc

    return {
        "provider": "liboqs-python",
        "version": version,
        "kem": KEM_ALGORITHM,
        "signature": SIGNATURE_ALGORITHM,
        "status": "available",
    }
