"""In-memory replay guard and safe replay demonstration for QShield messages."""
from collections import OrderedDict
import json
import math
import time
from threading import Lock


class ReplayCacheFullError(RuntimeError):
    """Raised when the replay cache is full and must fail closed."""


class ReplayGuard:
    """Reject message identifiers already accepted inside a retention window.

    Use authenticated identifiers or nonces. This cache is process-local; a
    multi-worker deployment needs a shared replay-state service.
    """
    def __init__(self, *, window_seconds: float = 300.0, max_entries: int = 10000) -> None:
        if not isinstance(window_seconds, (int, float)) or window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        if not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("max_entries must be a positive integer")
        self.window_seconds = float(window_seconds)
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = Lock()

    @staticmethod
    def _normalise(message_id: str | bytes) -> str:
        if isinstance(message_id, bytes):
            if not message_id:
                raise ValueError("message_id must not be empty")
            return "bytes:" + message_id.hex()
        if isinstance(message_id, str):
            if not message_id:
                raise ValueError("message_id must not be empty")
            return "str:" + message_id
        raise TypeError("message_id must be str or bytes")

    def accept(self, message_id: str | bytes, *, now: float | None = None) -> bool:
        """Return True for first acceptance and False for a duplicate."""
        key = self._normalise(message_id)
        current = time.monotonic() if now is None else float(now)
        if not math.isfinite(current):
            raise ValueError("now must be finite")
        cutoff = current - self.window_seconds
        with self._lock:
            expired = [item for item, seen_at in self._seen.items() if seen_at < cutoff]
            for item in expired:
                self._seen.pop(item, None)
            if key in self._seen:
                return False
            if len(self._seen) >= self.max_entries:
                raise ReplayCacheFullError("Replay cache is full; rejecting new message")
            self._seen[key] = current
            return True


def run_replay_demo() -> dict[str, bool]:
    """Show the first delivery accepted and the same identifier rejected."""
    guard = ReplayGuard(window_seconds=60)
    first = guard.accept("demo-message-001", now=100.0)
    replay = guard.accept("demo-message-001", now=101.0)
    return {"first_delivery_accepted": first, "replayed_delivery_rejected": not replay}


def main() -> None:
    print(json.dumps(run_replay_demo(), indent=2))


if __name__ == "__main__":
    main()
