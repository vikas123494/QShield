"""Tests for offline tampering and replay demonstrations."""
import pytest
from attacks.replay_lab import ReplayCacheFullError, ReplayGuard, run_replay_demo
from attacks.tamper_lab import run_tamper_demo


def test_tamper_lab_detects_modified_ciphertext_and_aad():
    result = run_tamper_demo()
    assert result.original_round_trip_succeeded is True
    assert result.ciphertext_tampering_rejected is True
    assert result.associated_data_tampering_rejected is True


def test_replay_guard_accepts_once_and_rejects_duplicate():
    guard = ReplayGuard(window_seconds=30)
    assert guard.accept("packet-1", now=100) is True
    assert guard.accept("packet-1", now=101) is False


def test_replay_guard_expires_old_entries_and_fails_closed_when_full():
    guard = ReplayGuard(window_seconds=5, max_entries=1)
    assert guard.accept(b"old", now=10) is True
    assert guard.accept(b"new", now=16) is True
    with pytest.raises(ReplayCacheFullError):
        guard.accept(b"third", now=17)


def test_replay_demo_output():
    assert run_replay_demo() == {
        "first_delivery_accepted": True, "replayed_delivery_rejected": True
    }
