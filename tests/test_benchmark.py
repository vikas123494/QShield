"""Smoke tests for the PQ-versus-classical benchmark runner."""
import pytest
from benchmarks.bench_pq_vs_classic import run_benchmarks


def test_benchmark_runs_all_four_algorithm_families():
    results = run_benchmarks(iterations=1)
    algorithms = {row["algorithm"] for row in results}
    assert algorithms == {"ML-KEM-768", "ECDH-P256", "ML-DSA-65", "ECDSA-P256"}
    assert all(row["iterations"] == 1 for row in results)
    assert all(row["keygen_ms"] >= 0 for row in results)


def test_benchmark_rejects_zero_iterations():
    with pytest.raises(ValueError, match="positive integer"):
        run_benchmarks(iterations=0)
