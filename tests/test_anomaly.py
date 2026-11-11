"""Tests for the Isolation Forest detector."""
import pytest
from qshield.monitor.anomaly import (
    FEATURE_COLUMNS,
    IsolationForestAnomalyDetector,
    evaluate_labelled_csv,
)


def make_window(value=10):
    row = {column: float(value) for column in FEATURE_COLUMNS}
    row["window_seconds"] = 10.0
    row["message_rate"] = float(value) / 10
    return row


def test_isolation_forest_fits_and_predicts():
    baseline = [make_window(10 + index % 3) for index in range(30)]
    detector = IsolationForestAnomalyDetector(random_state=7).fit(baseline)
    result = detector.predict_one(make_window(11))
    assert result.label in {"NORMAL", "ANOMALY"}
    assert isinstance(result.anomaly_score, float)


def test_anomaly_detector_accepts_feature_window_like_mapping():
    detector = IsolationForestAnomalyDetector().fit(
        [make_window(10), make_window(12), make_window(11)]
    )
    assert len(detector.predict([make_window(10), make_window(12)])) == 2


def test_anomaly_detector_requires_fit_and_valid_features():
    detector = IsolationForestAnomalyDetector()
    with pytest.raises(RuntimeError, match="fitted"):
        detector.predict_one(make_window())
    with pytest.raises(ValueError, match="missing anomaly feature"):
        detector.fit([{"packet_count": 1}, {"packet_count": 2}])


def test_anomaly_detector_evaluate_returns_metrics():
    baseline = [make_window(10 + index % 2) for index in range(30)]
    detector = IsolationForestAnomalyDetector(random_state=1).fit(baseline)
    report = detector.evaluate(
        [make_window(10), make_window(12), make_window(500)], [False, False, True]
    )
    assert set(report) == {"precision", "recall", "f1"}



def test_evaluate_labelled_csv_uses_holdout_and_reports_metrics(tmp_path):
    import csv

    path = tmp_path / "labelled_windows.csv"
    fields = list(FEATURE_COLUMNS) + ["label"]
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index in range(10):
            writer.writerow({**make_window(10 + index % 2), "label": "normal"})
        for index in range(3):
            writer.writerow({**make_window(400 + index * 10), "label": "port_scan"})

    report = evaluate_labelled_csv(path, contamination=0.1)
    assert report["training_normal_windows"] >= 2
    assert report["testing_normal_windows"] >= 1
    assert report["testing_attack_windows"] == 3
    assert 0.0 <= report["precision"] <= 1.0
    assert 0.0 <= report["recall"] <= 1.0
    assert 0.0 <= report["f1"] <= 1.0
