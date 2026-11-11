"""Isolation Forest anomaly detection over QShield traffic feature windows."""
from __future__ import annotations
from dataclasses import dataclass
import csv
import math
import random
from pathlib import Path
from typing import Any, Iterable, Mapping

from sklearn.ensemble import IsolationForest
from sklearn.metrics import f1_score, precision_score, recall_score

FEATURE_COLUMNS = (
    "window_seconds", "packet_count", "connection_attempts", "syn_count",
    "syn_ack_count", "rst_count", "half_open_syns", "failed_handshakes",
    "distinct_dst_ports", "distinct_dst_ips", "bytes_total", "message_rate",
)


@dataclass(frozen=True, slots=True)
class AnomalyResult:
    is_anomaly: bool
    label: str
    anomaly_score: float


class IsolationForestAnomalyDetector:
    """Train on representative normal traffic and flag outlying windows.

    FeatureWindow objects from qshield.monitor.features are accepted directly.
    Scores are the negated Isolation Forest decision function, so larger values
    mean more anomalous. This unsupervised detector is not proof of an attack.
    """
    def __init__(self, *, contamination: float = 0.05, n_estimators: int = 200,
                 random_state: int = 42) -> None:
        if not isinstance(contamination, (int, float)) or not 0.0 < contamination <= 0.5:
            raise ValueError("contamination must be in the range (0, 0.5]")
        if not isinstance(n_estimators, int) or n_estimators < 10:
            raise ValueError("n_estimators must be an integer of at least 10")
        self._model = IsolationForest(
            contamination=float(contamination), n_estimators=n_estimators,
            random_state=random_state,
        )
        self._fitted = False

    @staticmethod
    def _to_row(sample: Mapping[str, Any] | Any) -> list[float]:
        if hasattr(sample, "to_dict") and callable(sample.to_dict):
            values = sample.to_dict()
        elif isinstance(sample, Mapping):
            values = sample
        else:
            raise TypeError("each sample must be a mapping or feature-window object")
        row: list[float] = []
        for column in FEATURE_COLUMNS:
            if column not in values:
                raise ValueError(f"missing anomaly feature: {column}")
            value = values[column]
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise TypeError(f"feature {column} must be numeric")
            numeric = float(value)
            if not math.isfinite(numeric):
                raise ValueError(f"feature {column} must be finite")
            row.append(numeric)
        return row

    def fit(self, baseline_samples: Iterable[Mapping[str, Any] | Any]) -> "IsolationForestAnomalyDetector":
        rows = [self._to_row(item) for item in baseline_samples]
        if len(rows) < 2:
            raise ValueError("at least two baseline samples are required")
        self._model.fit(rows)
        self._fitted = True
        return self

    def predict_one(self, sample: Mapping[str, Any] | Any) -> AnomalyResult:
        if not self._fitted:
            raise RuntimeError("detector must be fitted before prediction")
        row = [self._to_row(sample)]
        prediction = int(self._model.predict(row)[0])
        score = -float(self._model.decision_function(row)[0])
        anomaly = prediction == -1
        return AnomalyResult(anomaly, "ANOMALY" if anomaly else "NORMAL", score)

    def predict(self, samples: Iterable[Mapping[str, Any] | Any]) -> list[AnomalyResult]:
        return [self.predict_one(sample) for sample in samples]

    def evaluate(self, samples: Iterable[Mapping[str, Any] | Any],
                 expected_anomalies: Iterable[bool]) -> dict[str, float]:
        """Return precision, recall and F1 against labelled test windows."""
        results = self.predict(samples)
        expected = [bool(value) for value in expected_anomalies]
        if len(results) != len(expected) or not expected:
            raise ValueError("samples and expected_anomalies must have equal non-zero lengths")
        predicted = [result.is_anomaly for result in results]
        return {
            "precision": float(precision_score(expected, predicted, zero_division=0)),
            "recall": float(recall_score(expected, predicted, zero_division=0)),
            "f1": float(f1_score(expected, predicted, zero_division=0)),
        }


def evaluate_labelled_csv(
    path: str | Path,
    *,
    contamination: float = 0.05,
    random_state: int = 42,
) -> dict[str, float | int]:
    """Train on normal rows and evaluate on held-out normal plus labelled attacks.

    Rows labelled "unknown" are excluded. Attack labels are treated as positive
    examples; the CSV's operator-supplied labels remain the ground truth.
    At least three normal rows and one known-attack row are required.
    """
    normal_rows: list[dict[str, Any]] = []
    attack_rows: list[dict[str, Any]] = []
    with Path(path).open("r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = set(FEATURE_COLUMNS) | {"label"}
        if not reader.fieldnames or not required.issubset(reader.fieldnames):
            raise ValueError("labelled CSV is missing required feature or label columns")
        for raw in reader:
            label = (raw.get("label") or "").strip().lower()
            if label == "unknown" or not label:
                continue
            row: dict[str, Any] = {}
            for column in FEATURE_COLUMNS:
                try:
                    row[column] = float(raw[column])
                except (TypeError, ValueError) as exc:
                    raise ValueError(f"invalid numeric value in column {column}") from exc
            if label == "normal":
                normal_rows.append(row)
            else:
                attack_rows.append(row)

    if len(normal_rows) < 3 or not attack_rows:
        raise ValueError("CSV needs at least three normal rows and one known-attack row")

    rng = random.Random(random_state)
    rng.shuffle(normal_rows)
    train_count = min(len(normal_rows) - 1, max(2, int(len(normal_rows) * 0.7)))
    training = normal_rows[:train_count]
    held_out_normal = normal_rows[train_count:]
    testing = held_out_normal + attack_rows
    expected = [False] * len(held_out_normal) + [True] * len(attack_rows)

    detector = IsolationForestAnomalyDetector(
        contamination=contamination, random_state=random_state
    ).fit(training)
    metrics = detector.evaluate(testing, expected)
    return {
        "training_normal_windows": len(training),
        "testing_normal_windows": len(held_out_normal),
        "testing_attack_windows": len(attack_rows),
        **metrics,
    }


__all__ = [
    "AnomalyResult", "FEATURE_COLUMNS", "IsolationForestAnomalyDetector",
    "evaluate_labelled_csv",
]
