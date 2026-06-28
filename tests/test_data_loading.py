from pathlib import Path

from log_anomaly_threat_detection.data_loading import load_dataset_config


def test_dataset_config_contains_primary_datasets():
    datasets = load_dataset_config(Path("config/datasets.yaml"))
    assert "request_logs_30d" in datasets
    assert "app_logs_7d" in datasets
