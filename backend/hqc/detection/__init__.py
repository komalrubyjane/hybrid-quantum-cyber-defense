"""Classical network intrusion detection on CIC-IDS2017 (Milestone 5).

dataset (CSV adapter) -> preprocessing (day split, feature policy, train-only
preprocessor, duplicate audit) -> models (LogReg, RandomForest) -> evaluation -> tracking.
Detections are DetectionResult objects; CIC-IDS2017 labels are NOT ATT&CK techniques.
"""
