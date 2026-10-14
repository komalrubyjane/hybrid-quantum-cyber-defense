# models/

Model files are **local artifacts and are not in Git**. Only this README and the small derived vocabulary are tracked.

| Path | Tracked | Contents |
|---|---|---|
| `attack_prediction/vocabulary/technique-vocabulary-attack-19.2.json` | yes | Technique vocabulary built from ATT&CK 19.2 (`scripts/build_vocabulary.py`) |
| `generated/attack_prediction/<run-id>/` | no (git-ignored) | Milestone 3 Markov models (`B1.json`, `M1.json`, `M2.json`) and Milestone 4 LSTM fold checkpoints (`lstm/fold-NN.pt` + `.json` metadata) |
| `generated/detection/<run-id>/` | no (git-ignored) | Milestone 5 CIC-IDS2017 detectors (`*.joblib`) with metadata and preprocessing records (`*.json`) |
| `generated/quantum/<run-id>/` | no (git-ignored) | Milestone 6 quantum-kernel and comparison adjudicators with metadata |

Every model file has a JSON metadata record next to it: model type, training dataset and version, ATT&CK version, features, hyperparameters, training date, seed and the run it belongs to. Evaluation results are stored in `reports/runs/<run-id>/`, which is also git-ignored.

## Creating the models on a fresh clone
The models are produced by the evaluation scripts. Each writes a new `<run-id>` folder; nothing is downloaded pre-trained:

1. **Knowledge data:** `scripts/fetch_attack.py`, `build_attack_kb.py`, `fetch_attack_flow.py`, `build_attack_flow_corpus.py` and `build_vocabulary.py` (see the main README).
2. **Milestone 3:** `evaluation/run_markov_baseline.py`.
3. **Milestone 4:** `evaluation/run_sequence_models.py`.
4. **Milestone 5:** a manual CIC-IDS2017 download, then `scripts/register_cicids2017.py` and `evaluation/run_classical_detection.py`.
5. **Milestone 6:** `evaluation/run_quantum_adjudicator.py`, which reads the Milestone 5 run.

The API and the Milestone 7 pipeline load the Milestone 3/4 models by the run IDs pinned in `configs/integration.yaml`, and Milestone 6 reads the Milestone 5 run ID set in `configs/quantum_adjudicator.yaml`. A regenerated run gets a new, timestamped ID, so update those pinned IDs to use it (see `docs/REPRODUCIBILITY.md`). Without the models, the API's `/api/v1` intelligence endpoints return 503, while `/health`, `/api/v1/runs` and `/api/v1/assessments` still work.
