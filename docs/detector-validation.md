# Detector validation and remaining evidence gap

## Verified mechanics

The active sensor now emits completed bidirectional flows rather than treating each packet as a connection. Payload bytes are counted separately for the original and reverse directions. TCP close/reset and idle expiration finalize flows. Service names match the saved categorical vocabulary. Flow memory is bounded. Sensor and browser replay share the same feature encoder, which rejects unsupported categorical values instead of silently encoding them as all zeroes.

Controlled synthetic TCP, UDP and ICMP packets test direction, payload bytes, one result per flow, idle expiry, service/error statistics, bounded state and actual saved-model inference. These tests send no attack traffic. They verify the mechanics; they do not establish attack detection accuracy.

The network-only sensor cannot observe NSL-KDD host/content variables such as successful login, root-shell activity or failed login counts. Those fields are explicitly listed as unobserved in model metadata; zero placeholders are not observations. Fragment validity is also unobserved. Live classification therefore requires explicit acknowledgement:

```sh
.venv/bin/python scripts/run_monitor.py --interface en0 --allow-experimental-features
```

Do this only on an authorized interface. Automatic sensor-driven file encryption is disabled; file changes use the authenticated customer-scoped API. The dashboard visibly marks live capture as experimental.

## Reproducible candidate experiment

```sh
.venv/bin/python scripts/train_candidate.py --output .runtime/experiments/new-run
```

The output directory must be new and separate from `models2`. Training uses only the training CSV, removes duplicate feature vectors before a stratified 80/20 split, fits vocabulary/scaling on the fitting partition, and compares Random Forest, unweighted XGBoost and square-root class-weighted XGBoost. XGBoost early stopping uses validation records. Selection uses validation macro F1 with a predeclared Normal false-positive rate ceiling of 5%. Only the selected candidate is evaluated on the held-out test CSV. No model is automatically promoted.

The first comparison selected weighted XGBoost (validation macro F1 0.9616). On the held-out benchmark:

| Metric | Preserved active model | Selected candidate |
| --- | ---: | ---: |
| Macro F1 | 0.5693 | 0.5585 |
| R2L recall | 12.89% | 9.98% |
| U2R recall | 13.43% | 11.94% |
| Normal false-positive rate | 2.89% | 2.88% |

The candidate failed the macro F1 and rare-class improvement gates and was **not promoted**. All active model artifacts remain unchanged. Full data/artifact hashes, package versions, validation results, confusion matrix and release gates are in [the experiment report](experiments/customer-readiness-1.json). Candidate binaries remain private local experiment outputs, not deployment assets.

The already-inspected NSL-KDD test set is not a new real-world holdout. Further attempts should not tune against these test results. The next evidence requirement is labelled authorized captures with corresponding host logs, split by capture/session/time so related records cannot cross the training/evaluation boundary. Define attack/normal labels independently of this model's predictions. Evaluate per-class recall, Normal false alerts and unknown feature rates before considering live use. More class weighting alone did not close the gap.

Method references: [scikit-learn data leakage guidance](https://scikit-learn.org/stable/common_pitfalls.html), [XGBoost fit and validation API](https://xgboost.readthedocs.io/en/stable/python/python_api.html).


## Evaluate an authorized capture without starting live capture

```sh
.venv/bin/python scripts/evaluate_capture.py --pcap /path/to/authorized.pcap --output .runtime/capture-review.json
```

This reads a capture offline and transmits no packets. The output contains private addresses and raw features, so keep it out of Git and share it deliberately. It lists stable flow IDs. Supply independently established labels in a CSV with `flow_id,label` columns, using Normal/DoS/Probe/R2L/U2R, then repeat with `--labels /path/to/labels.csv` and a new output filename. Without labels, no accuracy is reported. Partial labels produce metrics only for labelled flows and an explicit coverage fraction. Unknown/duplicate labels and out-of-order captures are rejected. Captures are bounded to 100,000 packets per run.
