# Final result tables (generated from stored runs; do not edit by hand)

## 1. Attack-chain prediction (macro mean [95% bootstrap CI], 36 groups)

| Model | Top-1 | Top-5 | MRR | Log loss | Run |
|---|---|---|---|---|---|
| B0 | 0.0046 [0.000, 0.014] | 0.0102 [0.001, 0.024] | 0.0166 [0.010, 0.027] | 6.547 [6.547, 6.547] | `20261006T173740Z-markov-baselines-document` |
| B1 | 0.0736 [0.043, 0.107] | 0.1325 [0.089, 0.180] | 0.1205 [0.088, 0.156] | 5.724 [5.480, 5.963] | `20261006T173740Z-markov-baselines-document` |
| M1 | 0.0498 [0.029, 0.073] | 0.1380 [0.097, 0.182] | 0.1091 [0.083, 0.137] | 5.853 [5.589, 6.112] | `20261006T173740Z-markov-baselines-document` |
| M2 | 0.0521 [0.030, 0.076] | 0.1368 [0.095, 0.181] | 0.1110 [0.084, 0.139] | 6.235 [5.852, 6.622] | `20261006T173740Z-markov-baselines-document` |
| LSTM | 0.0711 [0.041, 0.104] | 0.1621 [0.111, 0.219] | 0.1218 [0.090, 0.156] | 5.896 [5.667, 6.117] | `20261006T181005Z-lstm-hybrid-beam-document` |
| HYBRID | 0.0573 [0.033, 0.085] | 0.1560 [0.106, 0.209] | 0.1149 [0.087, 0.145] | 5.736 [5.507, 5.956] | `20261006T181005Z-lstm-hybrid-beam-document` |

Paired differences (A - B; significant = 95% CI excludes 0):

| A | B | Metric | Difference [95% CI] | Significant |
|---|---|---|---|---|
| LSTM | B1 | top1 | -0.0025 [-0.0063, 0.0000] | no |
| LSTM | B1 | top5 | 0.0296 [0.0059, 0.0554] | yes |
| LSTM | B1 | mrr | 0.0013 [-0.0053, 0.0077] | no |
| LSTM | B1 | log_loss | 0.1724 [0.0475, 0.2939] | yes |
| LSTM | MARKOV | top1 | 0.0214 [0.0031, 0.0420] | yes |
| LSTM | MARKOV | top5 | 0.0240 [-0.0150, 0.0680] | no |
| LSTM | MARKOV | mrr | 0.0126 [-0.0067, 0.0339] | no |
| LSTM | MARKOV | log_loss | 0.0437 [-0.0914, 0.1694] | no |
| HYBRID | B1 | top1 | -0.0163 [-0.0334, -0.0026] | yes |
| HYBRID | B1 | top5 | 0.0235 [-0.0038, 0.0535] | no |
| HYBRID | B1 | mrr | -0.0056 [-0.0204, 0.0072] | no |
| HYBRID | B1 | log_loss | 0.0116 [-0.0751, 0.0956] | no |
| HYBRID | LSTM | top1 | -0.0138 [-0.0308, -0.0008] | yes |
| HYBRID | LSTM | top5 | -0.0061 [-0.0369, 0.0221] | no |
| HYBRID | LSTM | mrr | -0.0069 [-0.0204, 0.0041] | no |
| HYBRID | LSTM | log_loss | -0.1607 [-0.2133, -0.1096] | yes |
| HYBRID | MARKOV | top1 | 0.0076 [-0.0043, 0.0197] | no |
| HYBRID | MARKOV | top5 | 0.0180 [-0.0046, 0.0442] | no |
| HYBRID | MARKOV | mrr | 0.0057 [-0.0066, 0.0174] | no |
| HYBRID | MARKOV | log_loss | -0.1171 [-0.2072, -0.0347] | yes |
| MARKOV | B1 | top1 | -0.0238 [-0.0448, -0.0051] | yes |
| MARKOV | B1 | top5 | 0.0056 [-0.0284, 0.0403] | no |
| MARKOV | B1 | mrr | -0.0113 [-0.0328, 0.0079] | no |
| MARKOV | B1 | log_loss | 0.1287 [0.0566, 0.1932] | yes |

Multi-step (beam width 10): exact path hit@10 (macro mean [95% CI]):

| Model | H | path_hit@1 | path_hit@10 | step1_acc |
|---|---|---|---|---|
| B1 | 2 | 0.0075 [0.001, 0.017] | 0.0440 [0.016, 0.079] | 0.0885 [0.052, 0.130] |
| MARKOV | 2 | 0.0000 [0.000, 0.000] | 0.0132 [0.004, 0.025] | 0.0528 [0.031, 0.078] |
| LSTM | 2 | 0.0075 [0.001, 0.017] | 0.0374 [0.012, 0.071] | 0.0885 [0.052, 0.130] |
| HYBRID | 2 | 0.0049 [0.000, 0.013] | 0.0289 [0.009, 0.058] | 0.0727 [0.042, 0.108] |
| B1 | 3 | 0.0000 [0.000, 0.000] | 0.0033 [0.000, 0.009] | 0.1072 [0.060, 0.162] |
| MARKOV | 3 | 0.0000 [0.000, 0.000] | 0.0000 [0.000, 0.000] | 0.0745 [0.043, 0.111] |
| LSTM | 3 | 0.0000 [0.000, 0.000] | 0.0015 [0.000, 0.004] | 0.1072 [0.060, 0.162] |
| HYBRID | 3 | 0.0000 [0.000, 0.000] | 0.0000 [0.000, 0.000] | 0.0994 [0.054, 0.154] |

## 2. CIC-IDS2017 detection (Thursday-Friday holdout; single run, no CIs)

| Model | Features | Subset | Precision | Recall | F1 | ROC-AUC | PR-AUC | Benign FPR |
|---|---|---|---|---|---|---|---|---|
| logreg | full | all_test_rows | 0.8206 | 0.4582 | 0.5880 | 0.7184 | 0.6426 | 0.0335 |
| logreg | full | test_rows_not_in_train | 0.8729 | 0.4582 | 0.6009 | 0.7249 | 0.6614 | 0.0242 |
| random_forest | full | all_test_rows | 0.9955 | 0.2834 | 0.4412 | 0.8097 | 0.6900 | 0.0004 |
| random_forest | full | test_rows_not_in_train | 0.9979 | 0.2834 | 0.4414 | 0.8075 | 0.7011 | 0.0002 |
| logreg | no_destination_port | all_test_rows | 0.5926 | 0.7073 | 0.6449 | 0.9008 | 0.7144 | 0.1625 |
| logreg | no_destination_port | test_rows_not_in_train | 0.6538 | 0.7099 | 0.6807 | 0.9136 | 0.7602 | 0.1462 |
| random_forest | no_destination_port | all_test_rows | 0.9892 | 0.2517 | 0.4012 | 0.8893 | 0.7116 | 0.0009 |
| random_forest | no_destination_port | test_rows_not_in_train | 0.9927 | 0.2526 | 0.4027 | 0.8907 | 0.7413 | 0.0007 |

## 3. Quantum matched budget (E2; balanced accuracy mean ± 95% t-CI over 5 seeds)

d = 4:

| N | random_forest | logreg | linear_svm | rbf_svm | zz_qsvm | z_qsvm |
|---|---|---|---|---|---|---|
| 100 | 0.721 ± 0.138 | 0.652 ± 0.149 | 0.674 ± 0.138 | 0.804 ± 0.050 | 0.732 ± 0.034 | 0.790 ± 0.086 |
| 250 | 0.692 ± 0.040 | 0.584 ± 0.085 | 0.572 ± 0.103 | 0.785 ± 0.075 | 0.774 ± 0.077 | 0.732 ± 0.077 |
| 500 | 0.783 ± 0.021 | 0.612 ± 0.041 | 0.640 ± 0.028 | 0.845 ± 0.023 | 0.834 ± 0.039 | 0.828 ± 0.041 |
| 1000 | 0.711 ± 0.095 | 0.571 ± 0.050 | 0.603 ± 0.054 | 0.848 ± 0.026 | 0.830 ± 0.021 | 0.836 ± 0.028 |
| 2000 | 0.727 ± 0.072 | 0.579 ± 0.053 | 0.652 ± 0.011 | 0.827 ± 0.025 | 0.779 ± 0.010 | 0.823 ± 0.022 |

d = 6:

| N | random_forest | logreg | linear_svm | rbf_svm | zz_qsvm | z_qsvm |
|---|---|---|---|---|---|---|
| 100 | 0.706 ± 0.107 | 0.675 ± 0.146 | 0.700 ± 0.108 | 0.814 ± 0.030 | 0.709 ± 0.084 | 0.782 ± 0.062 |
| 250 | 0.722 ± 0.084 | 0.610 ± 0.088 | 0.612 ± 0.059 | 0.713 ± 0.095 | 0.715 ± 0.076 | 0.711 ± 0.047 |
| 500 | 0.752 ± 0.023 | 0.606 ± 0.056 | 0.687 ± 0.035 | 0.758 ± 0.051 | 0.776 ± 0.072 | 0.758 ± 0.038 |
| 1000 | 0.702 ± 0.066 | 0.611 ± 0.054 | 0.669 ± 0.032 | 0.834 ± 0.020 | 0.820 ± 0.039 | 0.818 ± 0.040 |
| 2000 | 0.709 ± 0.059 | 0.617 ± 0.042 | 0.661 ± 0.019 | 0.722 ± 0.037 | 0.747 ± 0.027 | 0.727 ± 0.072 |

d = 8:

| N | random_forest | logreg | linear_svm | rbf_svm | zz_qsvm | z_qsvm |
|---|---|---|---|---|---|---|
| 100 | 0.718 ± 0.116 | 0.711 ± 0.036 | 0.709 ± 0.038 | 0.753 ± 0.085 | 0.685 ± 0.133 | 0.785 ± 0.104 |
| 250 | 0.747 ± 0.076 | 0.712 ± 0.075 | 0.733 ± 0.060 | 0.747 ± 0.073 | 0.719 ± 0.093 | 0.750 ± 0.053 |
| 500 | 0.719 ± 0.069 | 0.732 ± 0.028 | 0.709 ± 0.020 | 0.781 ± 0.051 | 0.752 ± 0.040 | 0.745 ± 0.089 |
| 1000 | 0.694 ± 0.043 | 0.673 ± 0.049 | 0.650 ± 0.049 | 0.776 ± 0.060 | 0.748 ± 0.076 | 0.751 ± 0.061 |
| 2000 | 0.710 ± 0.075 | 0.657 ± 0.073 | 0.652 ± 0.034 | 0.718 ± 0.034 | 0.684 ± 0.025 | 0.716 ± 0.053 |

## 4. Quantum second-opinion fusion (E3, whole test set)

primary band [4.2e-05, 0.999958] (train OOF coverage 0.0986, test coverage 0.3026):

| Arm | Precision | Recall | F1 | ROC-AUC | PR-AUC | Benign FPR |
|---|---|---|---|---|---|---|
| RF alone | 0.9955 | 0.2834 | 0.4412 | 0.8097 | 0.6900 | 0.0004 |
| RF + rbf_svm | 0.7232 | 0.6109 | 0.6623 | 0.8163 | 0.7060 | 0.0781 |
| RF + zz_qsvm | 0.6964 | 0.5644 | 0.6235 | 0.8096 | 0.6664 | 0.0822 |
| RF + z_qsvm | 0.7113 | 0.6554 | 0.6822 | 0.8168 | 0.7118 | 0.0889 |

secondary band [0.01, 0.99] (train OOF coverage 0.0488, test coverage 0.1879):

| Arm | Precision | Recall | F1 | ROC-AUC | PR-AUC | Benign FPR |
|---|---|---|---|---|---|---|
| RF alone | 0.9955 | 0.2834 | 0.4412 | 0.8097 | 0.6900 | 0.0004 |
| RF + rbf_svm | 0.8524 | 0.5006 | 0.6308 | 0.8094 | 0.6581 | 0.0290 |
| RF + zz_qsvm | 0.7279 | 0.2078 | 0.3234 | 0.8055 | 0.6301 | 0.0260 |
| RF + z_qsvm | 0.9164 | 0.3476 | 0.5040 | 0.8090 | 0.6850 | 0.0106 |

## 5. Quantum noise (E4; single seed, N_train = N_test = 200)

| Setting | Shots | p1 | p2 | Readout | Rel. kernel error (test) | Balanced acc | ROC-AUC |
|---|---|---|---|---|---|---|---|
| shots-256 | 256 | 0.0 | 0.0 | 0.0 | 0.0467 | 0.6733 | 0.7176 |
| shots-1024 | 1024 | 0.0 | 0.0 | 0.0 | 0.0233 | 0.7200 | 0.7008 |
| shots-4096 | 4096 | 0.0 | 0.0 | 0.0 | 0.0116 | 0.7433 | 0.7139 |
| low-noise-1024 | 1024 | 0.0001 | 0.001 | 0.01 | 0.0661 | 0.7133 | 0.6705 |
| mid-noise-1024 | 1024 | 0.001 | 0.01 | 0.01 | 0.2440 | 0.7233 | 0.6893 |
| mid-noise-ro3-1024 | 1024 | 0.001 | 0.01 | 0.03 | 0.2993 | 0.7100 | 0.6857 |
| high-noise-1024 | 1024 | 0.01 | 0.05 | 0.03 | 0.7392 | 0.6100 | 0.6599 |
| high-noise-4096 | 4096 | 0.01 | 0.05 | 0.03 | 0.7387 | 0.6067 | 0.6721 |

Exact statevector: balanced accuracy 0.7567, ROC-AUC 0.7247.

## 6. M7 integration demonstration (SYNTHETIC)

| Chain | Status | Observed | Top next (probability) | Risk | Recommendations |
|---|---|---|---|---|---|
| chain-syn-ms-e01 | CORRELATED | T1190 → T1059.004 → T1098.004 → T1003.008 → T1021.004 → T1041 | T1105 (0.0904) | 76.45 CRITICAL | escalate_severity, restrict_communication, collect_additional_evidence, increase_monitoring |
| chain-syn-ms-e07 | STANDALONE | T1110.001 | T1105 (0.0238) | 44.38 MEDIUM | collect_additional_evidence, increase_monitoring |

Integration checks: 13/13 passed.

