# Cost-Aware Feasible Attacks on Tabular Data (CaFA)

A university project reproducing and extending [CaFA](https://ieeexplore.ieee.org/document/10646875) — a cost-aware adversarial attack framework for tabular ML classifiers, presented at **IEEE S&P 2024**. This implementation complies with the [Adversarial Robustness Toolbox (ART)](https://github.com/Trusted-AI/adversarial-robustness-toolbox) framework.

> Completed as part of the **AI & Cybersecurity** course, University of Luxembourg.

---

## What is CaFA?

CaFA (*Cost-aware Feasible Attack*) is an adversarial example attack designed specifically for **tabular data**. Given a dataset and a trained ML classifier, CaFA crafts malicious inputs — based on real samples — that fool the model while remaining realistic and constraint-compliant.

This makes CaFA particularly relevant for high-stakes domains like fraud detection, intrusion detection, and credit scoring, where adversarial inputs must satisfy real-world data constraints to be meaningful.

CaFA has three logical components:

**1. Mine** — Denial Constraints are mined from the dataset using [FastADC](https://github.com/RangerShaw/FastADC) and a custom ranking scheme, capturing structural rules the data must satisfy.

**2. Perturb** — Two attack variants craft adversarial examples under cost and structural constraints:
- *TabPGD* — a tabular adaptation of [Projected Gradient Descent (PGD)](https://arxiv.org/abs/1706.06083)
- *TabCWL0* — a tabular adaptation of the [Carlini-Wagner L0](https://arxiv.org/abs/1608.04644) attack

**3. Project** — Crafted samples are projected onto the constrained space using the [Z3 SAT Theorem Prover](https://github.com/Z3Prover/z3), ensuring constraint compliance.

---

## Our Contributions

We modified the constraint weighting scheme in `mine_dc.py` to improve the balance between strictness, simplicity, and coverage. Specifically, we tuned the `col_to_weight` dictionary as follows:

| Metric | Weight | Rationale |
|--------|--------|-----------|
| `tuple_violation_rate_per_dc__below_1_pct` | 6.0 | Reward strict constraint adherence |
| `coverage_per_dc` | 5.0 | Prioritise broad rule coverage |
| `tuple_violation_rate_per_dc__below_5_pct` | 2.0 | Moderate reward for near-strict constraints |
| `succinctness_per_dc` | 2.0 | Encourage simpler constraint definitions |
| `pairs_violation_rate_per_dc` | -2.0 | Penalise higher violation rates |
| `tuple_violation_rate_per_dc` | -2.0 | Penalise higher violation rates |

### Results

Our tuning improved compliance rates across both attack scenarios:

| Scenario | Misclassification Rate | Compliance Rate (baseline) | Compliance Rate (ours) |
|----------|----------------------|---------------------------|------------------------|
| CAFA | 94.3% | 48.8% | **50.5%** |
| CAFA-projection | 70.6% | 75.8% | **77.4%** |

The improvements demonstrate a better trade-off between adversarial effectiveness and constraint adherence — generating attacks that are both more successful and more realistic.

---

## Datasets

Experiments were run on three standard tabular benchmarks:

| Dataset | Source | Task |
|---------|--------|------|
| Adult Income | [UCI](https://archive.ics.uci.edu/ml/datasets/adult) | Binary classification |
| Bank Marketing | [UCI](https://archive.ics.uci.edu/dataset/222/bank+marketing) | Binary classification |
| Phishing Websites | [UCI](https://archive.ics.uci.edu/ml/datasets/phishing+websites) | Binary classification |

Additional datasets can be integrated by following the structure in `config/data/`.

---

## Setup

**Requirements:** Python 3.8.5+, Java 11+ (for FastADC)

```bash
git clone https://github.com/mariummajid12/CAFA_AI_Cybersecurity_project.git
cd CAFA_AI_Cybersecurity_project
pip install -r requirements.txt
```

---

## Usage

```bash
python attack.py data=<dataset_name>
```

Where `<dataset_name>` is one of the datasets in the `data/` directory. Attack components can be configured via [Hydra](https://hydra.cc/) config files or overridden at the CLI:

| Component | Description |
|-----------|-------------|
| `data` | Dataset selection and preprocessing |
| `ml_model` | Model to train and attack |
| `attack` | CaFA attack parameters |
| `constraints` | Constraint mining, specification, and projection settings |

---

## References

```bibtex
@inproceedings{BenTov24CaFA,
  title={{CaFA}: {C}ost-aware, Feasible Attacks With Database Constraints Against Neural Tabular Classifiers},
  author={Ben-Tov, Matan and Deutch, Daniel and Frost, Nave and Sharif, Mahmood},
  booktitle={Proceedings of the 45th IEEE Symposium on Security and Privacy (S&P)},
  year={2024}
}
```

---

## License

Licensed under the [MIT License](LICENSE).
