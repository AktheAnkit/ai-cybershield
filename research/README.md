# Phishing detection — research artifacts

This is the material that feeds directly into your paper's Methodology
and Results sections.

Note: `pandas` is required here (for `train.py`) but not by the deployed
app itself — `app/scanners/phishing_detector.py` was rewritten to avoid
it, since a plain Python list serves the same purpose at inference time
and keeps the live app's dependency footprint smaller.

## Dataset

**Source:** ESDAUNG/PhishDataset (GitHub) — the balanced 20,000-URL
variant (10,000 phishing / 10,000 legitimate).

**Cite this in your paper.** It's the dataset distributed with:
> Segmentation-based Phishing URL Detection, WI-IAT '21: IEEE/WIC/ACM
> International Conference on Web Intelligence and Intelligent Agent
> Technology. https://doi.org/10.1145/3486622.3493983

- Phishing URLs: collected from PhishTank (May–June 2021)
- Legitimate URLs: sampled from IP2Location-listed domains, crawled with
  Apache Nutch

## What's in `results/`

- `model_comparison.json` — Accuracy / Precision / Recall / F1 / ROC-AUC
  for all three models. This is your Table in the Results section.
- `confusion_matrices.json` — per-model confusion matrices, in case you
  want a figure.
- `feature_importance.json` — top 8 features by Random Forest importance.
  Good material for the Discussion section (which URL properties actually
  matter).

## Reproducing

```bash
pip install pandas numpy scikit-learn xgboost openpyxl --break-system-packages
python3 train.py
```

## Methodology summary (paraphrase this into your own words for the paper)

21 lexical/structural features are extracted directly from each raw URL
string (length, hostname structure, subdomain count, special-character
counts, Shannon entropy, presence of suspicious keywords, HTTPS usage,
etc.) — no network calls, no WHOIS lookups. The same `extract_features()`
function is used both for training and for live prediction in the
deployed app, so there's no train/serve mismatch. Three classifiers were
trained on an 80/20 stratified split and compared: Logistic Regression as
a linear baseline, Random Forest and XGBoost as ensemble methods.

**Result:** XGBoost performed best (see `model_comparison.json` for exact
numbers), consistent with the general finding in phishing-detection
literature that ensemble tree methods outperform linear models on this
kind of tabular, non-linear feature set.

## Known limitation (worth a paragraph in your Discussion/Limitations section)

The raw dataset's legitimate (Labels==0) class is **100% sub-page URLs**
(e.g. `.../versa-lift-fork-truck/`) — **zero examples** of a bare root
domain (`https://example.com/`). A model trained on this alone
systematically misclassifies plain domain lookups as phishing, because it
never saw a legitimate example without a path. Verified empirically:
`mean(path_length)` is 0 for 100% of the legitimate class vs ~1% of the
phishing class.

**Fix 1 — dataset augmentation:** `train.py` now adds root-domain versions
of the dataset's own legitimate hostnames as extra training examples
(no new external domains introduced — same hostnames, just the bare-root
form). This nearly doubles the legitimate class, so class weighting
(`class_weight="balanced"` / `scale_pos_weight`) is used during training
to compensate.

**Fix 2 — remaining generalization gap:** Even after augmentation, the
model still misclassified globally top-ranked domains (google.com,
github.com) specifically — because the dataset's legitimate class was
sampled from long-tail small/medium business sites via IP2Location, with
**no globally top-ranked domains represented at all**. A 10-14 character
hostname belonging to a household-name brand is out-of-distribution for
what the model learned "legitimate" looks like. This is mitigated in the
live app with a small, disclosed trusted-domain allowlist
(`app/scanners/trusted_domains.py`) — a standard, precedented technique in
production phishing detection (most real systems combine ML/heuristic
scoring with a reputation signal rather than relying on either alone).

**Why this is worth including, not hiding:** identifying and
quantifying a training-data distribution gap — rather than only reporting
accuracy on a same-distribution test split — is exactly the kind of
empirical rigor reviewers look for. It also gives you a legitimate
"Future Work" line: collecting a legitimate-class sample stratified by
domain popularity (e.g. via a Tranco/Alexa-style ranked list) would close
this gap without needing an allowlist at all.

## Second bias finding (discovered via real-world testing after deployment)

A genuine Udemy affiliate link (`udemy.com/?im_ref=...&utm_medium=affiliate&utm_source=impact&...`)
was flagged as 100% phishing during manual testing. Root cause: the
legitimate class had `mean(num_query_params) == 0.0` — **not one single
legitimate URL in the raw dataset carried a query string** — while
`utm_*`/tracking-parameter links are an industry-standard, entirely
legitimate convention on real marketing/e-commerce/course-platform URLs.
The model had never seen a legitimate example with query parameters, so
it associated query-string length/entropy/parameter-count with phishing
regardless of the domain.

**Fix:** `train.py` now also synthesizes UTM-style tracking URLs on the
dataset's own legitimate root domains (`augment_with_tracking_params()`)
— same no-new-domains principle as the root-domain fix. After retraining,
the Udemy URL dropped from 100% ("Very likely phishing") to 43.7%
("Probably safe"). It does not drop further, and this is reported
honestly rather than tuned away: distinguishing a legitimate long
tracking URL from a phishing URL deliberately mimicking that pattern is a
genuinely hard problem from lexical features alone, since an attacker can
construct a URL with the same surface statistics. This residual
uncertainty is a defensible, citable limitation, not a bug — see
Discussion/Limitations.

**Pattern worth noting for the paper:** both bias findings follow the
same shape — a real-world feature of legitimate URLs (bare root domains;
marketing tracking parameters) was completely absent (0%) from this
specific dataset's legitimate-class sample, despite being common on the
live web. This suggests the dataset's legitimate URLs were collected from
a narrow crawl pattern (single fixed sub-page per domain, no marketing
links), which is a more general characterization of the dataset's
limitation than either finding alone.
