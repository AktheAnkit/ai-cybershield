"""Train and compare phishing URL classifiers.

Usage: python3 train.py

Outputs:
- results/model_comparison.json  -> metrics table for the paper
- results/confusion_matrices.json
- models/best_model.pkl          -> the winning model, for the live app
"""
import json
import os
import pickle
import random
import sys
import time
from urllib.parse import urlparse

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "cybershield"))
from app.scanners.phishing_features import extract_features, FEATURE_NAMES  # noqa: E402

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False

DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "phish_data.xlsx")
RESULTS_DIR = os.path.join(os.path.dirname(__file__), "results")
MODELS_DIR = os.path.join(os.path.dirname(__file__), "models")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(MODELS_DIR, exist_ok=True)


def augment_with_tracking_params(df: pd.DataFrame, seed: int = 42) -> pd.DataFrame:
    """Second dataset bias fix (found via a real false positive during
    testing — a genuine Udemy affiliate link flagged as 100% phishing).

    Every legitimate (Labels==0) URL in the raw dataset has mean
    num_query_params == 0.0 — literally none of them carry a query
    string at all — while real-world marketing, affiliate, and analytics
    links on entirely legitimate sites commonly do (UTM parameters are an
    open, industry-wide convention, not a phishing signal). A classifier
    trained on this never sees a legitimate example with query
    parameters, so it associates query-string complexity/length/entropy
    with phishing regardless of the domain.

    Fix: synthesize UTM-style tracking URLs on top of the dataset's own
    legitimate root domains (same domains as augment_with_root_domains,
    no new external domains introduced).
    """
    rng = random.Random(seed)
    sources = ["google", "newsletter", "affiliate", "facebook", "instagram", "email", "impact", "partner", "bing"]
    mediums = ["cpc", "email", "social", "affiliate", "referral", "organic", "display"]
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    legit = df[df["Labels"] == 0].copy()

    def parts(u):
        u = str(u)
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        p = urlparse(u)
        return p.scheme, p.hostname

    parsed = legit["URLs"].apply(parts)
    hosts_df = pd.DataFrame(parsed.tolist(), columns=["scheme", "hostname"]).dropna()
    hosts_df = hosts_df.drop_duplicates(subset="hostname")

    synthetic = []
    for _, row in hosts_df.iterrows():
        campaign_id = "".join(rng.choices(chars, k=rng.choice([12, 20, 28])))
        source, medium = rng.choice(sources), rng.choice(mediums)
        synthetic.append(
            f"{row['scheme']}://{row['hostname']}/?utm_source={source}&utm_medium={medium}&utm_campaign={campaign_id}"
        )

    augmented = pd.DataFrame({"URLs": synthetic, "Labels": 0})
    print(f"Dataset bias fix #2: adding {len(augmented)} legitimate examples with synthetic "
          f"UTM-style tracking parameters (source data had 0% query-parameter representation "
          f"in the legitimate class).")
    return pd.concat([df, augmented], ignore_index=True).drop_duplicates(subset="URLs")


def augment_with_root_domains(df: pd.DataFrame) -> pd.DataFrame:
    """Dataset bias fix.

    Every single legitimate (Labels==0) URL in the raw ESDAUNG dataset is
    a sub-page (e.g. '.../versa-lift-fork-truck/') — 0% of them are a bare
    root domain like 'https://example.com/'. A classifier trained on this
    never sees a legitimate example without a path, so it systematically
    flags plain domain lookups (e.g. https://www.google.com) as phishing —
    confirmed empirically: mean path_length is 0 for 100% of the legit
    class vs ~1% of the phishing class.

    Fix: add root-domain versions of the *same* legitimate hostnames
    already in the dataset as extra Labels==0 rows. This introduces no new
    domains/external bias — it just fills a representation gap that
    existed in the source data.
    """
    legit = df[df["Labels"] == 0].copy()

    def parts(u):
        u = str(u)
        if not u.startswith(("http://", "https://")):
            u = "http://" + u
        p = urlparse(u)
        return p.scheme, p.hostname

    parsed = legit["URLs"].apply(parts)
    hosts_df = pd.DataFrame(parsed.tolist(), columns=["scheme", "hostname"]).dropna()
    hosts_df = hosts_df.drop_duplicates(subset="hostname")

    root_urls = hosts_df.apply(lambda r: f"{r['scheme']}://{r['hostname']}/", axis=1)
    augmented = pd.DataFrame({"URLs": root_urls, "Labels": 0})

    print(f"Dataset bias fix: adding {len(augmented)} root-domain legitimate examples "
          f"(source data had 0% bare-domain representation in the legitimate class).")
    return pd.concat([df, augmented], ignore_index=True).drop_duplicates(subset="URLs")


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for url in df["URLs"]:
        try:
            rows.append(extract_features(str(url)))
        except Exception:
            rows.append({name: 0 for name in FEATURE_NAMES})
    return pd.DataFrame(rows)


def main():
    print("Loading dataset...")
    df = pd.read_excel(DATA_PATH)
    df = df.dropna(subset=["URLs", "Labels"]).drop_duplicates(subset=["URLs"])
    df = augment_with_root_domains(df)
    df = augment_with_tracking_params(df)
    print(f"Rows after cleaning + augmentation: {len(df)}  "
          f"(class balance: {df['Labels'].value_counts().to_dict()})")

    print("Extracting features from raw URLs...")
    X = build_feature_matrix(df)
    y = df["Labels"].astype(int).values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"Train: {len(X_train)}  Test: {len(X_test)}")

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Augmentation makes the legitimate class larger than the phishing
    # class, so every model is told to weight classes accordingly rather
    # than just optimizing raw accuracy.
    neg, pos = (y_train == 0).sum(), (y_train == 1).sum()
    scale_pos_weight = neg / pos

    models = {
        "Logistic Regression": (
            LogisticRegression(max_iter=1000, random_state=42, class_weight="balanced"), True
        ),
        "Random Forest": (
            RandomForestClassifier(
                n_estimators=200, max_depth=20, random_state=42, n_jobs=-1, class_weight="balanced"
            ), False
        ),
    }
    if HAS_XGB:
        models["XGBoost"] = (
            XGBClassifier(
                n_estimators=200, max_depth=6, eval_metric="logloss", random_state=42,
                scale_pos_weight=scale_pos_weight,
            ),
            False,
        )
    else:
        print("xgboost not installed — skipping (LR + RF comparison still valid).")

    results = {}
    confusion = {}
    trained_models = {}

    for name, (model, needs_scaling) in models.items():
        print(f"\nTraining {name}...")
        t0 = time.time()
        Xtr = X_train_scaled if needs_scaling else X_train
        Xte = X_test_scaled if needs_scaling else X_test
        model.fit(Xtr, y_train)
        train_time = time.time() - t0

        y_pred = model.predict(Xte)
        y_proba = model.predict_proba(Xte)[:, 1]

        metrics = {
            "accuracy": round(accuracy_score(y_test, y_pred), 4),
            "precision": round(precision_score(y_test, y_pred), 4),
            "recall": round(recall_score(y_test, y_pred), 4),
            "f1_score": round(f1_score(y_test, y_pred), 4),
            "roc_auc": round(roc_auc_score(y_test, y_proba), 4),
            "train_time_seconds": round(train_time, 2),
        }
        results[name] = metrics
        confusion[name] = confusion_matrix(y_test, y_pred).tolist()
        trained_models[name] = (model, needs_scaling)

        print(f"  Accuracy={metrics['accuracy']}  Precision={metrics['precision']}  "
              f"Recall={metrics['recall']}  F1={metrics['f1_score']}  AUC={metrics['roc_auc']}")

    best_name = max(results, key=lambda k: results[k]["f1_score"])

    # Deployment consideration, not just raw score: XGBoost's native
    # save_model()/load_model() format survives library version upgrades;
    # pickled sklearn models do not (this bit us once already during this
    # project — see phishing_detector.py). If XGBoost is within 1 point of
    # F1 of the actual best model, we deploy XGBoost anyway. Worth stating
    # explicitly in the paper's Discussion section as a deployment
    # trade-off, not hidden.
    DEPLOYMENT_TOLERANCE = 0.01
    if "XGBoost" in results and best_name != "XGBoost":
        gap = results[best_name]["f1_score"] - results["XGBoost"]["f1_score"]
        if gap <= DEPLOYMENT_TOLERANCE:
            print(f"\n{best_name} scored marginally higher on F1 (+{round(gap, 4)}), but "
                  f"selecting XGBoost for deployment — native serialization survives library "
                  f"version upgrades, which matters more in practice than a <1pt F1 difference.")
            best_name = "XGBoost"

    print(f"\nSelected for deployment: {best_name}")

    with open(os.path.join(RESULTS_DIR, "model_comparison.json"), "w") as f:
        json.dump(results, f, indent=2)
    with open(os.path.join(RESULTS_DIR, "confusion_matrices.json"), "w") as f:
        json.dump(confusion, f, indent=2)

    best_model, needs_scaling = trained_models[best_name]
    model_format = "xgboost_native" if best_name == "XGBoost" else "sklearn_pickle"

    metadata = {
        "model_name": best_name,
        "feature_names": FEATURE_NAMES,
        "needs_scaling": needs_scaling,
        "model_format": model_format,
    }

    # XGBoost's own save_model()/load_model() (native json/ubj format) is
    # explicitly designed to stay loadable across different xgboost
    # versions — unlike pickle, which broke here once xgboost was upgraded
    # from 2.1 (used to train) to 3.4 (installed later). For the sklearn
    # models (LogisticRegression/RandomForest) there's no equivalent native
    # format, so pickle is used, with the understanding that a retrain is
    # needed if the scikit-learn version changes significantly.
    if model_format == "xgboost_native":
        best_model.save_model(os.path.join(MODELS_DIR, "phishing_model.ubj"))
    else:
        with open(os.path.join(MODELS_DIR, "phishing_model.pkl"), "wb") as f:
            pickle.dump(best_model, f)

    if needs_scaling:
        with open(os.path.join(MODELS_DIR, "scaler.pkl"), "wb") as f:
            pickle.dump(scaler, f)

    with open(os.path.join(MODELS_DIR, "metadata.json"), "w") as f:
        json.dump(metadata, f, indent=2)

    print(f"\nSaved comparison table -> {RESULTS_DIR}/model_comparison.json")
    print(f"Saved best model ({best_name}, format={model_format}) -> {MODELS_DIR}/")

    # Feature importance from Random Forest (if trained) — useful for the paper's discussion
    if "Random Forest" in trained_models:
        rf_model = trained_models["Random Forest"][0]
        importances = sorted(
            zip(FEATURE_NAMES, rf_model.feature_importances_),
            key=lambda x: -x[1],
        )[:8]
        print("\nTop 8 features (Random Forest importance):")
        for feat, score in importances:
            print(f"  {feat}: {round(score, 4)}")
        with open(os.path.join(RESULTS_DIR, "feature_importance.json"), "w") as f:
            json.dump([{"feature": f_, "importance": round(s, 4)} for f_, s in importances], f, indent=2)


if __name__ == "__main__":
    main()
