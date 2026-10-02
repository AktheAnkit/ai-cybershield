"""AI Phishing Detection — production inference.

Loads the model trained by phishing_ml/train.py. The model itself is
loaded via XGBoost's native save_model()/load_model() format (not
pickle) — pickle broke across an xgboost version upgrade during
development (2.1 -> 3.4 produced "input stream corrupted"), while the
native ubj/json format is explicitly designed by the XGBoost team to
stay loadable across versions.

Deliberately does NOT import pandas or scikit-learn here — the only
thing this module ever needed from pandas was wrapping one row of
features into the right column order, which a plain list does just as
well, and XGBoost's predict_proba() accepts array-like input directly.
Keeping the live app's dependency footprint small avoids pulling in
pandas' large compiled-extension surface for something that isn't
otherwise needed at inference time (pandas/scikit-learn are still used
in research/train.py, which is offline tooling, not part of the
deployed app).
"""
import json
import os
import pickle
from urllib.parse import urlparse

from xgboost import XGBClassifier

from app.scanners.phishing_features import extract_features
from app.scanners.trusted_domains import is_trusted

_MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "ml_models")
_bundle = None


def _load_bundle():
    global _bundle
    if _bundle is None:
        with open(os.path.join(_MODELS_DIR, "metadata.json")) as f:
            metadata = json.load(f)

        if metadata["model_format"] == "xgboost_native":
            model = XGBClassifier()
            model.load_model(os.path.join(_MODELS_DIR, "phishing_model.ubj"))
        else:
            # Fallback path — only used if a future retrain picks
            # Logistic Regression or Random Forest instead of XGBoost.
            with open(os.path.join(_MODELS_DIR, "phishing_model.pkl"), "rb") as f:
                model = pickle.load(f)

        scaler = None
        if metadata["needs_scaling"]:
            with open(os.path.join(_MODELS_DIR, "scaler.pkl"), "rb") as f:
                scaler = pickle.load(f)

        _bundle = {
            "model": model,
            "scaler": scaler,
            "needs_scaling": metadata["needs_scaling"],
            "feature_names": metadata["feature_names"],
            "model_name": metadata["model_name"],
        }
    return _bundle


def predict_phishing(url: str) -> dict:
    bundle = _load_bundle()
    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_names = bundle["feature_names"]

    features = extract_features(url)
    X = [[features[name] for name in feature_names]]

    if bundle["needs_scaling"] and scaler is not None:
        X = scaler.transform(X)

    proba = model.predict_proba(X)[0]
    phishing_probability = float(proba[1]) * 100  # convert to 0-100 percentage right away

    scheme_url = url if url.startswith(("http://", "https://")) else "https://" + url
    hostname = urlparse(scheme_url).hostname
    trusted = is_trusted(hostname)
    if trusted:
        # Documented mitigation for a training-data gap — see
        # trusted_domains.py docstring. Disclosed in the result, not
        # silently applied.
        phishing_probability = min(phishing_probability, 3.0)

    prediction = int(phishing_probability >= 50)

    if phishing_probability >= 85:
        risk_label = "Very likely phishing"
    elif phishing_probability >= 50:
        risk_label = "Likely phishing"
    elif phishing_probability >= 20:
        risk_label = "Probably safe"
    else:
        risk_label = "Likely legitimate"

    top_signals = _top_signals(features)
    if trusted:
        top_signals = ["Domain matched a trusted allowlist entry (overrides raw ML score)."]

    return {
        "url": url,
        "is_phishing": bool(prediction),
        "phishing_probability": round(phishing_probability, 1),
        "risk_label": risk_label,
        "model_used": bundle["model_name"],
        "trusted_domain_match": trusted,
        "top_signals": top_signals,
    }


def _top_signals(features: dict) -> list:
    """Human-readable flags for the AI Advisor to build on later."""
    signals = []
    if features["has_ip_host"]:
        signals.append("URL uses a raw IP address instead of a domain name.")
    if features["num_at_symbols"] > 0:
        signals.append("URL contains '@', which can hide the real destination.")
    if features["num_subdomains"] >= 3:
        signals.append(f"Unusually deep subdomain chain ({features['num_subdomains']} levels).")
    if not features["is_https"]:
        signals.append("Connection is not using HTTPS.")
    if features["suspicious_word_count"] >= 2:
        signals.append("Multiple credential-related keywords found in the URL (e.g. login, verify, secure).")
    if features["https_token_in_path"]:
        signals.append("The word 'https' appears in the path/query — a common disguise trick.")
    if features["url_entropy"] > 4.5:
        signals.append("URL has unusually high character randomness.")
    return signals
