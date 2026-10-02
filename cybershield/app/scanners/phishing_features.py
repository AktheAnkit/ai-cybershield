"""Phishing URL feature extraction.

All features are computed purely from the URL string itself — no live
network calls (no WHOIS, no page fetch). This matters for two reasons:
1. The exact same function is used at training time and at inference
   time in the live app, so there's no train/serve skew.
2. Prediction is instant and doesn't depend on the target site being
   reachable, rate limits, or WHOIS servers being up during a demo.

Feature choices follow the lexical-analysis approach common in phishing
detection literature (URL length, IP-literal hosts, '@' obfuscation,
subdomain count, suspicious keywords, character entropy, etc.).
"""
import math
import re
from urllib.parse import urlparse

SUSPICIOUS_WORDS = [
    "login", "verify", "account", "secure", "update", "confirm",
    "bank", "signin", "password", "billing", "webscr", "ebayisapi",
    "suspend", "recover", "unlock",
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def extract_features(url: str) -> dict:
    url = url.strip()
    if not re.match(r"^https?://", url, re.IGNORECASE):
        # No scheme typed (e.g. user entered "google.com") — assume https,
        # matching how modern browsers behave by default (HTTPS-first),
        # rather than defaulting to http and unfairly penalizing the
        # is_https feature for a URL that never specified a protocol.
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    host_no_port = hostname
    labels = [p for p in host_no_port.split(".") if p]

    lower_url = url.lower()

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "has_ip_host": int(bool(IP_PATTERN.match(hostname))),
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_underscores": url.count("_"),
        "num_slashes": url.count("/"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_at_symbols": url.count("@"),
        "num_subdomains": max(len(labels) - 2, 0),
        "num_query_params": query.count("=") if query else 0,
        "has_fragment": int("#" in url),
        "is_https": int(parsed.scheme == "https"),
        "has_port": int(parsed.port is not None),
        "digit_ratio": (sum(c.isdigit() for c in url) / len(url)) if url else 0.0,
        "hyphen_ratio": (url.count("-") / len(url)) if url else 0.0,
        "url_entropy": round(_shannon_entropy(url), 3),
        "suspicious_word_count": sum(w in lower_url for w in SUSPICIOUS_WORDS),
        "https_token_in_path": int("https" in (path + query).lower()),
        "double_slash_in_path": int("//" in path),
    }


FEATURE_NAMES = list(extract_features("http://example.com/").keys())
