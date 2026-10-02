"""Rule engine + AI Risk Score aggregation.

Deterministic layer: turns raw scan results (SSL, Headers, Phishing) into
a structured list of findings with severities, plus a single weighted
0-100 risk score. This is intentionally separate from the LLM — the LLM
(ai_advisor.py) only ever sees this structured output and reformats/
prioritizes it in natural language. Keeping the scoring deterministic
means the number is reproducible and explainable even if the LLM is
unreachable.
"""

# Weights for combining the three sub-scores into one risk score.
# Phishing gets the most weight since it's a direct, live threat signal;
# SSL and headers are more about baseline configuration hygiene. This is
# a design choice worth stating explicitly in the paper — future work
# could tune these empirically rather than by fixed assignment.
WEIGHTS = {"phishing": 0.4, "ssl": 0.3, "headers": 0.3}

HEADER_SEVERITY = {
    "Strict-Transport-Security": "high",
    "Content-Security-Policy": "high",
    "X-Frame-Options": "medium",
    "X-Content-Type-Options": "medium",
    "Referrer-Policy": "low",
    "Permissions-Policy": "low",
}

# Points contributed to headers_risk when a header of this severity is
# missing. Derived from HEADER_SEVERITY so there's one source of truth —
# previously the risk *score* used a flat "% of headers present" while
# the *findings* list already used this severity taxonomy, an
# inconsistency that made a missing Permissions-Policy count the same as
# a missing Strict-Transport-Security. Values sum to 100 when all six are
# missing (25+25 high, 15+15 medium, 10+10 low).
_SEVERITY_POINTS = {"high": 25, "medium": 15, "low": 10}
HEADER_RISK_WEIGHTS = {header: _SEVERITY_POINTS[sev] for header, sev in HEADER_SEVERITY.items()}


def build_findings(ssl_result: dict, headers_result: dict, phishing_result: dict) -> list:
    findings = []

    # --- SSL ---
    if not ssl_result.get("reachable"):
        findings.append({
            "category": "SSL", "severity": "high",
            "message": ssl_result.get("error", "SSL check failed."),
        })
    else:
        for f in ssl_result.get("findings", []):
            findings.append({"category": "SSL", "severity": f["severity"], "message": f["message"]})

    # --- Headers ---
    if headers_result.get("reachable"):
        for m in headers_result.get("missing", []):
            sev = HEADER_SEVERITY.get(m["header"], "low")
            findings.append({
                "category": "Headers", "severity": sev,
                "message": f"Missing {m['header']} — {m['description']}",
            })
    else:
        findings.append({
            "category": "Headers", "severity": "medium",
            "message": headers_result.get("error", "Headers check failed."),
        })

    # --- Phishing ---
    prob = phishing_result.get("phishing_probability", 0)
    if phishing_result.get("trusted_domain_match"):
        findings.append({
            "category": "Phishing", "severity": "info",
            "message": "Domain matched a trusted allowlist entry — ML score overridden.",
        })
    else:
        if prob >= 85:
            findings.append({"category": "Phishing", "severity": "critical", "message": f"URL pattern strongly resembles known phishing ({prob}% probability)."})
        elif prob >= 50:
            findings.append({"category": "Phishing", "severity": "high", "message": f"URL pattern resembles phishing ({prob}% probability)."})
        elif prob >= 20:
            findings.append({"category": "Phishing", "severity": "medium", "message": f"Some suspicious URL characteristics detected ({prob}% probability)."})

        for signal in phishing_result.get("top_signals", []):
            if signal not in [f["message"] for f in findings]:
                findings.append({"category": "Phishing", "severity": "info", "message": signal})

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))
    return findings


def compute_risk_score(ssl_result: dict, headers_result: dict, phishing_result: dict) -> dict:
    # SSL sub-score
    if not ssl_result.get("reachable"):
        ssl_risk = 100
    else:
        days_left = ssl_result.get("days_left", 999)
        if days_left < 0:
            ssl_risk = 100
        elif days_left < 15:
            ssl_risk = 75
        elif days_left < 30:
            ssl_risk = 40
        else:
            ssl_risk = 5
        if ssl_result.get("protocol") in ("TLSv1", "TLSv1.1"):
            ssl_risk = min(100, ssl_risk + 30)

    # Headers sub-score — severity-weighted, not flat percentage (see
    # HEADER_RISK_WEIGHTS above)
    if headers_result.get("reachable"):
        missing = [m["header"] for m in headers_result.get("missing", [])]
        headers_risk = min(100, sum(HEADER_RISK_WEIGHTS.get(h, 10) for h in missing))
    else:
        headers_risk = 60  # unknown — treated as moderate risk, not zero

    # Phishing sub-score
    phishing_risk = phishing_result.get("phishing_probability", 0)

    raw_score = (
        WEIGHTS["phishing"] * phishing_risk
        + WEIGHTS["ssl"] * ssl_risk
        + WEIGHTS["headers"] * headers_risk
    )
    risk_score = max(0, min(100, round(raw_score)))

    if risk_score >= 76:
        risk_label = "Critical"
    elif risk_score >= 51:
        risk_label = "High"
    elif risk_score >= 26:
        risk_label = "Medium"
    else:
        risk_label = "Low"

    return {
        "risk_score": risk_score,
        "risk_label": risk_label,
        "sub_scores": {
            "ssl_risk": round(ssl_risk),
            "headers_risk": round(headers_risk),
            "phishing_risk": round(phishing_risk),
        },
    }
