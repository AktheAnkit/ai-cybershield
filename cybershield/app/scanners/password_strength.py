"""Password Strength Analyzer.

Wraps Dropbox's zxcvbn library, which scores a password 0-4 based on
realistic crack-time estimation (dictionary words, l33t-speak, keyboard
walks, dates, repeats) rather than naive "needs a symbol" rules. This is
the same class of approach used by most production signup forms.
"""
from zxcvbn import zxcvbn

SCORE_LABELS = {
    0: "Very weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very strong",
}


def analyze_password(password: str) -> dict:
    result = zxcvbn(password)

    return {
        "score": result["score"],  # 0-4
        "label": SCORE_LABELS[result["score"]],
        "crack_time_display": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "warning": result["feedback"].get("warning") or "",
        "suggestions": result["feedback"].get("suggestions") or [],
        "guesses_log10": round(result["guesses_log10"], 1),
    }
