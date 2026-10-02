"""A small, transparent allowlist of extremely well-established domains.

Why this exists: the training dataset's legitimate class was sampled from
long-tail small/medium business websites (via IP2Location), with zero
examples of globally top-ranked domains. This is a genuine, documented
distribution gap (see research/README.md "Known limitation") that causes
the pure ML model to sometimes misclassify these specific sites — a
14-character hostname like "google.com" simply never appeared as a
legitimate example during training.

Rather than hide this, it's mitigated with a small, disclosed allowlist —
a standard, precedented technique in production phishing detection (most
commercial tools combine ML/heuristic scoring with a reputation or
allowlist signal rather than relying on either alone).
"""

TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "github.com", "wikipedia.org",
    "microsoft.com", "apple.com", "amazon.com", "facebook.com",
    "linkedin.com", "twitter.com", "x.com", "instagram.com",
    "stackoverflow.com", "mozilla.org", "python.org", "npmjs.com",
    "wordpress.com", "cloudflare.com", "adobe.com", "netflix.com",
    "reddit.com", "quora.com", "medium.com",
    # Indian government / education — relevant given the deployment context
    "gov.in", "nic.in", "ugc.ac.in", "aicte-india.org",
}


def is_trusted(hostname: str) -> bool:
    if not hostname:
        return False
    hostname = hostname.lower()
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return any(hostname == d or hostname.endswith("." + d) for d in TRUSTED_DOMAINS)
