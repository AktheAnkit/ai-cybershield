"""Website Security Scanner.

Passive, OSINT-style checks only — a handful of GET requests to
well-known public paths, the same requests any browser could make.
Deliberately does NOT do port scanning, brute-forcing, or anything that
attempts to bypass authentication or reach non-public resources. That
distinction matters both ethically and legally — more aggressive active
scanning of third-party infrastructure without permission can cross into
unauthorized-access territory in most jurisdictions, which is why this
module stays limited to what's already publicly reachable.
"""
import requests

SENSITIVE_PATHS = [
    ("/.env", "Environment file exposed — often contains secrets/API keys."),
    ("/.git/HEAD", "Git repository exposed — full source code may be downloadable."),
    ("/.git/config", "Git config exposed — may reveal repository URLs/credentials."),
    ("/.DS_Store", "macOS folder metadata exposed — can leak internal file/folder names."),
    ("/wp-config.php.bak", "WordPress config backup exposed — may contain DB credentials."),
    ("/backup.sql", "Database backup file publicly accessible."),
    ("/config.php.bak", "Config backup file publicly accessible."),
    ("/.htaccess", "Apache config file exposed."),
]


def _safe_get(url, timeout=4.0):
    try:
        return requests.get(url, timeout=timeout, allow_redirects=False)
    except requests.RequestException:
        return None


def scan_website(url: str, timeout: float = 5.0) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    base = url.rstrip("/")

    try:
        home = requests.get(base, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return {"error": str(exc), "reachable": False}

    findings = []

    # --- Server/framework version disclosure ---
    server = home.headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
        findings.append({"severity": "low", "message": f"Server header discloses version info: '{server}'."})
    powered_by = home.headers.get("X-Powered-By", "")
    if powered_by:
        findings.append({"severity": "low", "message": f"X-Powered-By header discloses tech stack: '{powered_by}'."})

    # --- Cookie flags ---
    for cookie in home.cookies:
        if not cookie.secure:
            findings.append({"severity": "medium", "message": f"Cookie '{cookie.name}' is missing the Secure flag."})
        if not (cookie.has_nonstandard_attr("HttpOnly") or cookie.has_nonstandard_attr("httponly")):
            findings.append({"severity": "medium", "message": f"Cookie '{cookie.name}' is missing the HttpOnly flag."})

    # --- Sensitive file/path exposure ---
    # Baseline first: some misconfigured servers return 200 for every path
    # ("soft 404s") instead of a real 404 — without this check, that would
    # make every path below look "exposed" as a false positive.
    baseline = _safe_get(base + "/__cybershield_baseline_9f3a__", timeout=timeout)
    soft_404 = baseline is not None and baseline.status_code == 200

    exposed = []
    if soft_404:
        findings.append({
            "severity": "info",
            "message": "Server returns HTTP 200 for nonexistent paths (soft-404s) — sensitive-file checks skipped as unreliable.",
        })
    else:
        for path, desc in SENSITIVE_PATHS:
            resp = _safe_get(base + path, timeout=timeout)
            if resp is not None and resp.status_code == 200 and len(resp.content) > 0:
                exposed.append(path)
                findings.append({"severity": "critical", "message": f"{path} is publicly accessible — {desc}"})

    # --- robots.txt ---
    robots = _safe_get(base + "/robots.txt", timeout=timeout)
    has_robots = robots is not None and robots.status_code == 200
    if has_robots and "disallow" in robots.text.lower():
        disallowed = [
            line.split(":", 1)[1].strip()
            for line in robots.text.splitlines()
            if line.lower().startswith("disallow") and len(line.split(":", 1)) > 1 and line.split(":", 1)[1].strip()
        ]
        if disallowed:
            findings.append({
                "severity": "info",
                "message": f"robots.txt discloses {len(disallowed)} restricted path(s) — worth checking none are sensitive.",
            })

    # --- security.txt ---
    sec_txt = _safe_get(base + "/.well-known/security.txt", timeout=timeout)
    has_security_txt = sec_txt is not None and sec_txt.status_code == 200
    if not has_security_txt:
        findings.append({
            "severity": "low",
            "message": "No security.txt found — no published channel for researchers to report vulnerabilities responsibly.",
        })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 5))

    return {
        "reachable": True,
        "final_url": home.url,
        "server_header": server or None,
        "exposed_paths": exposed,
        "has_robots_txt": has_robots,
        "has_security_txt": has_security_txt,
        "findings": findings,
    }
