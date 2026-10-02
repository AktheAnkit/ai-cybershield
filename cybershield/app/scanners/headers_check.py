"""Security Headers Checker.

Fetches the target URL and inspects the response for standard security
headers, modeled loosely on securityheaders.com's checklist. Each missing
header is a specific, explainable finding — feeds directly into the AI
Advisor's rule engine later (weeks 5-6).
"""
import requests

CHECKED_HEADERS = {
    "Strict-Transport-Security": "Forces browsers to only use HTTPS for this site.",
    "Content-Security-Policy": "Restricts which sources scripts/styles can load from, mitigating XSS.",
    "X-Content-Type-Options": "Stops browsers from MIME-sniffing responses away from the declared type.",
    "X-Frame-Options": "Prevents this page from being embedded in a clickjacking iframe.",
    "Referrer-Policy": "Controls how much referrer information leaks to other sites.",
    "Permissions-Policy": "Restricts access to browser features like camera, mic, geolocation.",
}


def check_headers(url: str, timeout: float = 6.0) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return {"error": str(exc), "reachable": False}

    present = {}
    missing = []

    for header, description in CHECKED_HEADERS.items():
        if header in response.headers:
            present[header] = response.headers[header]
        else:
            missing.append({"header": header, "description": description})

    score = round(len(present) / len(CHECKED_HEADERS) * 100)

    return {
        "reachable": True,
        "final_url": response.url,
        "status_code": response.status_code,
        "present": present,
        "missing": missing,
        "score": score,
    }
