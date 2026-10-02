"""SSL Certificate Checker.

Opens a TLS connection to the target host on port 443 and inspects the
certificate the server presents: expiry, issuer, protocol version. Pure
standard library (ssl + socket) — no external API dependency, which
matters for a viva demo where you don't want a third-party rate limit
to break your live check.
"""
import socket
import ssl
from datetime import datetime


def check_ssl(hostname: str, port: int = 443, timeout: float = 5.0) -> dict:
    hostname = hostname.replace("https://", "").replace("http://", "").split("/")[0]

    context = ssl.create_default_context()
    findings = []

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
    except (socket.gaierror, socket.timeout, ConnectionRefusedError, OSError) as exc:
        return {"error": f"Could not connect to {hostname}:{port} — {exc}", "reachable": False}
    except ssl.SSLCertVerificationError as exc:
        return {"error": f"Certificate verification failed — {exc}", "reachable": False}

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    days_left = (not_after - datetime.utcnow()).days

    issuer = dict(x[0] for x in cert.get("issuer", []))
    subject = dict(x[0] for x in cert.get("subject", []))

    if days_left < 0:
        findings.append({"severity": "critical", "message": "Certificate has expired."})
    elif days_left < 15:
        findings.append({"severity": "high", "message": f"Certificate expires in {days_left} days."})
    elif days_left < 30:
        findings.append({"severity": "medium", "message": f"Certificate expires in {days_left} days — renew soon."})

    if protocol in ("TLSv1", "TLSv1.1"):
        findings.append({"severity": "high", "message": f"Outdated protocol in use: {protocol}."})

    return {
        "reachable": True,
        "hostname": hostname,
        "issuer": issuer.get("organizationName", issuer.get("commonName", "Unknown")),
        "subject": subject.get("commonName", hostname),
        "valid_from": cert.get("notBefore"),
        "valid_until": cert.get("notAfter"),
        "days_left": days_left,
        "protocol": protocol,
        "findings": findings,
    }
