"""AI Security Advisor — LLM layer.

Takes the rule engine's structured findings + risk score and asks a
local LLM (via Ollama) to write a short, prioritized, natural-language
summary. The prompt explicitly forbids inventing new findings — the LLM
only reformats/prioritizes what the deterministic rule engine already
produced. This keeps the advisory grounded and auditable, which matters
both for trustworthiness and for defending the design in a viva.

Running locally (rather than an external API) means scan results for a
security tool never leave the machine, and the app keeps working even
without internet access during a demo — falls back to a rule-based
summary if Ollama isn't reachable, rather than crashing.
"""
import requests

from app.config import settings


def _build_prompt(target: str, risk_score: int, risk_label: str, findings: list) -> str:
    if findings:
        findings_text = "\n".join(
            f"- [{f['severity'].upper()}] {f['category']}: {f['message']}" for f in findings
        )
    else:
        findings_text = "No issues found."

    return f"""You are a security advisor summarizing an automated scan for a non-expert user.

Target: {target}
Overall risk score: {risk_score}/100 ({risk_label} risk)

Findings from automated checks:
{findings_text}

Write:
1. A 2-3 sentence plain-language summary of the overall security posture.
2. The top 3 most important actions to take, ordered by priority, one sentence each.

Rules: only reference the findings listed above — never invent new issues. Plain text only, no markdown headers or asterisks."""


def generate_advisory(target: str, risk_score: int, risk_label: str, findings: list) -> dict:
    prompt = _build_prompt(target, risk_score, risk_label, findings)

    try:
        response = requests.post(
            f"{settings.ollama_base_url}/api/generate",
            json={"model": settings.ollama_model, "prompt": prompt, "stream": False},
            timeout=45,
        )
        response.raise_for_status()
        text = response.json().get("response", "").strip()
        if text:
            return {"advisory_text": text, "source": "llm", "model": settings.ollama_model}
    except requests.RequestException:
        pass

    return {
        "advisory_text": _fallback_summary(risk_label, findings),
        "source": "rule-based-fallback",
        "model": None,
    }


def _fallback_summary(risk_label: str, findings: list) -> str:
    critical_high = [f for f in findings if f["severity"] in ("critical", "high")]
    if not critical_high:
        return f"Overall risk is {risk_label.lower()}. No critical or high-severity issues were found in this scan."
    lines = [f"Overall risk is {risk_label.lower()}. Top issues to address:"]
    for f in critical_high[:3]:
        lines.append(f"- {f['message']}")
    return "\n".join(lines)
