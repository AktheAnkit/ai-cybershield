import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.auth import get_current_user_optional
from app.scanners.ssl_check import check_ssl
from app.scanners.headers_check import check_headers
from app.scanners.phishing_detector import predict_phishing
from app.scanners.risk_rules import build_findings, compute_risk_score
from app.scanners.ai_advisor import generate_advisory

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/tools/advisor", response_class=HTMLResponse)
def advisor_form(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("advisor_tool.html", {"request": request, "user": user, "result": None})


@router.post("/tools/advisor", response_class=HTMLResponse)
def advisor_submit(
    request: Request,
    target: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    target = target.strip()
    hostname_only = target.replace("https://", "").replace("http://", "").split("/")[0]

    ssl_result = check_ssl(hostname_only)
    headers_result = check_headers(target)
    phishing_result = predict_phishing(target)

    findings = build_findings(ssl_result, headers_result, phishing_result)
    risk = compute_risk_score(ssl_result, headers_result, phishing_result)
    advisory = generate_advisory(target, risk["risk_score"], risk["risk_label"], findings)

    result = {
        "target": target,
        "ssl": ssl_result,
        "headers": headers_result,
        "phishing": phishing_result,
        "findings": findings,
        "risk_score": risk["risk_score"],
        "risk_label": risk["risk_label"],
        "sub_scores": risk["sub_scores"],
        "advisory": advisory,
    }

    scan_id = None
    if user:
        scan = Scan(
            user_id=user.id,
            scan_type="full_assessment",
            target=target,
            result_json=json.dumps(result, default=str),
            risk_score=risk["risk_score"],
        )
        db.add(scan)
        db.commit()
        scan_id = scan.id

    return templates.TemplateResponse(
        "advisor_tool.html",
        {"request": request, "user": user, "result": result, "scan_id": scan_id},
    )
