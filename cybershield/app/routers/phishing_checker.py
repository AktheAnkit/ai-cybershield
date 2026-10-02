import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.auth import get_current_user_optional
from app.scanners.phishing_detector import predict_phishing

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/tools/phishing", response_class=HTMLResponse)
def phishing_form(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("phishing_tool.html", {"request": request, "user": user, "result": None})


@router.post("/tools/phishing", response_class=HTMLResponse)
def phishing_submit(
    request: Request,
    url: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    result = predict_phishing(url)

    if user:
        scan = Scan(
            user_id=user.id,
            scan_type="phishing",
            target=url,
            result_json=json.dumps(result),
            risk_score=result["phishing_probability"],
        )
        db.add(scan)
        db.commit()

    return templates.TemplateResponse("phishing_tool.html", {"request": request, "user": user, "result": result})
