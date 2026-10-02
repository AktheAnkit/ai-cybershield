import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.auth import get_current_user_optional
from app.scanners.password_strength import analyze_password

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/tools/password", response_class=HTMLResponse)
def password_form(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("password_tool.html", {"request": request, "user": user, "result": None})


@router.post("/tools/password", response_class=HTMLResponse)
def password_submit(
    request: Request,
    password: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    result = analyze_password(password)

    if user:
        scan = Scan(user_id=user.id, scan_type="password", target=None, result_json=json.dumps(result))
        db.add(scan)
        db.commit()

    return templates.TemplateResponse("password_tool.html", {"request": request, "user": user, "result": result})
