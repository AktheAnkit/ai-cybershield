import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.auth import get_current_user_optional
from app.scanners.ssl_check import check_ssl

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/tools/ssl", response_class=HTMLResponse)
def ssl_form(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("ssl_tool.html", {"request": request, "user": user, "result": None})


@router.post("/tools/ssl", response_class=HTMLResponse)
def ssl_submit(
    request: Request,
    hostname: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    result = check_ssl(hostname)

    if user and result.get("reachable"):
        scan = Scan(user_id=user.id, scan_type="ssl", target=hostname, result_json=json.dumps(result))
        db.add(scan)
        db.commit()

    return templates.TemplateResponse("ssl_tool.html", {"request": request, "user": user, "result": result})
