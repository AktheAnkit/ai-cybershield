import json

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.auth import get_current_user_optional
from app.scanners.website_scanner import scan_website

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/tools/website", response_class=HTMLResponse)
def website_form(request: Request, user=Depends(get_current_user_optional)):
    return templates.TemplateResponse("website_tool.html", {"request": request, "user": user, "result": None})


@router.post("/tools/website", response_class=HTMLResponse)
def website_submit(
    request: Request,
    url: str = Form(...),
    db: Session = Depends(get_db),
    user=Depends(get_current_user_optional),
):
    result = scan_website(url)

    if user and result.get("reachable"):
        scan = Scan(user_id=user.id, scan_type="website", target=url, result_json=json.dumps(result))
        db.add(scan)
        db.commit()

    return templates.TemplateResponse("website_tool.html", {"request": request, "user": user, "result": result})
