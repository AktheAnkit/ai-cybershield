from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import Scan
from app.auth import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db), user=Depends(get_current_user)):
    recent_scans = (
        db.query(Scan)
        .filter(Scan.user_id == user.id)
        .order_by(desc(Scan.created_at))
        .limit(10)
        .all()
    )
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "user": user, "scans": recent_scans}
    )
