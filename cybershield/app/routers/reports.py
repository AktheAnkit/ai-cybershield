from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Scan
from app.auth import get_current_user
from app.scanners.pdf_report import generate_scan_pdf

router = APIRouter()


@router.get("/reports/{scan_id}/pdf")
def download_report(scan_id: int, db: Session = Depends(get_db), user=Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    pdf_bytes = generate_scan_pdf(scan)
    filename = f"cybershield-report-{scan.scan_type}-{scan.id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
