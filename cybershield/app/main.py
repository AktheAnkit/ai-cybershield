from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.database import Base, engine
from app.routers import (
    auth_routes, dashboard, password_checker, ssl_checker,
    headers_checker, phishing_checker, risk_advisor, website_checker, reports,
)

# Creates tables on first run. For anything beyond a student project,
# switch this to Alembic migrations.
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI-Powered CyberShield")

app.mount("/static", StaticFiles(directory="app/static"), name="static")

app.include_router(auth_routes.router)
app.include_router(dashboard.router)
app.include_router(password_checker.router)
app.include_router(ssl_checker.router)
app.include_router(headers_checker.router)
app.include_router(phishing_checker.router)
app.include_router(risk_advisor.router)
app.include_router(website_checker.router)
app.include_router(reports.router)
