from datetime import datetime

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, Float
from sqlalchemy.orm import relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(120), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("Scan", back_populates="owner", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scan_type = Column(String(30), nullable=False)  # password | ssl | headers | phishing | website
    target = Column(String(255), nullable=True)  # domain/url — null for password checks
    result_json = Column(Text, nullable=False)  # raw structured result, used later for PDF reports
    risk_score = Column(Float, nullable=True)  # 0-100, filled once the AI Risk Score module exists
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("User", back_populates="scans")
