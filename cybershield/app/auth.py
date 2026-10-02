from datetime import datetime, timedelta
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status, Request
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.database import get_db
from app.models import User

# Using bcrypt directly rather than passlib's CryptContext: passlib 1.7.4's
# backend self-test breaks on bcrypt>=4.1 (a known, still-unfixed
# incompatibility). Calling bcrypt directly sidesteps it entirely.
BCRYPT_MAX_BYTES = 72  # bcrypt silently ignores bytes beyond this


def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")[:BCRYPT_MAX_BYTES]
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    pw_bytes = plain_password.encode("utf-8")[:BCRYPT_MAX_BYTES]
    return bcrypt.checkpw(pw_bytes, hashed_password.encode("utf-8"))


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Protects a route: redirects to /login if there's no valid token."""
    token = request.cookies.get("access_token")
    redirect = HTTPException(status_code=status.HTTP_303_SEE_OTHER, headers={"Location": "/login"})

    if not token:
        raise redirect
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise redirect
    except JWTError:
        raise redirect

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise redirect
    return user


def get_current_user_optional(request: Request, db: Session = Depends(get_db)) -> Optional[User]:
    """Same idea, but returns None instead of redirecting — for pages usable
    while logged out (e.g. tools should still work anonymously, just won't
    save history)."""
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        username: Optional[str] = payload.get("sub")
    except JWTError:
        return None
    if not username:
        return None
    return db.query(User).filter(User.username == username).first()
