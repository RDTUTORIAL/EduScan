"""
Middleware for user session management via cookies.
"""

from fastapi import Request, Response
from typing import Optional
import uuid

from .database import db

COOKIE_NAME = "eduscan_user_id"
COOKIE_MAX_AGE = 60 * 60 * 24 * 365  

def get_user_id_from_request(request: Request) -> str:
    """Get or create user ID from request cookies."""
    user_id = request.cookies.get(COOKIE_NAME)
    
    
    if user_id and db.get_user(user_id):
        db.update_user_activity(user_id)
        return user_id
    
    
    new_user_id = db.create_user()
    return new_user_id

def set_user_cookie(response: Response, user_id: str):
    """Set user ID cookie in response."""
    response.set_cookie(
        key=COOKIE_NAME,
        value=user_id,
        max_age=COOKIE_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False  
    )
