from sqlalchemy.orm import Session
from starlette.responses import Response

from fastapi import Request, Depends, HTTPException

from model.settings import get_db
from services.user_services import get_current_user


def CheckAuthMiddleware(
    request: Request, response: Response, db: Session = Depends(get_db)
):
    """Middleware проверяет авторизован ли пользователь"""
    authorization_header = request.headers.get("authorization")
    print(authorization_header)
    if not authorization_header:
        raise HTTPException(
            status_code=401,
            detail="Пользователь не авторизован",
        )
    user = get_current_user(token=authorization_header, db=db)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Пользователь не авторизован",
        )
