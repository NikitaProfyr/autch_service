from datetime import timedelta
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session

from starlette.status import HTTP_200_OK, HTTP_400_BAD_REQUEST, HTTP_408_REQUEST_TIMEOUT

from middleware.Token import CheckAuthMiddleware
from model.user_schema import UserLogin, UserUpdate, UserBase
from model.settings import get_db
from security import ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS

from services.user_services import (
    authenticated,
    create_token,
    validate_refresh_token,
    create_user,
    update_user,
    get_data_users,
    get_current_user,
)

user_public_router = APIRouter(tags=["UserPublicRoutes"])
user_private_router = APIRouter(
    tags=["UserPrivate"], dependencies=[Depends(CheckAuthMiddleware)]
)


@user_public_router.post("/logup")
def registration(user_data: UserLogin, db: Session = Depends(get_db)):
    """Регистрирует нового пользователя"""
    create_user(db=db, user_data=user_data)
    return HTTP_200_OK


@user_public_router.post("/refresh")
def refresh(request: Request):
    """Получает существующий рефреш токен, при условии корректного рефреш токена возвращает access_token"""
    refresh_token = request.cookies.get("refreshToken")
    if refresh_token is None:
        print("Нет токена")
        raise HTTPException(
            status_code=HTTP_408_REQUEST_TIMEOUT, detail="Не валидный refresh token"
        )
    refresh_token = validate_refresh_token(token=refresh_token)
    if refresh_token is None:
        print("Не прошел проверку")
        raise HTTPException(
            status_code=HTTP_408_REQUEST_TIMEOUT, detail="Не валидный refresh token"
        )
    access_token = create_token({"userName": refresh_token.get("userName")})

    return {"accessToken": access_token}


@user_public_router.post("/login")
def authorization(
    user_data: UserLogin,
    response: Response,
    db: Session = Depends(get_db),
):
    """Авторизует пользователя"""
    user = authenticated(db=db, user_data=user_data)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    access_token = create_token(
        data={"userName": user.user_name}, expires_delta=access_token_expires
    )
    refresh_token = create_token(
        data={"userName": user.user_name}, expires_delta=refresh_token_expires
    )

    response.set_cookie(
        key="refreshToken",
        value=refresh_token,
        max_age=24 * 30 * 60 * 60 * 1000,
        httponly=True,
        samesite=None,
        secure=False,
    )
    response.headers["Authorization"] = access_token
    return {"user": user, "accessToken": access_token, "refreshToken": refresh_token}


@user_public_router.post("/logout")
def logout(response: Response):
    """Удаляет токен и куки пользователя (Выход из аккаунта)"""
    response.delete_cookie("refreshToken")
    return HTTP_200_OK


@user_public_router.get("/")
def get_users_data(db: Session = Depends(get_db)) -> List[UserBase]:
    data = get_data_users(db=db)
    return data


@user_private_router.post("/me")
def update_user_data(
    user_data: UserUpdate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Обновляет данные конкретного пользователя"""
    user_updated = update_user(request=request, db=db, user_data=user_data)
    response.delete_cookie("refreshToken")
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    refresh_token_expires = timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    access_token = create_token(
        data={"userName": user_updated.user_name}, expires_delta=access_token_expires
    )
    refresh_token = create_token(
        data={"userName": user_updated.user_name}, expires_delta=refresh_token_expires
    )
    response.set_cookie(
        key="refreshToken",
        value=refresh_token,
        max_age=24 * 30 * 60 * 60 * 1000,
        httponly=True,
        samesite=None,
        secure=False,
    )
    response.headers["authorization"] = access_token

    return {
        "user": {
            "user_name": user_updated.user_name,
            "email": user_updated.email,
        },
        "accessToken": access_token,
    }


@user_private_router.get("/me")
def get_data_current_user(
    request: Request, db: Session = Depends(get_db)
) -> UserUpdate:
    refresh_token = request.cookies.get("refreshToken")
    user = get_current_user(token=refresh_token, db=db)
    return UserUpdate(user_name=user.user_name, email=user.email)
