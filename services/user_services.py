from datetime import timedelta, datetime
from typing import Annotated, List

from fastapi import HTTPException, Depends
from fastapi import Request
from jose import jwt, JWTError
from sqlalchemy import select, update, or_, and_, delete
from sqlalchemy.orm import Session
from starlette import status
from starlette.status import HTTP_400_BAD_REQUEST

from model.settings import get_db
from model.user_model import User
from model.user_schema import (
    UserBase,
    UserLogin,
    UserUpdate,
)
from security import pwdContext, SECRET_KEY, ALGORITHM, oauth2Scheme


def get_user_by_name(user_data: UserBase, db: Session = Depends(get_db)):
    """Функция возвращает пользователя из бд по его никнейму"""
    user = db.scalar(select(User).where(or_(User.user_name == user_data.user_name)))
    if not user:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким именем не найден.",
        )
    return user


def create_user(db: Session, user_data: UserLogin):
    if db.scalar(select(User).where(or_(User.user_name == user_data.user_name))):
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким именем уже зарегистрирован",
        )
    hashed_password = pwdContext.hash(user_data.password)
    user = User(userName=user_data.userName)
    user.hashed_password = hashed_password
    db.add(user)
    db.commit()
    return user


def authenticated(user_data: UserLogin, db: Session = Depends(get_db)) -> User:
    """ Функция производит аутентификацию пользователя"""
    user = get_user_by_name(db=db, user_data=user_data)
    if not user:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким именем не найден",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not pwdContext.verify(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Не правильный пароль",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def create_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Функция создает и возвращает jwt токен"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def validate_refresh_token(token: str) -> dict | None:
    """Функция проводит валидацию refresh токена"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


def get_current_user(
    token: Annotated[str, Depends(oauth2Scheme)],
    db: Session = Annotated[str, Depends(get_db)],
) -> User:
    """Функция возвращает пользователя из данных JWT токена"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не удалось проверить учетные данные",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_name = payload.get("userName")
        if not user_name:
            raise credentials_exception
        token_data = UserBase(user_name=user_name)
    except JWTError:
        raise credentials_exception
    user = get_user_by_name(db=db, user_data=token_data)
    if not user:
        raise credentials_exception
    return user


def update_user(old_user_data: User, db: Session, new_user_data: UserUpdate):
    """Функция обновляет данные пользователя"""

    try:
        query = (
            update(User)
            .where(and_(User.user_name == old_user_data.user_name))
            .values(
                user_name=new_user_data.user_name,
                email=new_user_data.email,
            )
        )
        db.execute(query)
        db.commit()
        updated_user = db.execute(
            select(User).where(or_(User.user_name == new_user_data.user_name))
        ).scalar()

        return updated_user

    except Exception as ex:
        print(ex)
        db.rollback()
        raise HTTPException(
            status_code=500, detail="Произошла ошибка при обновлении пользователя."
        )


def create_user(db: Session, user_data: UserLogin):
    if db.scalar(select(User).where(or_(User.user_name == user_data.user_name))):
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST,
            detail="Пользователь с таким именем уже зарегистрирован",
        )
    hashed_password = pwdContext.hash(user_data.password)
    user = User(user_name=user_data.user_name)
    user.hashed_password = hashed_password
    db.add(user)
    db.commit()
    return user


def get_data_users(db: Session) -> List[UserBase]:
    users = db.execute(select(User.user_name))
    data = []
    for user in users:
        data.append(UserBase(user_name=user.user_name))
    return data


def delete_user(user_data: User, db: Session = Depends(get_db)):
    try:
        db.execute(delete(User).where(and_(User.user_name == user_data.user_name)))
        db.commit()
    except HTTPException:
        return HTTPException(status_code=HTTP_400_BAD_REQUEST)
