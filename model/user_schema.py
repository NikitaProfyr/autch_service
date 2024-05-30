from pydantic import BaseModel, EmailStr


class UserSchema(BaseModel):
    id: int
    email: EmailStr
    hashed_password: str
    user_name: str


class UserBase(BaseModel):
    user_name: str


class UserLogin(UserBase):
    password: str


class UserUpdate(UserBase):
    email: str | None
