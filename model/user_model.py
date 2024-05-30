from sqlalchemy.orm import relationship
from model.settings import Base
from sqlalchemy import Column, Integer, String, ForeignKey, Boolean


class User(Base):
    __tablename__ = "User"

    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String, nullable=True, unique=True)
    hashed_password = Column(String)
    user_name = Column(String, unique=True)

    def __str__(self):
        return f"{self.id} {self.user_name}"
