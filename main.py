from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from routers.user_router import user_public_router, user_private_router

app = FastAPI(
    title="BWG App",
    description="IBD Corporation - perfect, fast, cheap.",
    contact={"name": "Profyr Nikita"},
)


app.include_router(
    router=user_public_router,
    prefix="/users",
)

app.include_router(
    router=user_private_router,
    prefix="/users",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,  # Разрешить отправлять куки
    allow_methods=["POST", "GET", "DELETE", "PUT"],  # Разрешить любые HTTP-методы
    allow_headers=["*"],  # Разрешить любые заголовки
)
