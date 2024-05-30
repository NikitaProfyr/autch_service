from fastapi.testclient import TestClient

from main import app

from model.user_schema import UserLogin, UserUpdate


client = TestClient(app)

auth_data = UserLogin(user_name="TestUserName", password="TestPassword")
user_data = UserUpdate(user_name="TestUserName", email=None)
fake_auth_data = UserLogin(user_name="TestUserName", password="FakePassword")
update_auth_data = UserUpdate(user_name="TestUserName", email="NewEmail@gmail.com")


def test_registration():
    response = client.post("/users/logup", data=auth_data.json())

    # Успешная регистрация
    assert response.status_code == 200
    response = client.post("/users/logup", data=auth_data.json())

    # Пользователь с таким именем уже зарегистрирован
    assert response.status_code == 400


def test_authorization():
    response = client.post("/users/login", data=auth_data.json())

    # Успешная авторизация.
    assert response.status_code == 200
    response = client.post("/users/login", data=fake_auth_data.json())

    # Не существует пользователя с данным логином или некорректный пароль.
    assert response.status_code == 400


def test_private_routers():
    auth_response = client.post("/users/login", data=auth_data.json())

    response = client.get(
        "/users/me", headers=auth_response.headers, cookies=auth_response.cookies
    )

    # После успешной проверки прав доступа возвращается личная информация
    assert response.status_code == 200

    response = client.post(
        "/users/me",
        content=update_auth_data.json(),
        headers=auth_response.headers,
        cookies=auth_response.cookies,
    )
    new_user_response = response.json()
    assert new_user_response["user"] == update_auth_data.dict()

    # Пользователь не авторизован
    response = client.get("/users/me")
    assert response.status_code == 401
