import pytest
import requests
import json
from datetime import datetime, timedelta
import time

# Базовый URL API
BASE_URL = "http://127.0.0.1:8000/"

# Тестовые данные
TEST_USERNAME = f"testuser_{int(time.time())}"
TEST_PASSWORD = "testpassword123"
TEST_PUBLIC_KEY = "test_public_key_12345"


@pytest.fixture(scope="module")
def auth_headers():
    """
    Fixture for creating a test user and getting a token
    :return:
    """
    register_data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD,
        "public_key": TEST_PUBLIC_KEY
    }

    response = requests.post(f"{BASE_URL}/register", json=register_data)
    assert response.status_code == 201

    login_data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD
    }

    response = requests.post(
        f"{BASE_URL}/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD, "grant_type": "password"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    assert response.status_code == 200
    token_data = response.json()
    access_token = token_data["access_token"]

    return {"Authorization": f"Bearer {access_token}"}


def test_register_user():
    """
    New user registration test
    :return:
    """
    username = f"newuser_{int(time.time())}"

    register_data = {
        "username": username,
        "password": "newpassword123",
        "public_key": "new_public_key_123"
    }

    response = requests.post(f"{BASE_URL}/register", json=register_data)

    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["username"] == username


def test_register_existing_user(auth_headers):
    """
    Test attempt to register an existing user
    :param auth_headers (Not using):
    :return:
    """
    register_data = {
        "username": TEST_USERNAME,
        "password": "differentpassword",
        "public_key": "different_public_key"
    }

    response = requests.post(f"{BASE_URL}/register", json=register_data)

    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "already exists" in data["detail"].lower()


def test_login_success():
    """
    Successful login test
    :return:
    """
    login_data = {
        "username": TEST_USERNAME,
        "password": TEST_PASSWORD
    }

    response = requests.post(
        f"{BASE_URL}/login",
        data={"username": TEST_USERNAME, "password": TEST_PASSWORD, "grant_type": "password"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_credentials():
    """
    Test login with invalid credentials
    :return:
    """
    response = requests.post(
        f"{BASE_URL}/login",
        data={"username": "nonexistent", "password": "wrongpassword", "grant_type": "password"},
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )

    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "invalid" in data["detail"].lower()


def test_get_current_user(auth_headers):
    """
    Test to get information about the current user
    :param auth_headers:
    :return:
    """
    response = requests.get(f"{BASE_URL}/me", headers=auth_headers)

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == TEST_USERNAME
    assert "id" in data
    assert "hashed_password" not in data  # Пароль не должен возвращаться


def test_get_current_user_unauthorized():
    """
    Test of getting user information without authentication
    :return:
    """

    response = requests.get(f"{BASE_URL}/me")

    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def test_get_public_key(auth_headers):
    """
    Test to get the public key of a user
    :param auth_headers:
    :return:
    """
    # Сначала получаем ID пользователя
    response = requests.get(f"{BASE_URL}/me", headers=auth_headers)
    user_id = response.json()["id"]

    response = requests.get(f"{BASE_URL}/public-key/{user_id}", headers=auth_headers)

    assert response.status_code == 200
    data = response.json()
    assert data["user_id"] == user_id
    assert data["public_key"] == TEST_PUBLIC_KEY


def test_get_nonexistent_public_key(auth_headers):
    """
    Test of getting public key of non-existent user
    :param auth_headers:
    :return:
    """
    response = requests.get(f"{BASE_URL}/public-key/999999", headers=auth_headers)

    assert response.status_code == 404
    data = response.json()
    assert "detail" in data


def test_update_public_key(auth_headers):
    """
    Public Key Update Test
    :param auth_headers:
    :return:
    """
    new_public_key = "updated_public_key_56789"
    update_data = {
        "public_key": new_public_key
    }

    response = requests.put(
        f"{BASE_URL}/update-key",
        json=update_data,
        headers=auth_headers
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "public key updated"

    response = requests.get(f"{BASE_URL}/me", headers=auth_headers)
    user_id = response.json()["id"]

    response = requests.get(f"{BASE_URL}/public-key/{user_id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["public_key"] == new_public_key


def test_update_public_key_unauthorized():
    """Тест обновления публичного ключа без аутентификации"""
    update_data = {
        "public_key": "new_key"
    }

    response = requests.put(f"{BASE_URL}/update-key", json=update_data)

    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def test_token_expiration(auth_headers):
    """
    Token expiration test (simulation)
    :param auth_headers (Not using):
    :return:
    """
    expired_token = create_expired_token(TEST_USERNAME)
    expired_headers = {"Authorization": f"Bearer {expired_token}"}

    response = requests.get(f"{BASE_URL}/me", headers=expired_headers)

    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "token" in data["detail"].lower() or "expired" in data["detail"].lower()


def test_invalid_token():
    """
    Test with an invalid token
    :return:
    """
    invalid_headers = {"Authorization": "Bearer invalid_token_123"}

    response = requests.get(f"{BASE_URL}/me", headers=invalid_headers)

    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def create_expired_token(username):
    """
    Helper function for creating an expired token
    # In a real implementation this should use the same secret key and algorithm as the server
    # Here is a simplified simulation
    :param username:
    :return:
    """

    return "expired_token_placeholder"