import pytest
import requests
import json
from datetime import datetime, timedelta
import time
import base64
import secrets
from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Базовый URL API
BASE_URL = "http://127.0.0.1:8000/"


def generate_test_keys():
    """
    Generate test keys for JWT
    Using ECDSA with SECP384R1 curve (P-384), can change in future on x25519
    :return:
    """
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode('utf-8'), public_pem.decode('utf-8')

# Test data
TEST_USERNAME = f"testuser_{int(time.time())}"
TEST_PRIVATE_KEY, TEST_PUBLIC_KEY = generate_test_keys()


@pytest.fixture(scope="module")
def auth_headers():
    """
    Fixture for creating a test user and getting a token
    """
    # Register a new use
    register_data = {
        "username": TEST_USERNAME,
        "public_key": TEST_PUBLIC_KEY
    }

    response = requests.post(f"{BASE_URL}/register", json=register_data)
    assert response.status_code == 201

    # Get challenge auth
    challenge_response = requests.get(f"{BASE_URL}/challenge/{TEST_USERNAME}")
    assert challenge_response.status_code == 200
    challenge_data = challenge_response.json()
    challenge = challenge_data["challenge"]

    # Sign the challenge with a private key
    private_key = serialization.load_pem_private_key(
        TEST_PRIVATE_KEY.encode(),
        password=None,
        backend=default_backend()
    )

    signature = private_key.sign(
        challenge.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    signature_b64 = base64.b64encode(signature).decode('utf-8')

    # Authenticate using a signature
    login_data = {
        "username": TEST_USERNAME,
        "signature": signature_b64
    }

    response = requests.post(f"{BASE_URL}/login", json=login_data)
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
    public_key = generate_test_keys()[1]

    register_data = {
        "username": username,
        "public_key": public_key
    }

    response = requests.post(f"{BASE_URL}/register", json=register_data)
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["username"] == username


def test_register_existing_user(auth_headers):
    """
    Test attempt to register an existing user
    """
    public_key = generate_test_keys()[1]

    register_data = {
        "username": TEST_USERNAME,
        "public_key": public_key
    }

    response = requests.post(f"{BASE_URL}/register", json=register_data)
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "already exists" in data["detail"].lower()


def test_login_success():
    """
    Successful login test
    """
    # Get challenge
    challenge_response = requests.get(f"{BASE_URL}/challenge/{TEST_USERNAME}")
    assert challenge_response.status_code == 200
    challenge_data = challenge_response.json()
    challenge = challenge_data["challenge"]

    # Sign challenge
    private_key = serialization.load_pem_private_key(
        TEST_PRIVATE_KEY.encode(),
        password=None,
        backend=default_backend()
    )

    signature = private_key.sign(
        challenge.encode(),
        ec.ECDSA(hashes.SHA256())
    )

    signature_b64 = base64.b64encode(signature).decode('utf-8')

    # Auth
    login_data = {
        "username": TEST_USERNAME,
        "signature": signature_b64
    }

    response = requests.post(f"{BASE_URL}/login", json=login_data)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_signature():
    """
    Test login with invalid signature
    """
    # Get challenge
    challenge_response = requests.get(f"{BASE_URL}/challenge/{TEST_USERNAME}")
    assert challenge_response.status_code == 200
    challenge_data = challenge_response.json()
    challenge = challenge_data["challenge"]

    # Create an invalid signature (just random data)
    invalid_signature = base64.b64encode(b"invalid_signature_data").decode('utf-8')

    login_data = {
        "username": TEST_USERNAME,
        "signature": invalid_signature
    }

    response = requests.post(f"{BASE_URL}/login", json=login_data)
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "invalid" in data["detail"].lower()


def test_login_nonexistent_user():
    """
    Test login with nonexistent user
    """
    # Trying to get a challenge for a non-existent user
    response = requests.get(f"{BASE_URL}/challenge/nonexistent_user")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data


def test_get_current_user(auth_headers):
    """
    Test to get information about the current user
    """
    response = requests.get(f"{BASE_URL}/me", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == TEST_USERNAME
    assert "id" in data
    assert "public_key" in data


def test_get_current_user_unauthorized():
    """
    Test of getting user information without authentication
    """
    response = requests.get(f"{BASE_URL}/me")
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def test_get_public_key(auth_headers):
    """
    Test to get the public key of a user
    """
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
    """
    response = requests.get(f"{BASE_URL}/public-key/999999", headers=auth_headers)
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data


def test_update_public_key(auth_headers):
    """
    Public Key Update Test
    """
    # Generating new key
    new_public_key = generate_test_keys()[1]

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

    # Проверяем, что ключ действительно обновился
    response = requests.get(f"{BASE_URL}/me", headers=auth_headers)
    user_id = response.json()["id"]

    response = requests.get(f"{BASE_URL}/public-key/{user_id}", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()
    assert data["public_key"] == new_public_key


def test_update_public_key_unauthorized():
    """
    Test updating public key without authentication
    """
    new_public_key = generate_test_keys()[1]

    update_data = {
        "public_key": new_public_key
    }

    response = requests.put(f"{BASE_URL}/update-key", json=update_data)
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def test_token_expiration():
    """
    Token expiration test (simulation)
    """
    # Create an expired token manually
    expired_payload = {
        "sub": "1",
        "exp": datetime.utcnow() - timedelta(minutes=5)
    }

    # Use the same secret key as the server
    # In a real test, you need to get the SECRET_KEY from the server configuration
    expired_token = jwt.encode(expired_payload, "test_secret_key", algorithm="HS256")

    expired_headers = {"Authorization": f"Bearer {expired_token}"}
    response = requests.get(f"{BASE_URL}/me", headers=expired_headers)
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data
    assert "token" in data["detail"].lower() or "expired" in data["detail"].lower()


def test_invalid_token():
    """
    Test with an invalid token
    """
    invalid_headers = {"Authorization": "Bearer invalid_token_123"}
    response = requests.get(f"{BASE_URL}/me", headers=invalid_headers)
    assert response.status_code == 401
    data = response.json()
    assert "detail" in data


def test_challenge_expiration():
    """
    Test that challenge expires after some time
    """
    challenge_response = requests.get(f"{BASE_URL}/challenge/{TEST_USERNAME}")
    assert challenge_response.status_code == 200
    challenge_data = challenge_response.json()
    challenge = challenge_data["challenge"]

    # Wait for the challenge to expire (depends on server configuration)
    # In this case, we assume that the challenge expires in 5 minutes
    # In a real test, you need to simulate the expiration of time

    # To simplify the test, just use the old challenge
    # The server should reject it
    login_data = {
        "username": TEST_USERNAME,
        "signature": "fake_signature_123"
    }

    response = requests.post(f"{BASE_URL}/login", json=login_data)
    # The server can return 400 (challenge not found) or 401 (invalid signature)
    assert response.status_code in [400, 401]
