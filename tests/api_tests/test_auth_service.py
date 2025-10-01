import pytest
import os
import base64
from dishka import make_async_container
from random import randint

from src.providers import AppProvider

from src.adapters.api.service import AuthHTTPService
from src.adapters.encryption.service import AbstractECDHCipher, AbstractECDSASignature

from src.adapters.encryption.service import X25519Cipher, SECP384R1Signature

from src.exceptions import *

number = randint(1, 1000000)
fake_user = f"fake_user{number}"

ecdsa_private_key = None

async def get_service():
    container = make_async_container(AppProvider())
    async with container() as request_container:
        auth_service = await request_container.get(AuthHTTPService)
        return auth_service, container

async def close_container(container):
    await container.close()

@pytest.mark.asyncio
async def test_register():
    auth_service, container = await get_service()

    try:
        # register new user
        data = await auth_service.register(fake_user)

        assert data.get('id') is not None
        assert data.get('username') == fake_user
        assert data.get('ecdsa_private_key') is not None
        assert data.get('ecdh_private_key') is not None

        global ecdsa_private_key
        ecdsa_private_key = data.get('ecdsa_private_key')

        # register already exists user
        with pytest.raises(UserAlreadyExistsError):
            await auth_service.register(fake_user)

        bad_username1 = "" # too short/empty

        with pytest.raises(APIError):
            await auth_service.register(bad_username1)

        bad_username2 = "a" * 256 # too long

        with pytest.raises(APIError):
            await auth_service.register(bad_username2)

    finally:
        await close_container(container)

@pytest.mark.asyncio
async def test_login():
    auth_service, container = await get_service()

    try:
        # login with ecdsa private key signature
        data = await auth_service.login(fake_user, ecdsa_private_key)

        assert data.get('access_token') is not None

        assert auth_service.get_session_status()['is_authenticated'] == True

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_logout():
    auth_service, container = await get_service()

    try:
        # create random user
        test_number = randint(3000001, 4000000)
        test_user = f"logout_user_{test_number}"

        # register and login
        reg_data = await auth_service.register(test_user)
        await auth_service.login(test_user, reg_data['ecdsa_private_key'])

        # check session status
        assert auth_service.get_session_status()['is_authenticated'] == True

        # logout
        result = await auth_service.logout()

        # check logout status
        assert result['status'] in ['success', 'logged out locally']
        assert auth_service.get_session_status()['is_authenticated'] == False

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_get_current_user_info():
    auth_service, container = await get_service()

    try:
        # create random user
        test_number = randint(4000001, 5000000)
        test_user = f"user_info_user_{test_number}"

        # register and login
        reg_data = await auth_service.register(test_user)
        await auth_service.login(test_user, reg_data['ecdsa_private_key'])

        # get user info
        user_info = await auth_service.get_current_user_info()

        # check response structure
        assert 'id' in user_info
        assert 'username' in user_info
        assert user_info['username'] == test_user

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_get_current_user_info_unauthenticated():
    auth_service, container = await get_service()

    try:
        # try to get user info without authentication
        with pytest.raises(AuthenticationError):
            await auth_service.get_current_user_info()

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_get_public_keys():
    auth_service, container = await get_service()

    try:
        # first login
        await auth_service.login(fake_user, ecdsa_private_key)

        # get current user public keys
        user_info = await auth_service.get_current_user_info()
        user_id = user_info['id']

        public_keys = await auth_service.get_public_keys(user_id)

        # check response structure
        assert 'ecdsa_public_key' in public_keys
        assert 'ecdh_public_key' in public_keys

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_update_keys():
    auth_service, container = await get_service()

    try:
        # first login
        await auth_service.login(fake_user, ecdsa_private_key)

        # save old keys
        old_session_status = auth_service.get_session_status()

        # refresh keys
        new_keys = await auth_service.update_keys()

        # check, that keys were upd
        assert 'ecdsa_private_key' in new_keys
        assert 'ecdh_private_key' in new_keys

        # check session status
        assert auth_service.get_session_status()['is_authenticated'] == True

        # check that keys were changed
        assert new_keys['ecdsa_private_key'] != ecdsa_private_key

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_validate_session():
    auth_service, container = await get_service()

    try:
        # generate random user
        test_number = randint(1000001, 2000000)
        test_user = f"validate_session_user_{test_number}"

        # register and login
        reg_data = await auth_service.register(test_user)
        await auth_service.login(test_user, reg_data['ecdsa_private_key'])

        # check valid session
        assert await auth_service.validate_session() == True

        # check session status
        status = auth_service.get_session_status()
        assert status['is_authenticated'] == True
        assert status['has_token'] == True

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_get_session_status():
    auth_service, container = await get_service()

    try:
        # generate random user
        test_number = randint(2000001, 3000000)
        test_user = f"session_status_user_{test_number}"

        # check unauthenticated session status
        status = auth_service.get_session_status()
        assert status['is_authenticated'] == False
        assert status['has_token'] == False
        assert status['current_user'] is None
        assert status['user_id'] is None

        # register and login
        reg_data = await auth_service.register(test_user)
        await auth_service.login(test_user, reg_data['ecdsa_private_key'])

        # check authenticated session
        status = auth_service.get_session_status()
        assert status['is_authenticated'] == True
        assert status['has_token'] == True
        assert status['current_user'] == test_user
        assert status['user_id'] is not None

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_set_token():
    auth_service, container = await get_service()

    try:
        # set token manually
        test_token = "test_token_123"
        auth_service.set_token(test_token)

        # check that the token has been installed and the session is active.
        assert auth_service.get_current_token() == test_token
        assert auth_service.get_session_status()['is_authenticated'] == True
        assert auth_service.get_session_status()['has_token'] == True

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_health_check():
    auth_service, container = await get_service()

    try:
        # checking service availability
        # the service may or may not be available in the test environment
        # therefore, we simply check that the method works without errors
        is_healthy = await auth_service.health_check()
        assert isinstance(is_healthy, bool)

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_login_with_invalid_credentials():
    auth_service, container = await get_service()

    try:
        # try to login with incorrect credentials
        with pytest.raises(AuthenticationError):
            await auth_service.login("nonexistent_user", "invalid_private_key")

    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_register_existing_user():
    auth_service, container = await get_service()

    try:
        # try to register an existing user
        with pytest.raises(UserAlreadyExistsError):
            await auth_service.register(fake_user)

    finally:
        await close_container(container)
