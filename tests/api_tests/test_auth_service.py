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
        data = await auth_service.register(fake_user)

        assert data.get('id') is not None
        assert data.get('username') == fake_user
        assert data.get('ecdsa_private_key') is not None
        assert data.get('ecdh_private_key') is not None

        global ecdsa_private_key
        ecdsa_private_key = data.get('ecdsa_private_key')

        with pytest.raises(UserAlreadyExistsError):
            await auth_service.register(fake_user) # already exists

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
        global ecdsa_private_key
        data = await auth_service.login(fake_user, ecdsa_private_key)

        assert data.get('access_token') is not None

        assert auth_service.get_session_status()['is_authenticated'] == True

    finally:
        await close_container(container)
