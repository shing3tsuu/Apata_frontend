import pytest
import os
import base64
from dishka import make_async_container
from random import randint

from src.providers import AppProvider

from src.adapters.api.service import AuthHTTPService
from src.adapters.encryption.service import AbstractECDHCipher, AbstractECDSASignature

from src.adapters.encryption.service import X25519Cipher, SECP384R1Signature

number = randint(1, 1000000)
fake_user = f"fake_user{number}"

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

        print(data)

        assert data.get('id') is not None
        assert data.get('username') == fake_user
        assert data.get('ecdsa_private_key') is not None
        assert data.get('ecdh_private_key') is not None

    finally:
        await close_container(container)