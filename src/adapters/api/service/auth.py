from typing import List, Any
import base64
import asyncio
from datetime import datetime

from ..dao.auth import AuthHTTPDAO
from src.adapters.encryption.service import AbstractECDSASignature, AbstractECDHCipher


class AuthHTTPService:
    def __init__(
            self,
            auth_dao: AuthHTTPDAO,
            ecdsa_signer: AbstractECDSASignature,
            ecdh_cipher: AbstractECDHCipher
    ):
        self._auth_dao = auth_dao
        self._ecdsa_signer = ecdsa_signer
        self._ecdh_cipher = ecdh_cipher

    async def register(self, username: str) -> dict[str, Any]:
        ecdsa_private, ecdsa_public = await self._ecdsa_signer.generate_key_pair()
        ecdh_private, ecdh_public = await self._ecdh_cipher.generate_key_pair()

        result = await self._auth_dao.register_user(username, ecdsa_public, ecdh_public)

        return {
            **result,
            "ecdsa_private_key": ecdsa_private,
            "ecdh_private_key": ecdh_private
        }

    async def login(self, username: str, ecdsa_private_key: str) -> dict[str, Any]:
        challenge_data = await self._auth_dao.get_challenge(username)
        challenge = challenge_data["challenge"]

        signature = await self._ecdsa_signer.sign_message(ecdsa_private_key, challenge)

        return await self._auth_dao.login(username, signature)

    async def get_user_info(self, token: str) -> dict[str, Any]:
        return await self._auth_dao.get_current_user(token)

    async def get_public_keys(self, user_id: int, token: str) -> dict[str, Any]:
        return await self._auth_dao.get_public_keys(user_id, token)

    async def update_keys(self, token: str) -> dict[str, Any]:
        ecdsa_private, ecdsa_public = await self._ecdsa_signer.generate_key_pair()
        ecdh_private, ecdh_public = await self._ecdh_cipher.generate_key_pair()

        await self._auth_dao.update_ecdsa_key(ecdsa_public, token)
        await self._auth_dao.update_ecdh_key(ecdh_public, token)

        return {
            "ecdsa_private_key": ecdsa_private,
            "ecdh_private_key": ecdh_private
        }