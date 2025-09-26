from typing import Any, Type
import base64

from src.adapters.encryption.service import AbstractAES256Cipher, AbstractECDHCipher

class EncryptionService:
    def __init__(self, ecdh_cipher: AbstractECDHCipher, aes_cipher: AbstractAES256Cipher):
        self._ecdh_cipher = ecdh_cipher
        self._aes_cipher = aes_cipher

    async def encrypt_message(
            self,
            message: str,
            private_key: str,
            public_key: str
    ) -> bytes:
        shared_key = await self._ecdh_cipher.derive_shared_key(
            private_key,
            public_key
        )

        encrypted_message = await self._aes_cipher.encrypt(message, shared_key)
        return encrypted_message

    async def decrypt_message(
            self,
            encrypted_message: str,
            private_key: str,
            public_key: str
    ) -> str:
        shared_key = await self._ecdh_cipher.derive_shared_key(
            private_key,
            public_key
        )

        decrypted_message = await self._aes_cipher.decrypt(encrypted_message, shared_key)
        return decrypted_message