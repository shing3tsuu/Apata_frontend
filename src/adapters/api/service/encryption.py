from typing import Any
import base64
import logging

from src.adapters.encryption.service import AbstractAES256Cipher, AbstractECDHCipher

class EncryptionService:
    def __init__(
        self,
        ecdh_cipher: AbstractECDHCipher,
        aes_cipher: AbstractAES256Cipher,
        logger: logging.Logger = None
    ):
        self._ecdh_cipher = ecdh_cipher
        self._aes_cipher = aes_cipher
        self._logger = logger or logging.getLogger(__name__)

    async def encrypt_message(
        self,
        message: str,
        sender_private_key: str,
        recipient_public_key: str
    ) -> str:
        """
        Encrypting a message for a specific recipient
        :param message:
        :param sender_private_key:
        :param recipient_public_key:
        :return:
        """
        try:
            # Calculate the shared key using ECDH
            shared_key = await self._ecdh_cipher.derive_shared_key(
                sender_private_key,
                recipient_public_key
            )

            # Encrypt the message with AES-GCM (returns a base64 string)
            encrypted_message = await self._aes_cipher.encrypt(message, shared_key)
            return encrypted_message

        except Exception as e:
            self._logger.error(f"Message encryption failed: {e}")
            raise

    async def decrypt_message(
        self,
        encrypted_message: str,  # base64 строка
        recipient_private_key: str,
        sender_public_key: str
    ) -> str:
        """
        Decrypting a message from a specific sender
        :param encrypted_message:
        :param recipient_private_key:
        :param sender_public_key:
        :return:
        """
        try:
            # Calculate the shared key using ECDH (must be the same as the sender's)
            shared_key = await self._ecdh_cipher.derive_shared_key(
                recipient_private_key,
                sender_public_key
            )

            # Decrypt the message (AESGCMCipher expects a base64 string)
            decrypted_message = await self._aes_cipher.decrypt(encrypted_message, shared_key)
            return decrypted_message

        except Exception as e:
            self._logger.error(f"Message decryption failed: {e}")
            raise
