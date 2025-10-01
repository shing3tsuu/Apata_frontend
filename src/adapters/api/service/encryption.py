from typing import Any
import base64
import logging

from src.adapters.encryption.service import AbstractAES256Cipher, AbstractECDHCipher


class EncryptionService:
    def __init__(
            self,
            ecdh_cipher: AbstractECDHCipher,
            aes_cipher: AbstractAES256Cipher,
            logger: logging.Logger | None = None
    ):
        self._ecdh_cipher = ecdh_cipher
        self._aes_cipher = aes_cipher
        self._logger = logger or logging.getLogger(__name__)

    async def encrypt_message(
            self,
            message: str,
            sender_private_key: str,
            recipient_public_key: str
    ) -> bytes:
        """
        Encrypting a message for a specific recipient
        Args:
            message: Message text
            sender_private_key: Sender's private key (from the keyring)
            recipient_public_key: Recipient's public key (from the contact database)
        """
        try:
            # Calculate the shared key using ECDH
            shared_key = await self._ecdh_cipher.derive_shared_key(
                sender_private_key,
                recipient_public_key
            )

            # Encrypt the message
            encrypted_message = await self._aes_cipher.encrypt(message, shared_key)
            return encrypted_message

        except Exception as e:
            self._logger.error(f"Message encryption failed: {e}")
            raise

    async def decrypt_message(
            self,
            encrypted_message: bytes,
            recipient_private_key: str,
            sender_public_key: str
    ) -> str:
        """
        Decrypting a message from a specific sender
        Args:
            encrypted_message: Encrypted message
            recipient_private_key: Recipient's private key (from the keyring)
            sender_public_key: Sender's public key (from the contact database)
        """
        try:
            # Calculate the shared key using ECDH (must be the same as the sender's)
            shared_key = await self._ecdh_cipher.derive_shared_key(
                recipient_private_key,
                sender_public_key
            )

            # Decrypt the message
            decrypted_message = await self._aes_cipher.decrypt(encrypted_message, shared_key)
            return decrypted_message

        except Exception as e:
            self._logger.error(f"Message decryption failed: {e}")
            raise
