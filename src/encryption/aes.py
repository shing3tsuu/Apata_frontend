import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag

from abc import ABC, abstractmethod
import asyncio
import logging

class BaseAES256Cipher(ABC):
    """
    Usage example:
    cipher = AES256Cipher(key)
    encrypted = await cipher.encrypt("secret")

    Warning:
    Always clear keys after use!
    """

    @abstractmethod
    async def encrypt(self, plaintext: str) -> str:
        """
        Encrypts the plaintext using AES-256-GCM
        :param plaintext:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts the ciphertext using AES-256-GCM
        :param ciphertext:
        :return:
        """
        raise NotImplementedError()

class AES256Cipher(BaseAES256Cipher):
    __slots__ = ('key', 'logger')
    
    def __init__(self, key: bytes, logger: logging.Logger | None = None):
        if len(key) != 32:
            raise ValueError("AES key must be 32 bytes long")
        self.key = key
        self.logger = logger or logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def __del__(self):
        if hasattr(self, 'key'):
            self.key = b'\x00' * 32

    async def encrypt(self, plaintext: str) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._safe_encrypt, plaintext)

    def _safe_encrypt(self, plaintext: str) -> str:
        try:
            nonce = os.urandom(12)
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
            return base64.b64encode(nonce + ciphertext + encryptor.tag).decode()
        except Exception as e:
            self.logger.error(f"Error encrypting data: {e}")
            raise

    async def decrypt(self, ciphertext: str) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._safe_decrypt, ciphertext)

    def _safe_decrypt(self, ciphertext: str) -> str:
        try:
            if not isinstance(ciphertext, str) or not ciphertext:
                self.logger.error("Invalid ciphertext")
                raise ValueError
            data = base64.b64decode(ciphertext)
            nonce = data[:12]
            ciphertext = data[12:-16]
            tag = data[-16:]

            cipher = Cipher(
                algorithms.AES(self.key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            try:
                decrypted = decryptor.update(ciphertext) + decryptor.finalize()
                return decrypted.decode()
            except InvalidTag:
                raise ValueError("Authentication failed")
        except (ValueError, IndexError) as e:
            self.logger.error(f"Invalid ciphertext format: {e}")
            raise
        except Exception as e:
            self.logger.error(f"Decryption failed: {e}")

            raise
