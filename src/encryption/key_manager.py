import os
import asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from abc import ABC, abstractmethod
import logging
from typing import Tuple
import secrets


class BaseKeyManager(ABC):
    @abstractmethod
    def derive_key_from_password(
            self,
            password: str,
            salt: bytes,
            iterations: int = 600000
    ) -> bytes:
        """
        Derive key from password (PBKDF2HMAC)
        :param password:
        :param salt:
        :param iterations:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def generate_master_key(
            self
    ) -> bytes:
        """
        Generate a random master key
        """
        raise NotImplementedError()

    @abstractmethod
    async def encrypt_with_master_key(
            self,
            data: bytes,
            master_key: bytes
    ) -> bytes:
        """
        Encrypt data using master key
        :param data:
        :param master_key:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def decrypt_with_master_key(
            self,
            encrypted_data: bytes,
            master_key: bytes
    ) -> bytes:
        """
        Decrypt data using master key
        :param encrypted_data:
        :param master_key:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def encrypt_master_key(
            self,
            master_key: bytes,
            password: str
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt master key with password
        :param master_key:
        :param password:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def decrypt_master_key(
            self,
            encrypted_master_key: bytes,
            password: str,
            salt: bytes
    ) -> bytes:
        """
        Decrypt master key with password
        :param encrypted_master_key:
        :param password:
        :param salt:
        :return:
        """
        raise NotImplementedError()


class KeyManager(BaseKeyManager):
    def __init__(self, iterations: int = 100000, logger: logging.Logger | None = None):
        self.iterations = iterations
        self.logger = logger or logging.getLogger(__name__)

    def derive_key_from_password(self, password: str, salt: bytes, iterations: int | None = None) -> bytes:
        if iterations is None:
            iterations = self.iterations

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    async def generate_master_key(self) -> bytes:
        """Generate a random 256-bit master key"""
        return secrets.token_bytes(32)

    async def encrypt_with_master_key(self, data: bytes, master_key: bytes) -> bytes:
        """Encrypt data using AES-GCM with master key"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._encrypt_with_master_key, data, master_key)

    def _encrypt_with_master_key(self, data: bytes, master_key: bytes) -> bytes:
        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(master_key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    async def decrypt_with_master_key(self, encrypted_data: bytes, master_key: bytes) -> bytes:
        """Decrypt data using AES-GCM with master key"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._decrypt_with_master_key, encrypted_data, master_key)

    def _decrypt_with_master_key(self, encrypted_data: bytes, master_key: bytes) -> bytes:
        if len(encrypted_data) < 28:  # 12 (nonce) + 16 (tag)
            raise ValueError("Invalid encrypted data")

        nonce = encrypted_data[:12]
        tag = encrypted_data[12:28]
        ciphertext = encrypted_data[28:]

        cipher = Cipher(
            algorithms.AES(master_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    async def encrypt_master_key(self, master_key: bytes, password: str) -> Tuple[bytes, bytes]:
        """Encrypt master key with password-derived key"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._encrypt_master_key, master_key, password)

    def _encrypt_master_key(self, master_key: bytes, password: str) -> Tuple[bytes, bytes]:
        salt = os.urandom(16)
        key = self.derive_key_from_password(password, salt)

        nonce = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(master_key) + encryptor.finalize()

        encrypted_data = nonce + encryptor.tag + ciphertext
        return encrypted_data, salt  # Возвращаем отдельно

    async def decrypt_master_key(self, encrypted_master_key: bytes, password: str, salt: bytes) -> bytes:
        """Decrypt master key with password"""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._decrypt_master_key, encrypted_master_key, password, salt)

    def _decrypt_master_key(self, encrypted_master_key: bytes, password: str, salt: bytes) -> bytes:
        if len(encrypted_master_key) < 28:  # 12 (nonce) + 16 (tag)
            raise ValueError("Invalid encrypted master key")

        nonce = encrypted_master_key[:12]
        tag = encrypted_master_key[12:28]
        ciphertext = encrypted_master_key[28:]

        key = self.derive_key_from_password(password, salt)

        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        try:
            return decryptor.update(ciphertext) + decryptor.finalize()
        except InvalidTag:
            raise ValueError("Invalid password or corrupted data")

    # Maintaining backward compatibility
    async def encrypt_private_key(self, private_key_pem: bytes, password: str, salt: bytes | None = None) -> bytes:
        """Legacy method for direct encryption"""
        master_key = await self.generate_master_key()
        encrypted_data = await self.encrypt_with_master_key(private_key_pem, master_key)
        encrypted_master_key, salt = await self.encrypt_master_key(master_key, password)

        # Формат: salt + encrypted_master_key + encrypted_data
        return salt + encrypted_master_key + encrypted_data

    async def decrypt_private_key(self, encrypted_data: bytes, password: str) -> bytes:
        """Legacy method for direct decryption"""
        if len(encrypted_data) < 16 + 28:  # salt (16) + minimal encrypted_master_key (28)
            raise ValueError("Invalid encrypted data")

        salt = encrypted_data[:16]
        encrypted_master_key = encrypted_data[16:16 + 28]
        encrypted_private_key = encrypted_data[16 + 28:]

        master_key = await self.decrypt_master_key(encrypted_master_key, password, salt)
        return await self.decrypt_with_master_key(encrypted_private_key, master_key)
