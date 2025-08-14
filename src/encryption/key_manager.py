import os
import asyncio
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import constant_time
from abc import ABC, abstractmethod
import logging

class BaseKeyManager(ABC):
    @abstractmethod
    def derive_key_from_password(
            self,
            password: str,
            salt: bytes,
            iterations: int = 100000
    ) -> bytes:
        """
        Generates an AES key from a password
        PBKDF2 key derivation implementation
        :param password: User password
        :param salt: Cryptographic salt
        :param iterations: PBKDF2 iterations
        :return: Derived encryption key
        """
        raise NotImplementedError()

    @abstractmethod
    async def encrypt_private_key(
            self,
            private_key_pem: bytes,
            password: str,
            salt: bytes | None = None
    ) -> bytes:
        """
        Encrypts private key using password
        :param private_key_pem: Private key in PEM format
        :param password: Encryption password
        :param salt: Optional predefined salt
        :return: Tuple (encrypted_data, salt)
        """
        raise NotImplementedError()

    @abstractmethod
    async def decrypt_private_key(
            self,
            encrypted_data: bytes,
            password: str
    ) -> bytes:
        """
        Decrypts private key using password
        :param encrypted_data: Encrypted private key
        :param password: Decryption password
        :return: Decrypted private key in PEM format
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
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    async def encrypt_private_key(self, private_key_pem: bytes, password: str, salt: bytes | None = None) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._safe_encrypt_private_key, private_key_pem, password, salt)

    def _safe_encrypt_private_key(self, private_key_pem: bytes, password: str, salt: bytes | None = None) -> bytes:
        # Generate salt if not provided
        salt = salt or os.urandom(16)

        # Derive encryption key from password
        key = self.derive_key_from_password(password, salt)

        # Generate random nonce
        nonce = os.urandom(12)

        # Encrypt using AES-GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(private_key_pem) + encryptor.finalize()

        # Combine salt + nonce + tag + ciphertext
        encrypted_data = salt + nonce + encryptor.tag + ciphertext
        return encrypted_data

    async def decrypt_private_key(self, encrypted_data: bytes, password: str) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._safe_decrypt_private_key, encrypted_data, password)

    def _safe_decrypt_private_key(self, encrypted_data: bytes, password: str) -> bytes:
        if len(encrypted_data) < 44:  # 16 (salt) + 12 (nonce) + 16 (tag)
            self.logger.error(f"Invalid encrypted data")
            raise ValueError

        # Extract components from encrypted data
        salt = encrypted_data[:16]
        nonce = encrypted_data[16:28]
        tag = encrypted_data[28:44]
        ciphertext = encrypted_data[44:]

        # Derive decryption key from password
        key = self.derive_key_from_password(password, salt)

        # Decrypt using AES-GCM
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()

        try:
            # Attempt decryption and verify authentication tag
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            return decrypted
        except InvalidTag:
            self.logger.error(f"Invalid password or corrupted data")
            raise ValueError