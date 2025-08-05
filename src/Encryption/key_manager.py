import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
from abc import ABC, abstractmethod


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
    def encrypt_private_key(
            self,
            private_key_pem: bytes,
            password: str,
            salt: bytes | None = None
    ) -> tuple[bytes, bytes]:
        """
        Encrypts private key using password
        :param private_key_pem: Private key in PEM format
        :param password: Encryption password
        :param salt: Optional predefined salt
        :return: Tuple (encrypted_data, salt)
        """
        raise NotImplementedError()

    @abstractmethod
    def decrypt_private_key(
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
    def __init__(self, iterations: int = 100000):
        self.iterations = iterations

    def derive_key_from_password(
            self,
            password: str,
            salt: bytes,
            iterations: int | None = None
    ) -> bytes:
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

    def encrypt_private_key(
            self,
            private_key_pem: bytes,
            password: str,
            salt: bytes | None = None
    ) -> tuple[bytes, bytes]:
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
        return encrypted_data, salt

    def decrypt_private_key(
            self,
            encrypted_data: bytes,
            password: str
    ) -> bytes:
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
            raise ValueError("Invalid password or corrupted data")