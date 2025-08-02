from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
from abc import ABC, abstractmethod

class BaseECDHCipher(ABC):
    @abstractmethod
    def get_public_key(self) -> str:
        raise NotImplementedError()

    @abstractmethod
    def derive_shared_key(self, peer_public_key_pem: str) -> str:
        raise NotImplementedError()

class ECDHCipher(BaseECDHCipher):
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        self.public_key = self.private_key.public_key()

    def get_public_key(self) -> str:
        """Возвращает публичный ключ в формате PEM"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

    def derive_shared_key(self, peer_public_key_pem: str) -> bytes:
        """Вычисляет общий секрет с использованием публичного ключа партнера"""
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem.encode(),
            backend=default_backend()
        )

        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        # Используем HKDF для получения ключа фиксированной длины
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Длина ключа AES-256
            salt=None,
            info=b'apata_messenger_ecdh',
            backend=default_backend()
        ).derive(shared_secret)

        return derived_key