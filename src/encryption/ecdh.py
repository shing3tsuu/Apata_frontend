import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
import asyncio
from abc import ABC, abstractmethod

class BaseECDHCipher(ABC):
    @abstractmethod
    def get_public_key(
            self
    ) -> str:
        """
        Returns the public key in PEM format
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    def get_private_key_pem(
            self
    ) -> str:
        """
        Returns the private key in PEM format (without password)
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    def from_private_key_pem(
            self, pem_data: bytes
    ) -> 'ECDHCipher':
        """
        Creates an instance from a private key in PEM format
        :param pem_data:
        :return:
        """
        raise NotImplementedError()

    @abstractmethod
    async def derive_shared_key(
            self, peer_public_key_pem: str
    ) -> bytes:
        """
        Derives a shared key using the provided peer's public key
        :param peer_public_key_pem:
        :return:
        """
        raise NotImplementedError()

class ECDHCipher(BaseECDHCipher):
    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None, logger: logging.Logger | None = None):
        if private_key is None:
            self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        else:
            if private_key and private_key.key_size < 384:
                self.logger.error("Insecure key size")
                raise ValueError
            else:
                self.private_key = private_key
        self.public_key = self.private_key.public_key()
        self.logger = logger or logging.getLogger(__name__)

    def get_public_key(self) -> str:
        pem_data = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem_data.decode("ascii")

    def get_private_key_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    @classmethod
    def from_private_key_pem(cls, pem_data: bytes) -> 'ECDHCipher':
        private_key = serialization.load_pem_private_key(
            pem_data,
            password=None,
            backend=default_backend()
        )
        return cls(private_key)

    async def derive_shared_key(self, peer_public_key_pem: str) -> bytes:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._safe_derive_shared_key, peer_public_key_pem)

    def _safe_derive_shared_key(self, peer_public_key_pem: str) -> bytes:
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem.encode(),
            backend=default_backend()
        )

        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'apata_messenger_ecdh',
            backend=default_backend()
        ).derive(shared_secret)

        return derived_key