from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import base64
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
    def derive_shared_key(
            self, peer_public_key_pem: str
    ) -> str:
        """
        Derives a shared key using the provided peer's public key
        :param peer_public_key_pem:
        :return:
        """
        raise NotImplementedError()

class ECDHCipher(BaseECDHCipher):
    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None):
        if private_key is None:
            self.private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()

    def get_public_key(self) -> str:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

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

    def derive_shared_key(self, peer_public_key_pem: str) -> bytes:
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
