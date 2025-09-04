import base64
import logging
import keyring
from keyring.errors import KeyringError
from cryptography.exceptions import InvalidTag

from src.encryption.key_manager import KeyManager

class EncryptedKeyStorage:
    def __init__(
            self,
            key_manager: KeyManager | None = None,
            logger: logging.Logger | None = None
    ):
        """
        Use this class to store and retrieve encrypted private keys securely using keyring.
        Use master key (key encrypted with key from password (PBKDF2HMAC) ) to encrypt private keys.
        :param username:
        :param ecdh_cipher:
        :param ecdsa_client:
        :param key_manager:
        :param logger:
        """
        self.key_manager = key_manager or KeyManager()
        self.logger = logger or logging.getLogger(__name__)

        # Constants for naming keys in keyring
        self.MASTER_KEY_SERVICE = "apata_messenger_master_key"
        self.ECDH_KEY_SERVICE = "apata_messenger_ecdh_key"
        self.ECDSA_KEY_SERVICE = "apata_messenger_ecdsa_key"

    def is_master_key_registered(self, username: str) -> bool:
        """
        Checks if the master key is registered for the user.
        :return:
        """
        try:
            encrypted_data = keyring.get_password(self.MASTER_KEY_SERVICE, username)
            return encrypted_data is not None
        except KeyringError as e:
            self.logger.error(f"Keyring error: {e}")
            return False

    async def register_master_key(self, username: str, password: str) -> bool:
        """
        Registers a new master key and stores it encrypted
        :param username
        :param password:
        :return:
        """
        if self.is_master_key_registered(username):
            self.logger.warning("Master key already registered")
            return False

        try:
            # Generate a new master key
            master_key = await self.key_manager.generate_master_key()

            # Encrypt the master key with a password
            encrypted_master_key, salt = await self.key_manager.encrypt_master_key(master_key, password)

            # Save in keyring (combine salt + encrypted_master_key in one line)
            combined_data = base64.b64encode(salt + encrypted_master_key).decode('utf-8')
            keyring.set_password(self.MASTER_KEY_SERVICE, username, combined_data)

            return True
        except Exception as e:
            self.logger.error(f"Failed to register master key: {e}")
            return False

    async def _get_master_key(self, username: str, password: str) -> bytes | None:
        """
        Receives and decrypts the master key
        :param username
        :param password:
        :return:
        """
        try:
            # Get encrypted data from keyring
            combined_data = keyring.get_password(self.MASTER_KEY_SERVICE, username)
            if not combined_data:
                return None

            # Decode and separate the salt and encrypted master key
            decoded_data = base64.b64decode(combined_data)
            salt = decoded_data[:16]
            encrypted_master_key = decoded_data[16:]

            # Decrypting the master key
            return await self.key_manager.decrypt_master_key(
                encrypted_master_key, password, salt
            )
        except (InvalidTag, ValueError) as e:
            self.logger.error(f"Invalid password or corrupted data: {e}")
            return None
        except KeyringError as e:
            self.logger.error(f"Keyring error: {e}")
            return None

    async def store_ecdh_private_key(self, username: str, ecdh_private_key: str, password: str) -> bool:
        """
        Stores the ECDH private key in encrypted form
        :param username
        :param ecdh_private_key
        :param password:
        :return:
        """
        try:
            # We receive the master key
            master_key = await self._get_master_key(username, password)
            if not master_key:
                return False

            # Encrypt and save the private key
            encrypted_ecdh = await self.key_manager.encrypt_with_master_key(ecdh_private_key, master_key)

            # Save in keyring
            keyring.set_password(
                self.ECDH_KEY_SERVICE,
                username,
                base64.b64encode(encrypted_ecdh).decode('utf-8')
            )

            return True
        except Exception as e:
            self.logger.error(f"Failed to store ECDH private key: {e}")
            return False

    async def store_ecdsa_private_key(self, username: str, password: str, private_key_pem: str) -> bool:
        """
        Stores the ECDSA private key in encrypted form
        :param username
        :param private_key_pem:
        :param password:
        :return:
        """
        try:
            # We receive the master key
            master_key = await self._get_master_key(username, password)
            if not master_key:
                return False

            # Encrypt and save the private key
            encrypted_ecdsa = await self.key_manager.encrypt_with_master_key(
                private_key_pem.encode(), master_key
            )

            # Save in keyring
            keyring.set_password(
                self.ECDSA_KEY_SERVICE,
                username,
                base64.b64encode(encrypted_ecdsa).decode('utf-8')
            )

            return True
        except Exception as e:
            self.logger.error(f"Failed to store ECDSA private key: {e}")
            return False

    async def get_ecdh_private_key(self, username: str, password: str) -> bytes | None:
        """
        Receives and decrypts the ECDH private key
        :param username
        :param password:
        :return:
        """
        try:
            master_key = await self._get_master_key(username, password)
            if not master_key:
                return None

            # Get encrypted private key
            encrypted_ecdh = keyring.get_password(self.ECDH_KEY_SERVICE, username)
            if not encrypted_ecdh:
                return None

            # Decrypt the key
            return await self.key_manager.decrypt_with_master_key(
                base64.b64decode(encrypted_ecdh), master_key
            )
        except Exception as e:
            self.logger.error(f"Failed to get ECDH private key: {e}")
            return None

    async def get_ecdsa_private_key(self, username: str, password: str) -> str | None:
        """
        Receives and decrypts the ECDSA private key
        :param username
        :param password:
        :return:
        """
        try:
            master_key = await self._get_master_key(username, password)
            if not master_key:
                return None

            # Get encrypted private key
            encrypted_ecdsa = keyring.get_password(self.ECDSA_KEY_SERVICE, username)
            if not encrypted_ecdsa:
                return None

            # Decrypt the key
            decrypted_ecdsa = await self.key_manager.decrypt_with_master_key(
                base64.b64decode(encrypted_ecdsa), master_key
            )

            return decrypted_ecdsa.decode('utf-8')
        except Exception as e:
            self.logger.error(f"Failed to get ECDSA private key: {e}")
            return None

    def clear_storage(self, username) -> None:
        """
        Clears all user keys from storage.
        :return:
        """
        try:
            for service in [self.MASTER_KEY_SERVICE, self.ECDH_KEY_SERVICE, self.ECDSA_KEY_SERVICE]:
                try:
                    keyring.delete_password(service, username)
                except KeyringError:
                    pass
        except Exception as e:
            self.logger.error(f"Failed to clear storage: {e}")