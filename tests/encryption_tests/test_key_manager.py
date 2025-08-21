import pytest
import os
from src.encryption.ecdh import ECDHCipher
from src.encryption.key_manager import KeyManager


@pytest.fixture
def key_manager():
    return KeyManager(iterations=10000)


@pytest.mark.asyncio
async def test_encrypt_decrypt(key_manager):
    """
    Purpose: Verify private key encryption cycle
    Test Case: Encrypts private key with password, Decrypts with same password
    Key Assertion: decrypted == private_key
    :param key_manager:
    :return:
    """
    ecdh = ECDHCipher()
    private_key = ecdh.get_private_key_pem()
    password = "secure_password_123"

    encrypted = await key_manager.encrypt_private_key(private_key, password)
    decrypted = await key_manager.decrypt_private_key(encrypted, password)

    assert decrypted == private_key


@pytest.mark.asyncio
async def test_wrong_password(key_manager):
    """
    Purpose: Validate password verification
    Test Case: Encrypts with password "correct_password", Attempts decryption with "wrong_password"
    Key Assertion: Raises ValueError
    :param key_manager:
    :return:
    """
    ecdh = ECDHCipher()
    private_key = ecdh.get_private_key_pem()
    password = "correct_password"

    encrypted = await key_manager.encrypt_private_key(private_key, password)

    with pytest.raises(ValueError):
        await key_manager.decrypt_private_key(encrypted, "wrong_password")


@pytest.mark.asyncio
async def test_custom_salt(key_manager):
    """
    Purpose: Verify salt handling
    Test Case: Encrypts with custom salt, Decrypts and verifies salt persistence
    Key Assertions: decrypted == private_key, encrypted[:16] == salt
    :param key_manager:
    :return:
    """
    ecdh = ECDHCipher()
    private_key = ecdh.get_private_key_pem()
    password = "password"
    salt = os.urandom(16)

    encrypted = await key_manager.encrypt_private_key(private_key, password, salt)
    decrypted = await key_manager.decrypt_private_key(encrypted, password)

    assert decrypted == private_key
    assert encrypted[:16] == salt