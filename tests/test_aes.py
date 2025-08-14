import pytest
import os
import base64
from src.encryption.aes import AES256Cipher

@pytest.fixture
def aes_cipher():
    key = os.urandom(32)
    return AES256Cipher(key)


@pytest.mark.asyncio
async def test_encrypt_decrypt(aes_cipher):
    """
    Purpose: Validate symmetric encryption/decryption
    Test Case: Encrypts plaintext → Decrypts ciphertext → Verifies original plaintext matches
    Key Assertion: decrypted == plaintext
    :param aes_cipher:
    :return:
    """
    plaintext = "Secret message"
    encrypted = await aes_cipher.encrypt(plaintext)
    decrypted = await aes_cipher.decrypt(encrypted)
    assert decrypted == plaintext


@pytest.mark.asyncio
async def test_invalid_key():
    """
    Purpose: Verify key integrity protection
    Test Case: Encrypts with key1, Attempts decryption with unrelated key2
    Key Assertion: Raises ValueError on decryption attempt
    :return:
    """
    plaintext = "Secret message"

    key1 = os.urandom(32)
    cipher1 = AES256Cipher(key1)
    encrypted = await cipher1.encrypt(plaintext)

    key2 = os.urandom(32)
    cipher2 = AES256Cipher(key2)

    with pytest.raises(ValueError):
        await cipher2.decrypt(encrypted)


@pytest.mark.asyncio
async def test_tampered_ciphertext(aes_cipher):
    """
    Purpose: Verify authentication tag validation
    Test Case: Encrypts plaintext, Modifies 1 byte in ciphertext, Attempts decryption of tampered data
    Key Assertion: Raises ValueError during decryption
    :param aes_cipher:
    :return:
    """
    plaintext = "Secret message"
    encrypted = await aes_cipher.encrypt(plaintext)

    tampered = bytearray(base64.b64decode(encrypted))
    tampered[15] ^= 0x01
    tampered_encrypted = base64.b64encode(tampered).decode()

    with pytest.raises(ValueError):
        await aes_cipher.decrypt(tampered_encrypted)
