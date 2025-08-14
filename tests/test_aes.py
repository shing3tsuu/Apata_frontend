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
    plaintext = "Secret message"
    encrypted = await aes_cipher.encrypt(plaintext)
    decrypted = await aes_cipher.decrypt(encrypted)
    assert decrypted == plaintext


@pytest.mark.asyncio
async def test_invalid_key():
    plaintext = "Secret message"

    # Шифрование с ключом 1
    key1 = os.urandom(32)
    cipher1 = AES256Cipher(key1)
    encrypted = await cipher1.encrypt(plaintext)

    # Попытка дешифрования с ключом 2
    key2 = os.urandom(32)
    cipher2 = AES256Cipher(key2)

    with pytest.raises(ValueError):
        await cipher2.decrypt(encrypted)


@pytest.mark.asyncio
async def test_tampered_ciphertext(aes_cipher):
    plaintext = "Secret message"
    encrypted = await aes_cipher.encrypt(plaintext)

    # Повреждаем шифротекст
    tampered = bytearray(base64.b64decode(encrypted))
    tampered[15] ^= 0x01  # Изменяем один байт
    tampered_encrypted = base64.b64encode(tampered).decode()

    with pytest.raises(ValueError):
        await aes_cipher.decrypt(tampered_encrypted)