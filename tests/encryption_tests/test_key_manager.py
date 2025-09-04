import pytest
import os
from src.encryption.ecdh import X25519Cipher
from src.encryption.key_manager import KeyManager


@pytest.fixture
def key_manager():
    return KeyManager(iterations=60000)
