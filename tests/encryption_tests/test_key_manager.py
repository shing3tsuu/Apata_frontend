import pytest
import os

from src.adapters.encryption.service import KeyManager

@pytest.fixture
def key_manager():
    return KeyManager(iterations=60000)

