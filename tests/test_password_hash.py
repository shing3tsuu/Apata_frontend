import pytest
from src.hashing.password_hash import PasswordHash


@pytest.fixture
def password_hasher():
    return PasswordHash(min_password_length=8)


@pytest.mark.asyncio
async def test_hash_and_verify(password_hasher):
    """
    Purpose: Validate password verification
    Test Cases: Correct password: compare() → True, Wrong password: compare() → False
    Key Assertions: Correct password verifies, Wrong password fails
    :param password_hasher:
    :return:
    """
    password = "strong_password"
    hashed = await password_hasher.hashing(password)

    assert await password_hasher.compare(password, hashed) is True

    assert await password_hasher.compare("wrong_password", hashed) is False


@pytest.mark.asyncio
async def test_short_password(password_hasher):
    """
    Purpose: Enforce minimum password length
    Test Case: Attempts to hash 5-character password
    Key Assertion: Raises ValueError
    :param password_hasher:
    :return:
    """
    with pytest.raises(ValueError):
        await password_hasher.hashing("short")


@pytest.mark.asyncio
async def test_invalid_hash(password_hasher):
    """
    Purpose: Handle malformed hashes
    Test Case: Compares password against invalid hash
    Key Assertion: Returns False
    :param password_hasher:
    :return:
    """
    assert await password_hasher.compare("password", "invalid_hash") is False


@pytest.mark.asyncio
async def test_empty_password(password_hasher):
    """
    Purpose: Handle empty passwords
    Test Cases: Hashing empty string → ValueError, Comparing empty password → False
    Key Assertions: Rejects empty password hashing, Empty comparison returns False
    :param password_hasher:
    :return:
    """
    with pytest.raises(ValueError):
        await password_hasher.hashing("")

    assert await password_hasher.compare("", "any_hash") is False
