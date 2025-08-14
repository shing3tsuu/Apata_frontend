import pytest
from src.hashing.password_hash import PasswordHash


@pytest.fixture
def password_hasher():
    return PasswordHash(min_password_length=8)


@pytest.mark.asyncio
async def test_hash_and_verify(password_hasher):
    """Проверка хеширования и верификации."""
    password = "strong_password"
    hashed = await password_hasher.hashing(password)

    # Проверка корректного пароля
    assert await password_hasher.compare(password, hashed) is True

    # Проверка неверного пароля
    assert await password_hasher.compare("wrong_password", hashed) is False


@pytest.mark.asyncio
async def test_short_password(password_hasher):
    """Проверка реакции на короткий пароль."""
    with pytest.raises(ValueError):
        await password_hasher.hashing("short")


@pytest.mark.asyncio
async def test_invalid_hash(password_hasher):
    """Проверка обработки невалидного хеша."""
    assert await password_hasher.compare("password", "invalid_hash") is False


@pytest.mark.asyncio
async def test_empty_password(password_hasher):
    """Проверка обработки пустого пароля."""
    with pytest.raises(ValueError):
        await password_hasher.hashing("")

    assert await password_hasher.compare("", "any_hash") is False