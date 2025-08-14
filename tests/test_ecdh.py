import pytest
from src.encryption.ecdh import ECDHCipher

@pytest.mark.asyncio
async def test_private_key_consistency():
    cipher = ECDHCipher()
    private_key1 = cipher.get_private_key_pem()
    private_key2 = cipher.get_private_key_pem()
    assert private_key1 == private_key2


@pytest.mark.asyncio
async def test_public_key_consistency():
    cipher = ECDHCipher()
    public_key1 = cipher.get_public_key()
    public_key2 = cipher.get_public_key()
    assert public_key1 == public_key2


@pytest.mark.asyncio
async def test_shared_key_derivation():
    alice = ECDHCipher()
    bob = ECDHCipher()

    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()

    alice_shared = await alice.derive_shared_key(bob_public)
    bob_shared = await bob.derive_shared_key(alice_public)

    assert alice_shared == bob_shared


@pytest.mark.asyncio
async def test_different_shared_secrets():
    alice = ECDHCipher()
    bob = ECDHCipher()
    eve = ECDHCipher()

    alice_bob = await alice.derive_shared_key(bob.get_public_key())
    alice_eve = await alice.derive_shared_key(eve.get_public_key())

    assert alice_bob != alice_eve


@pytest.mark.asyncio
async def test_load_from_private_key():
    original = ECDHCipher()
    private_key = original.get_private_key_pem()

    loaded = ECDHCipher.from_private_key_pem(private_key)

    assert loaded.get_public_key() == original.get_public_key()