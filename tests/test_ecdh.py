import pytest
from src.encryption.ecdh import ECDHCipher

@pytest.mark.asyncio
async def test_private_key_consistency():
    """
    Purpose: Verify private key stability
    Test Case: Retrieves private key twice from same instance
    Key Assertion: private_key1 == private_key2
    :return:
    """
    cipher = ECDHCipher()
    private_key1 = cipher.get_private_key_pem()
    private_key2 = cipher.get_private_key_pem()
    assert private_key1 == private_key2


@pytest.mark.asyncio
async def test_public_key_consistency():
    """
    Purpose: Verify public key stability
    Test Case: Retrieves public key twice from same instance
    Key Assertion: public_key1 == public_key2
    :return:
    """
    cipher = ECDHCipher()
    public_key1 = cipher.get_public_key()
    public_key2 = cipher.get_public_key()
    assert public_key1 == public_key2


@pytest.mark.asyncio
async def test_shared_key_derivation():
    """
    Purpose: Validate shared secret derivation
    Test Case: Alice and Bob exchange public keys, Both derive shared secret independently
    Key Assertion: alice_shared == bob_shared
    :return:
    """
    alice = ECDHCipher()
    bob = ECDHCipher()

    alice_public = alice.get_public_key()
    bob_public = bob.get_public_key()

    alice_shared = await alice.derive_shared_key(bob_public)
    bob_shared = await bob.derive_shared_key(alice_public)

    assert alice_shared == bob_shared


@pytest.mark.asyncio
async def test_different_shared_secrets():
    """
    Purpose: Verify distinct peer secrets
    Test Case: Alice-Bob derive shared secret, Alice-Eve derive shared secret
    Key Assertion: alice_bob != alice_eve
    :return:
    """
    alice = ECDHCipher()
    bob = ECDHCipher()
    eve = ECDHCipher()

    alice_bob = await alice.derive_shared_key(bob.get_public_key())
    alice_eve = await alice.derive_shared_key(eve.get_public_key())

    assert alice_bob != alice_eve


@pytest.mark.asyncio
async def test_load_from_private_key():
    """
    Purpose: Validate PEM key loading
    Test Case: Saves original private key, Creates new instance from saved key
    Key Assertion: Loaded public key matches original
    :return:
    """
    original = ECDHCipher()
    private_key = original.get_private_key_pem()

    loaded = ECDHCipher.from_private_key_pem(private_key)

    assert loaded.get_public_key() == original.get_public_key()
