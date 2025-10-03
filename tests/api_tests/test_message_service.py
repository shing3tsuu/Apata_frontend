import pytest
import os
import base64
import json
from dishka import make_async_container
from random import randint

from src.providers import AppProvider
from src.adapters.api.service import AuthHTTPService, MessageHTTPService
from src.exceptions import *

number1 = randint(1, 1000000)
number2 = randint(1, 1000000)
fake_user_1 = f"fake_user{number1}"
fake_user_2 = f"fake_user{number2}"


async def get_service():
    container = make_async_container(AppProvider())
    async with container() as request_container:
        auth_service = await request_container.get(AuthHTTPService)
        message_service = await request_container.get(MessageHTTPService)
        return auth_service, message_service, container


async def close_container(container):
    await container.close()

@pytest.mark.asyncio
async def test_send_and_receive_message():
    auth_service, message_service, container = await get_service()

    try:
        # register two users
        data_1 = await auth_service.register(fake_user_1)
        data_2 = await auth_service.register(fake_user_2)

        # login as user 1
        login_1 = await auth_service.login(data_1["username"], data_1["ecdsa_private_key"])
        token_1 = login_1["access_token"]

        # get user 2's public keys
        keys_2 = await auth_service.get_public_keys(data_2["id"])
        ecdh_public_key_2 = keys_2["ecdh_public_key"]

        # send encrypted message from user 1 to user 2
        message_text = "Hello, this is an encrypted message!"
        send_result = await message_service.send_encrypted_message(
            recipient_id=data_2["id"],
            message=message_text,
            sender_private_key=data_1["ecdh_private_key"],
            recipient_public_key=ecdh_public_key_2,
            token=token_1
        )

        assert "id" in send_result

        # Login as user 2
        login_2 = await auth_service.login(data_2["username"], data_2["ecdsa_private_key"])
        token_2 = login_2["access_token"]

        keys_1 = await auth_service.get_public_keys(data_1["id"])
        ecdh_public_key_1 = keys_1["ecdh_public_key"]

        # receive messages as user 2
        receive_result = await message_service.receive_messages(
            last_message_id=0,
            timeout=30,
            token=token_2
        )

        assert receive_result["has_messages"] == True
        assert len(receive_result["messages"]) > 0

        # decrypt each received message
        decrypted_messages = []
        for encrypted_message in receive_result["messages"]:
            encrypted_content = encrypted_message.get("message")

            if encrypted_content:
                try:
                    decrypted_text = await message_service.decrypt_message(
                        encrypted_message=encrypted_content,  # base64
                        user_private_key=data_2["ecdh_private_key"],
                        sender_public_key=ecdh_public_key_1
                    )

                    decrypted_messages.append({
                        "id": encrypted_message["id"],
                        "decrypted_content": decrypted_text,
                        "status": "success"
                    })

                    # verify the decrypted message matches the original
                    assert decrypted_text == message_text

                except Exception as e:
                    decrypted_messages.append({
                        "id": encrypted_message["id"],
                        "decrypted_content": None,
                        "status": "failed",
                        "error": str(e)
                    })
            else:
                decrypted_messages.append({
                    "id": encrypted_message["id"],
                    "decrypted_content": None,
                    "status": "not_encrypted"
                })

        # verify we have at least one successfully decrypted message
        success_decryptions = [msg for msg in decrypted_messages if msg["status"] == "success"]
        assert len(success_decryptions) > 0, "No messages were successfully decrypted"

        # acknowledge the messages
        message_ids = [msg["id"] for msg in receive_result["messages"]]
        ack_result = await message_service.acknowledge_messages(message_ids, token_2)
        assert "status" in ack_result

    except Exception as e:
        import traceback
        traceback.print_exc()
        pytest.fail(f"Test failed with error: {str(e)}")
    finally:
        await close_container(container)


@pytest.mark.asyncio
async def test_batch_decrypt_messages():
    auth_service, message_service, container = await get_service()

    try:
        # register two users
        data_1 = await auth_service.register(fake_user_1 + "_batch")
        data_2 = await auth_service.register(fake_user_2 + "_batch")

        # login as user 1
        login_1 = await auth_service.login(data_1["username"], data_1["ecdsa_private_key"])
        token_1 = login_1["access_token"]

        # get user 2's public keys
        keys_2 = await auth_service.get_public_keys(data_2["id"])
        ecdh_public_key_2 = keys_2["ecdh_public_key"]

        # send multiple encrypted messages
        messages_to_send = [
            "First test message",
            "Second test message",
            "Third test message"
        ]

        for msg_text in messages_to_send:
            await message_service.send_encrypted_message(
                recipient_id=data_2["id"],
                message=msg_text,
                sender_private_key=data_1["ecdh_private_key"],
                recipient_public_key=ecdh_public_key_2,
                token=token_1
            )

        # login as user 2
        login_2 = await auth_service.login(data_2["username"], data_2["ecdsa_private_key"])
        token_2 = login_2["access_token"]

        # get user 1's public keys
        keys_1 = await auth_service.get_public_keys(data_1["id"])
        ecdh_public_key_1 = keys_1["ecdh_public_key"]

        # receive messages
        receive_result = await message_service.receive_messages(
            last_message_id=0,
            timeout=30,
            token=token_2
        )

        assert receive_result["has_messages"] == True
        assert len(receive_result["messages"]) >= len(messages_to_send)

        # test batch decryption
        sender_public_keys = {
            data_1["id"]: ecdh_public_key_1
        }

        batch_result = await message_service.batch_decrypt_messages(
            encrypted_messages=receive_result["messages"],
            user_private_key=data_2["ecdh_private_key"],
            sender_public_keys=sender_public_keys
        )

        # verify all messages were processed
        assert len(batch_result) == len(receive_result["messages"])

        # check decryption status
        success_count = sum(1 for msg in batch_result if msg.get("decryption_status") == "success")

        assert success_count >= len(messages_to_send)

    except Exception as e:
        import traceback
        traceback.print_exc()
        pytest.fail(f"Batch decrypt test failed with error: {str(e)}")
    finally:
        await close_container(container)