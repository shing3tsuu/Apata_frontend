from typing import Any
import base64
import asyncio
from datetime import datetime

from .auth import AuthHTTPService
from .encryption import EncryptionService
from ..dao.message import MessageHTTPDAO
from src.adapters.encryption.service import AbstractECDHCipher

class MessageHTTPService:
    def __init__(
            self,
            message_dao: MessageHTTPDAO,
            encryption_service: EncryptionService,
            auth_service: AuthHTTPService
    ):
        self._message_dao = message_dao
        self._encryption_service = encryption_service
        self._auth_service = auth_service

    async def send_encrypted_message(
            self,
            recipient_id: int,
            message: str,
            sender_private_key: str,
            recipient_public_key: str,
            token: str
    ) -> dict[str, Any]:
        encrypted_message = await self._encryption_service.encrypt_message(
            message, sender_private_key, recipient_public_key
        )

        return await self._message_dao.send_message(recipient_id, encrypted_message, token)

    async def receive_messages(
            self,
            last_message_id: int,
            timeout: int,
            token: str
    ) -> dict[str, Any]:
        return await self._message_dao.poll_messages(last_message_id, timeout, token)

    async def decrypt_received_messages(
            self,
            messages_data: dict[str, Any],
            user_private_key: str,
            token: str
    ) -> dict[str, Any]:
        if not messages_data.get("has_messages") or not messages_data.get("messages"):
            return messages_data

        decrypted_messages = []

        for message in messages_data["messages"]:
            if message.get("message"):
                try:
                    sender_keys = await self._auth_service.get_public_keys(
                        message["sender_id"], token
                    )
                    sender_public_key = sender_keys["ecdh_public_key"]

                    decrypted_text = await self._encryption_service.decrypt_message(
                        message["message"],
                        user_private_key,
                        sender_public_key
                    )

                    decrypted_message = {
                        **message,
                        "decrypted_message": decrypted_text,
                        "decryption_status": "success"
                    }

                except Exception as e:
                    decrypted_message = {
                        **message,
                        "decrypted_message": None,
                        "decryption_status": "failed",
                        "decryption_error": str(e)
                    }

                decrypted_messages.append(decrypted_message)
            else:
                decrypted_messages.append(message)

        return {
            **messages_data,
            "messages": decrypted_messages
        }

    async def get_conversation_history(
            self,
            other_user_id: int,
            limit: int,
            token: str
    ) -> list[dict[str, Any]]:
        return await self._message_dao.get_conversation_history(other_user_id, limit, token)

    async def acknowledge_messages(self, message_ids: list[int], token: str) -> dict[str, Any]:
        return await self._message_dao.ack_messages(message_ids, token)