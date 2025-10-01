from typing import List, Dict, Any, Optional
import base64
import asyncio
from datetime import datetime
import logging

from ..dao.message import MessageHTTPDAO
from .encryption import EncryptionService
from src.exceptions import MessageDeliveryError, EncryptionError


class MessageHTTPService:
    def __init__(
            self,
            message_dao: MessageHTTPDAO,
            encryption_service: EncryptionService,
            logger: logging.Logger | None = None
    ):
        self._message_dao = message_dao
        self._encryption_service = encryption_service
        self._logger = logger or logging.getLogger(__name__)

    async def send_encrypted_message(
            self,
            recipient_id: int,
            message: str,
            sender_private_key: str,
            recipient_public_key: str,
            token: str
    ) -> dict[str, Any]:
        """
        Sending an encrypted message
        Args:
            recipient_id: Recipient ID on the server
            message: Message text
            sender_private_key: Sender's private ECDH key (from the keyring)
            recipient_public_key: Recipient's public ECDH key (from the contact database)
            token: JWT authentication token
        """
        try:
            # Encrypt the message
            encrypted_message = await self._encryption_service.encrypt_message(
                message=message,
                sender_private_key=sender_private_key,
                recipient_public_key=recipient_public_key
            )

            # Send to the server
            result = await self._message_dao.send_message(
                recipient_id=recipient_id,
                message=encrypted_message,
                token=token
            )

            self._logger.info(f"Encrypted message sent to {recipient_id}")
            return result

        except Exception as e:
            self._logger.error(f"Failed to send encrypted message: {e}")
            raise MessageDeliveryError(f"Message delivery failed: {e}")

    async def receive_and_decrypt_messages(
            self,
            last_message_id: int,
            timeout: int,
            user_private_key: str,
            get_sender_public_key_func: callable,  # Function for getting the public key by sender_id
            token: str
    ) -> dict[str, Any]:
        """
        Receiving and decrypting messages
        Args:
            last_message_id: ID of the last received message
            timeout: Long-polling timeout
            user_private_key: User's private ECDH key (from the keyring)
            get_sender_public_key_func: Function (sender_id -> public_key) for obtaining sender keys
            token: JWT authentication token
        """
        try:
            # Receiving messages from the server
            messages_data = await self._message_dao.poll_messages(
                last_message_id=last_message_id,
                timeout=timeout,
                token=token
            )

            if not messages_data.get("has_messages"):
                return messages_data

            # Decrypt each message
            decrypted_messages = []
            for message in messages_data["messages"]:
                decrypted_message = await self._decrypt_single_message(
                    message=message,
                    user_private_key=user_private_key,
                    get_sender_public_key_func=get_sender_public_key_func
                )
                decrypted_messages.append(decrypted_message)

            return {
                **messages_data,
                "messages": decrypted_messages
            }

        except Exception as e:
            self._logger.error(f"Failed to receive/decrypt messages: {e}")
            raise

    async def _decrypt_single_message(
            self,
            message: dict[str, Any],
            user_private_key: str,
            get_sender_public_key_func: callable
    ) -> dict[str, Any]:
        """
        Decrypting one message
        :param message:
        :param user_private_key:
        :param get_sender_public_key_func:
        :return:
        """
        try:
            if not message.get("encrypted_content"):
                return {**message, "decryption_status": "not_encrypted"}

            # Get the sender's public key via callback
            sender_public_key = get_sender_public_key_func(message["sender_id"])
            if not sender_public_key:
                raise EncryptionError(f"No public key for sender {message['sender_id']}")

            # Decrypt the message
            decrypted_text = await self._encryption_service.decrypt_message(
                encrypted_message=base64.b64decode(message["encrypted_content"]),
                recipient_private_key=user_private_key,
                sender_public_key=sender_public_key
            )

            return {
                **message,
                "decrypted_content": decrypted_text,
                "decryption_status": "success"
            }

        except Exception as e:
            self._logger.warning(f"Failed to decrypt message {message.get('id')}: {e}")
            return {
                **message,
                "decrypted_content": None,
                "decryption_status": "failed",
                "decryption_error": str(e)
            }

    async def get_encrypted_conversation_history(
            self,
            other_user_id: int,
            limit: int,
            user_private_key: str,
            get_contact_public_key_func: callable,  # Function to get the contact's public key
            token: str
    ) -> list[dict[str, Any]]:
        """
        Getting message history with decryption
        :param other_user_id:
        :param limit:
        :param user_private_key:
        :param get_contact_public_key_func:
        :param token:
        :return:
        """
        try:
            # Getting history from the server
            history = await self._message_dao.get_conversation_history(
                other_user_id=other_user_id,
                limit=limit,
                token=token
            )

            # Deciphering history
            decrypted_history = []
            for message in history:
                if message.get("encrypted_content"):
                    decrypted_message = await self._decrypt_single_message(
                        message=message,
                        user_private_key=user_private_key,
                        get_sender_public_key_func=get_contact_public_key_func
                    )
                    decrypted_history.append(decrypted_message)
                else:
                    decrypted_history.append(message)

            return decrypted_history

        except Exception as e:
            self._logger.error(f"Failed to get conversation history: {e}")
            raise

    async def acknowledge_messages(self, message_ids: list[int], token: str) -> dict[str, Any]:
        """
        Confirmation of receipt of messages
        :param message_ids:
        :param token:
        :return:
        """
        return await self._message_dao.ack_messages(message_ids, token)
