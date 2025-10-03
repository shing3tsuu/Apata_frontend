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
            logger: logging.Logger = None
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
        Sends an encrypted message to a recipient.
        :param recipient_id:
        :param message:
        :param sender_private_key:
        :param recipient_public_key:
        :param token:
        :return:
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
                message=encrypted_message,  # base64
                token=token
            )

            self._logger.info(f"Encrypted message sent to {recipient_id}")
            return result

        except Exception as e:
            self._logger.error(f"Failed to send encrypted message: {e}")
            raise MessageDeliveryError(f"Message delivery failed: {e}")

    async def receive_messages(
            self,
            last_message_id: int,
            timeout: int,
            token: str
    ) -> dict[str, Any]:
        """
        Get messages from the server
        last_message_id is needed to retrieve messages that were
        received without requests and to avoid unnecessary requests
        :param last_message_id:
        :param timeout:
        :param token:
        :return:
        """
        try:
            return await self._message_dao.poll_messages(
                last_message_id=last_message_id,
                timeout=timeout,
                token=token
            )
        except Exception as e:
            self._logger.error(f"Failed to receive messages: {e}")
            raise

    async def decrypt_message(
            self,
            encrypted_message: str,  # base64
            user_private_key: str,
            sender_public_key: str
    ) -> str:
        """
        Decrypts a message using the provided keys.
        :param encrypted_message:
        :param user_private_key:
        :param sender_public_key:
        :return:
        """
        try:
            return await self._encryption_service.decrypt_message(
                encrypted_message=encrypted_message,
                recipient_private_key=user_private_key,
                sender_public_key=sender_public_key
            )
        except Exception as e:
            self._logger.error(f"Failed to decrypt message: {e}")
            raise EncryptionError(f"Decryption failed: {e}")

    async def batch_decrypt_messages(
            self,
            encrypted_messages: List[dict[str, Any]],
            user_private_key: str,
            sender_public_keys: Dict[int, str]
    ) -> list[dict[str, Any]]:
        """
        Decrypts a list of messages
        :param encrypted_messages:
        :param user_private_key:
        :param sender_public_keys:
        :return:
        """
        decrypted_messages = []

        for message in encrypted_messages:
            try:
                # Receive encrypted content
                encrypted_content = message.get("message")
                if not encrypted_content:
                    decrypted_message = {**message, "decryption_status": "not_encrypted"}
                else:
                    sender_id = message["sender_id"]
                    if sender_id not in sender_public_keys:
                        raise EncryptionError(f"No public key for sender {sender_id}")

                    # Decrypt
                    decrypted_text = await self.decrypt_message(
                        encrypted_message=encrypted_content,
                        user_private_key=user_private_key,
                        sender_public_key=sender_public_keys[sender_id]
                    )

                    decrypted_message = {
                        **message,
                        "decrypted_content": decrypted_text,
                        "decryption_status": "success"
                    }

            except Exception as e:
                self._logger.warning(f"Failed to decrypt message {message.get('id')}: {e}")
                decrypted_message = {
                    **message,
                    "decrypted_content": None,
                    "decryption_status": "failed",
                    "decryption_error": str(e)
                }

            decrypted_messages.append(decrypted_message)

        return decrypted_messages

    async def get_conversation_history(
            self,
            other_user_id: int,
            limit: int,
            token: str
    ) -> list[dict[str, Any]]:
        """
        Get conversation history
        :param other_user_id:
        :param limit:
        :param token:
        :return:
        """
        try:
            return await self._message_dao.get_conversation_history(
                other_user_id=other_user_id,
                limit=limit,
                token=token
            )
        except Exception as e:
            self._logger.error(f"Failed to get conversation history: {e}")
            raise

    async def acknowledge_messages(self, message_ids: List[int], token: str) -> dict[str, Any]:
        """
        Acknowledge messages
        :param message_ids:
        :param token:
        :return:
        """
        return await self._message_dao.ack_messages(message_ids, token)
