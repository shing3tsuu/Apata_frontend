from typing import List, Optional, Dict, Any
import base64
import logging
from datetime import datetime

from .common import CommonHTTPClient
from src.exceptions import APIError, NetworkError

class MessageHTTPDAO:
    def __init__(self, http_client: CommonHTTPClient):
        self._http_client = http_client
        self._logger = logging.getLogger(__name__)

    async def send_message(self, recipient_id: int, message: bytes, token: str) -> dict[str, Any]:
        """
        Sending an encrypted message
        :param recipient_id:
        :param message:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        data = {
            "recipient_id": recipient_id,
            "message": base64.b64encode(message).decode('utf-8'),
            "timestamp": datetime.utcnow().isoformat()
        }
        return await self._http_client.post("/send", data)

    async def poll_messages(self, last_message_id: int, timeout: int, token: str) -> dict[str, Any]:
        """
        Long-polling to receive new messages
        :param last_message_id:
        :param timeout:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        params = {
            "last_message_id": last_message_id,
            "timeout": timeout
        }
        return await self._http_client.get("/poll", params=params)

    async def ack_messages(self, message_ids: List[int], token: str) -> dict[str, Any]:
        """
        Confirmation of receipt of messages
        :param message_ids:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        data = {"message_ids": message_ids}
        return await self._http_client.post("/ack", data)

    async def get_conversation_history(self, other_user_id: int, limit: int, token: str) -> list[dict[str, Any]]:
        """
        Retrieving message history
        :param other_user_id:
        :param limit:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        params = {"limit": limit}
        return await self._http_client.get(f"/history/{other_user_id}", params=params)

    async def get_unread_messages(self, token: str) -> list[dict[str, Any]]:
        """
        Receiving unread messages
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        return await self._http_client.get("/messages/unread")

    async def mark_as_read(self, message_ids: List[int], token: str) -> dict[str, Any]:
        """
        Marking messages as read
        :param message_ids:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        data = {"message_ids": message_ids}
        return await self._http_client.post("/messages/read", data)

    async def delete_message(self, message_id: int, token: str) -> dict[str, Any]:
        """
        Delete a message
        :param message_id:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        return await self._http_client.delete(f"/messages/{message_id}")

    async def edit_message(self, message_id: int, new_message: bytes, token: str) -> dict[str, Any]:
        """
        Editing a message
        :param message_id:
        :param new_message:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        data = {
            "message": base64.b64encode(new_message).decode('utf-8'),
            "edited_at": datetime.utcnow().isoformat()
        }
        return await self._http_client.put(f"/messages/{message_id}", data)

    async def get_message_status(self, message_id: int, token: str) -> dict[str, Any]:
        """
        Getting message status (delivered, read)
        :param message_id:
        :param token:
        :return:
        """
        self._http_client.set_auth_token(token)
        return await self._http_client.get(f"/messages/{message_id}/status")
