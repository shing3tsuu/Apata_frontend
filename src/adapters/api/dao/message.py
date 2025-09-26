from typing import List, Optional, Dict, Any
import base64
import logging

from .common import CommonHTTPClient

class MessageHTTPDAO:
    def __init__(self, http_client: CommonHTTPClient):
        self._http_client = http_client

    async def send_message(self, recipient_id: int, message: bytes, token: str) -> dict[str, Any]:
        self._http_client.set_auth_token(token)
        data = {
            "recipient_id": recipient_id,
            "message": base64.b64encode(message).decode('utf-8')
        }
        return await self._http_client.post("/send", data)

    async def poll_messages(self, last_message_id: int, timeout: int, token: str) -> dict[str, Any]:
        self._http_client.set_auth_token(token)
        params = {
            "last_message_id": last_message_id,
            "timeout": timeout
        }
        return await self._http_client.get("/poll", params=params)

    async def ack_messages(self, message_ids: List[int], token: str) -> dict[str, Any]:
        self._http_client.set_auth_token(token)
        data = {"message_ids": message_ids}
        return await self._http_client.post("/ack", data)

    async def get_conversation_history(self, other_user_id: int, limit: int, token: str) -> list[dict[str, Any]]:
        self._http_client.set_auth_token(token)
        params = {"limit": limit}
        return await self._http_client.get(f"/history/{other_user_id}", params=params)