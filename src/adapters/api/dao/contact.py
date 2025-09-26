from typing import List, Optional, Dict, Any
import base64
import logging

from .common import CommonHTTPClient

class ContactHTTPDAO:
    def __init__(self, http_client: CommonHTTPClient):
        self._http_client = http_client

    async def search_users(self, username: str, token: str) -> List[Dict[str, Any]]:
        self._http_client.set_auth_token(token)
        return await self._http_client.get("/get-users", params={"username": username})

    async def send_contact_request(self, sender_id: int, receiver_id: int, token: str) -> Dict[str, Any]:
        self._http_client.set_auth_token(token)
        data = {
            "sender_id": sender_id,
            "receiver_id": receiver_id
        }
        return await self._http_client.post("/send-contact-request", data)

    async def get_contact_requests(self, user_id: int, token: str) -> List[Dict[str, Any]]:
        self._http_client.set_auth_token(token)
        return await self._http_client.get("/get-contact-requests", params={"user_id": user_id})

    async def accept_contact_request(self, sender_id: int, receiver_id: int, token: str) -> Dict[str, Any]:
        self._http_client.set_auth_token(token)
        data = {
            "sender_id": sender_id,
            "receiver_id": receiver_id
        }
        return await self._http_client.put("/accept-contact-request", data)

    async def reject_contact_request(self, sender_id: int, receiver_id: int, token: str) -> Dict[str, Any]:
        self._http_client.set_auth_token(token)
        data = {
            "sender_id": sender_id,
            "receiver_id": receiver_id
        }
        return await self._http_client.put("/reject-contact-request", data)