from typing import Any
import base64
import asyncio
from datetime import datetime

from ..dao.contact import ContactHTTPDAO

class ContactHTTPService:
    def __init__(self, contact_dao: ContactHTTPDAO):
        self._contact_dao = contact_dao

    async def search_users(self, username: str, token: str) -> list[dict[str, Any]]:
        return await self._contact_dao.search_users(username, token)

    async def send_contact_request(self, sender_id: int, receiver_id: int, token: str) -> dict[str, Any]:
        return await self._contact_dao.send_contact_request(sender_id, receiver_id, token)

    async def get_pending_requests(self, user_id: int, token: str) -> list[dict[str, Any]]:
        return await self._contact_dao.get_contact_requests(user_id, token)

    async def accept_request(self, sender_id: int, receiver_id: int, token: str) -> dict[str, Any]:
        return await self._contact_dao.accept_contact_request(sender_id, receiver_id, token)

    async def reject_request(self, sender_id: int, receiver_id: int, token: str) -> dict[str, Any]:
        return await self._contact_dao.reject_contact_request(sender_id, receiver_id, token)