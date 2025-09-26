from ..dao.message import AbstractMessageDAO
from ..dao.common import AbstractCommonDAO
from src.adapters.database.dto import MessageDTO, MessageRequestDTO

class MessageService:
    def __init__(self, message_dao: AbstractMessageDAO, common_dao: AbstractCommonDAO):
        self._message_dao = message_dao
        self._common_dao = common_dao

    async def add_message(self, message: MessageRequestDTO) -> MessageDTO:
        return await self._message_dao.add_message(message)

    async def get_messages(self, contact_id: int, limit: int | None = None) -> list[MessageDTO]:
        return await self._message_dao.get_messages(contact_id=contact_id, limit=limit)

    async def delete_message(self, message_id: int) -> bool:
        return await self._message_dao.delete_message(message_id)