from ..dao.local_user import AbstractLocalUserDAO
from ..dao.common import AbstractCommonDAO
from src.adapters.database.dto import LocalUserDTO, LocalUserRequestDTO

class LocalUserService:
    def __init__(self, local_user_dao: AbstractLocalUserDAO, common_dao: AbstractCommonDAO):
        self._local_user_dao = local_user_dao
        self._common_dao = common_dao

    async def add_user(self, user: LocalUserRequestDTO) -> LocalUserDTO:
        return await self._local_user_dao.add_user(user)

    async def get_user_data(self) -> LocalUserDTO | None:
        return await self._local_user_dao.get_user_data()

    async def update_user_data(self, user: LocalUserDTO) -> LocalUserDTO | None:
        return await self._local_user_dao.update_user_data(user)