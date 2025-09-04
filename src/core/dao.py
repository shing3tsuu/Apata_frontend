from typing import Awaitable, Optional
from abc import ABC, abstractmethod

from .dto import LOcalUserDTO, ContactDTO, MessageDTO, EncryptionKeyDTO

class BaseLocalUserGateway(ABC):
    @abstractmethod
    async def get_user_by_id(self, user_id: int) -> LocalUserDTO | None:
        pass