from typing import Awaitable, Optional
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, date, time

from sqlalchemy import select, insert, update, delete
from sqlalchemy.ext.asyncio import AsyncSession
from abc import ABC
from functools import wraps
from typing import Callable, Optional
import logging

from .dao import BaseLocalUserGateway
from .dto import LOcalUserDTO, ContactDTO, MessageDTO, EncryptionKeyDTO
from src.config import load_config
from .db_manager import DatabaseManager

class LocalUserGateway(BaseLocalUserGateway):
    __slots__ = "db_manager"

    def __init__(self, db_manager: DatabaseManager, logger: logging.Logger | None = None):
        self.db_manager = db_manager
        self.logger = logger or logging.getLogger(__name__)

    async def get_user_by_id(self, user_id: int) -> UserDTO | None:
        async with self.db_manager.session() as session:
            async with self.db_manager.session() as session:
                try:
                    stmt = select(User).where(User.id == user_id)
                    result = await session.execute(stmt)
                    user = result.scalars().first()
                    if user:
                        return UserDTO(
                            id=user.id,
                            name=user.name,
                            hashed_password=user.hashed_password,
                            public_key=user.public_key
                        )
                    else:
                        return None
                except Exception as e:
                    self.logger.error(f"Error getting user by id: %s", e)
                    return None