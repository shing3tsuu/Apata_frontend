from pydantic import BaseModel, constr
from datetime import datetime
from typing import List

class LocalUserDTO(BaseModel):
    id: int
    name: constr(min_length=3, max_length=30)

class ContactDTO(BaseModel):
    id: int
    name: str
    public_key: str
    last_seen: datetime

class MessageDTO(BaseModel):
    id: int
    server_message_id: int
    sender_id: int
    receiver_id: int
    content: bytes
    timestamp: datetime
    is_read: bool
    type: constr(min_length=3, max_length=30)

class EncryptionKeyDTO(BaseModel):
    id: int
    wrapper_key: str
    algorithm: str
    created_at: datetime