from pydantic import BaseModel, constr
from datetime import datetime
from typing import List

class LocalUserDTO(BaseModel):
    server_user_id: int
    username: str
    hashed_password: str
    ecdsa_public_key: str
    ecdh_public_key: str
    last_poll_id: int | None = None

class LocalUserResponseDTO(LocalUserDTO):
    id: int

class ContactDTO(BaseModel):
    server_user_id: int
    status: str | None = None
    username: str
    ecdh_public_key: str

class ContactResponseDTO(ContactDTO):
    id: int

class MessageDTO(BaseModel):
    server_message_id: int
    contact_id: int
    content: bytes
    timestamp: datetime
    type: str  # "text", "image", "video", "audio", "file"
    is_outgoing: bool  # True - outgoing, False - incoming
    is_delivered: bool

class MessageResponseDTO(MessageDTO):
    id: int