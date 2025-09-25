from sqlalchemy import ForeignKey, String, Text, DateTime, Boolean, Index, BigInteger, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime
from typing import List, Optional

class Base(DeclarativeBase):
    pass

class LocalUser(Base):
    __tablename__ = "local_users"

    __table_args__ = (
        Index('ix_local_users_server_user_id', 'server_user_id', unique=True),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    server_user_id: Mapped[int] = mapped_column(BigInteger)  # ID on server
    username: Mapped[str] = mapped_column(String(50))
    hashed_password: Mapped[str] = mapped_column(String(100), nullable=False) # bcrypt hashed password
    ecdsa_public_key: Mapped[str] = mapped_column(Text)
    ecdh_public_key: Mapped[str] = mapped_column(Text)
    last_poll_id: Mapped[int] = mapped_column(default=0)  # last message pool id

class Contact(Base):
    __tablename__ = "contacts"

    __table_args__ = (
        Index('ix_contacts_server_user_id', 'server_user_id'),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    server_user_id: Mapped[int] = mapped_column(BigInteger)  # ID contact in server
    status: Mapped[Optional[str]]
    username: Mapped[str] = mapped_column(String(50))
    ecdh_public_key: Mapped[str] = mapped_column(Text)

    messages: Mapped[List["Message"]] = relationship(
        "Message",
        back_populates="contact",
        foreign_keys="Message.contact_id"
    )

class Message(Base):
    __tablename__ = "messages"

    __table_args__ = (
        Index('ix_messages_contact_timestamp', 'contact_id', 'timestamp'),
        Index('ix_messages_server_message_id', 'server_message_id', unique=True),
        Index('ix_messages_is_outgoing', 'is_outgoing'),
        Index('ix_messages_is_delivered', 'is_delivered'),
        Index('ix_messages_timestamp', 'timestamp'),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    server_message_id: Mapped[int]  # ID message on server
    contact_id: Mapped[int] = mapped_column(ForeignKey("contacts.id"))
    content: Mapped[bytes] = mapped_column(LargeBinary)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    type: Mapped[str] = mapped_column(String(20)) # "text", "image", "video", "audio", "file"
    is_outgoing: Mapped[bool]  # True - outgoing, False - incoming
    is_delivered: Mapped[bool] = mapped_column(default=False)

    contact: Mapped["Contact"] = relationship(
        back_populates="messages",
        foreign_keys=[contact_id]
    )

