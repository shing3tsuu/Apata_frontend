from sqlalchemy import ForeignKey, String, Text, DateTime, Boolean, Index, BigInteger, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from datetime import datetime
from typing import List, Optional

class Base(DeclarativeBase):
    """
    frontend (flet)
    """
    pass

class LocalUser(Base):
    __tablename__ = "local_users"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    hashed_password: Mapped[str] = mapped_column(String(100), nullable=False)
    ecdsa_public_key: Mapped[str] = mapped_column(Text)
    ecdh_public_key: Mapped[str] = mapped_column(Text)

    sent_messages: Mapped[List["Message"]] = relationship(
        back_populates="sender",
        foreign_keys="Message.sender_id"
    )
    received_messages: Mapped[List["Message"]] = relationship(
        back_populates="recipient",
        foreign_keys="Message.recipient_id"
    )

class Contact(Base):
    __tablename__ = "contacts"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50))
    public_key: Mapped[str] = mapped_column(Text)  # Public key contact
    last_seen: Mapped[Optional[datetime]] = mapped_column(DateTime)

    sent_messages: Mapped[List["Message"]] = relationship(
        back_populates="sender_contact",
        foreign_keys="Message.sender_id"
    )
    received_messages: Mapped[List["Message"]] = relationship(
        back_populates="recipient_contact",
        foreign_keys="Message.recipient_id"
    )

class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(primary_key=True)
    server_message_id: Mapped[int]  # Message ID on the server
    sender_id: Mapped[int] = mapped_column(ForeignKey("contacts.id"))
    recipient_id: Mapped[int] = mapped_column(ForeignKey("contacts.id"))
    content: Mapped[bytes] = mapped_column(LargeBinary) # Encrypted message data
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_read: Mapped[bool] = mapped_column(default=False)
    type: Mapped[str] = mapped_column(String(20))  # "text", "image", "file"

    sender_contact: Mapped["Contact"] = relationship(
        back_populates="sent_messages",
        foreign_keys=[sender_id]
    )
    recipient_contact: Mapped["Contact"] = relationship(
        back_populates="received_messages",
        foreign_keys=[recipient_id]
    )

class EncryptionKey(Base):
    __tablename__ = "encryption_keys"
    id: Mapped[int] = mapped_column(primary_key=True)
    wrapped_key: Mapped[bytes] = mapped_column(LargeBinary)  # Key encrypted with password
    algorithm: Mapped[str] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

