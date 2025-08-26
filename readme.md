Frontend Service - Secure Messenger Client
Overview

A Flet-based desktop/mobile application providing end-to-end encrypted messaging with local data storage. The client maintains a complete encrypted message history while synchronizing with the backend service.
Architecture
Core Components

    Flet Framework: Cross-platform client application

    SQLite Database: Local encrypted message storage

    Cryptography Module: Client-side encryption/decryption

    Sync Engine: Background synchronization with backend

Security Implementation

    AES-256-GCM for message encryption

    PBKDF2 for key derivation from user password

    ECDH (P-384) for secure key exchange

    Local database encryption using SQLCipher

    Separate encryption keys for messages and database

Key Features

    Complete offline functionality

    End-to-end encrypted messaging

    Local message history

    Secure contact management

    Background synchronization

    Cross-platform support (Windows, macOS, Linux, iOS, Android)

Cryptographic Workflow

    User password derives master key via PBKDF2

    Master key encrypts/decrypts local SQLite database

    ECDH generates ephemeral session keys for each conversation

    AES-256-GCM encrypts/decrypts individual messages

    Public keys exchanged via backend for initial contact setup

Data Flow

    Outgoing Messages:

        Encrypted with recipient's public key + session key

        Stored locally in SQLite

        Pushed to backend service

        Removed from backend after 7 days

    Incoming Messages:

        Retrieved from backend during sync

        Decrypted using recipient's private key

        Stored in local encrypted SQLite database

        Delivery confirmation sent to backend

Sync Mechanism

    Periodic background synchronization

    Conflict resolution using timestamp-based approach

    Delta updates to minimize data transfer

    Retry logic for failed operations

Deployment Considerations

    Single executable output via PyInstaller

    Automatic updates mechanism

    Platform-specific packaging

    Secure storage of encryption keys

Security Advantages

    Zero Knowledge: Server never has access to decrypted messages

    Forward Secrecy: Ephemeral session keys for each conversation

    Future Proof: Cryptographic agility through client-side implementation

    Device Independence: Migration possible through encrypted backup/restore

This architecture represents a modern approach to secure messaging that prioritizes user privacy while maintaining usability across multiple platforms.
