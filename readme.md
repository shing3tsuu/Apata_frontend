Frontend Application - Secure Messenger Client
Overview

A Flet-based desktop/mobile application that provides complete end-to-end encryption for messaging. The client handles all encryption/decryption locally and maintains a full message history in an encrypted local database.
Architecture Diagram
text

User Input → Flet UI → Encryption Module → Local SQLite DB
     ↑                           ↓
     └── Decryption ←── Server Sync (HTTPS)

Key Features

    End-to-End Encryption - All messages encrypted before leaving device

    Offline Capability - Full message history stored locally

    Cross-Platform - Runs on Windows, macOS, Linux, iOS and Android

    Local Database - SQLite with encryption for message storage

    Server Synchronization - Background sync with backend service

Security Implementation
Encryption Scheme
text

User Password → PBKDF2 → Master Key → AES-GCM → Database Encryption
                             ↓
                 Session Key → AES-GCM → Message Encryption

Key Management

    Master Key - Derived from user password using PBKDF2

    Session Keys - Generated per conversation using ECDH key exchange

    Local Storage - Encrypted SQLite database using SQLCipher

Component Structure
UI Layer (Flet)

    Login/Registration screens

    Conversation list view

    Message composition interface

    Contact management

Business Logic Layer

    Authentication manager

    Message encryption/decryption

    Contact management

    Server synchronization

Data Layer

    Encrypted SQLite database

    Local key storage

    Cached server data

Database Schema
Local Messages Table

    id - Primary key

    server_id - Corresponding server message ID

    conversation_id - Thread identifier

    sender_id - Message author

    recipient_id - Message recipient

    encrypted_content - Encrypted message content

    timestamp - Message creation time

    is_delivered - Delivery status

Local Keys Table

    id - Primary key

    conversation_id - Thread identifier

    public_key - Other party's public key

    private_key - Our private key (encrypted)

    shared_secret - Derived shared secret (encrypted)

Synchronization Process

    Authenticate - Login with JWT tokens

    Download New Messages - Retrieve undelivered messages from server

    Decrypt Messages - Decrypt using local keys

    Store Locally - Save to encrypted local database

    Confirm Delivery - Notify server of successful receipt

    Upload Outgoing - Send new messages to server

Deployment Considerations

    Single Executable - PyInstaller for standalone distribution

    Auto-Updates - Mechanism for delivering client updates

    Key Backup - Optional encrypted cloud backup of keys

    Multi-Device Support - Manual transfer process between devices

Getting Started

    Install Flet: pip install flet

    Run application: python main.py

    Register new account or login

    Start secure messaging

Security Considerations

    No Key Escrow - Server never has access to decryption keys

    Forward Secrecy - Each conversation has unique session keys

    Local Storage - Messages persist only on user's device

    Verification - Key fingerprint verification for contacts