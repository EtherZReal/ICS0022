# Password Manager Design Document

## 1. Overview
This project implements a secure password manager written in C. The application allows users to register, log in with a master password, and store credentials in a personal vault. Security is provided through password hashing, encrypted storage, input validation, and controlled access to user data. The design follows secure programming principles to protect sensitive information both in memory and at rest.

## 2. Architecture

 The application is divided into three main parts: the User Management Module, the Encryption Module, and the Storage Layer. The user interacts with the application through a command-line interface, which forwards requests to the appropriate module.

 ### User Management Module

The User Management Module is responsible for handling user registration, authentication, and access control. It manages user accounts, verifies master passwords during login, and ensures that only authenticated users can access their personal vault data.

Each user is associated with a unique account and a separate vault. Upon successful authentication, a user session is established, allowing access only to records owned by that user. Failed authentication attempts are rejected and may be subject to additional security measures such as temporary account lockouts.

Responsibilities:
- User registration
- User authentication
- Master password verification
- Session management
- Access control enforcement

 ### Encryption Module

The Encryption Module is responsible for protecting sensitive information handled by the password manager. It ensures that master passwords and stored credentials are not kept in plaintext and that confidential data remains protected if storage files are accessed by an unauthorized party.

Master passwords will be protected using bcrypt password hashing. Since user passwords only need to be verified during authentication, hashing provides a secure method of storage while reducing the risk of password disclosure if the user database is compromised.

Stored credentials must remain recoverable after successful authentication and will therefore be encrypted rather than hashed. Before credentials are written to persistent storage, they will be encrypted and can later be decrypted when accessed by an authenticated user.

Responsibilities:
- Hash master passwords using bcrypt
- Encrypt credential data before storage
- Decrypt credential data when required
- Protect sensitive information at rest

Planned Cryptographic Scheme:
- bcrypt for master password hashing
- AES-256 for credential encryption
- OpenSSL library for cryptographic operations

 ### Storage Layer

The Storage Layer is responsible for the persistent storage of user accounts and vault data. It manages reading, writing, updating, and deleting records while ensuring that sensitive information is only stored after being processed by the Encryption Module.

The Storage Layer does not perform authentication or encryption itself. Instead, it stores data that has already been validated by the User Management Module and protected by the Encryption Module.

Responsibilities:
- Store user account records
- Store encrypted credential records
- Retrieve stored data
- Update existing records
- Delete records when requested
- Maintain separate vaults for individual users

Planned File Structure:

users.dat
- Stores usernames and bcrypt password hashes

<username>.dat
- Stores encrypted credentials belonging to a specific user

Example Credential Record:

service|encrypted_username|encrypted_password

### Data Flow

The user interacts with the application through a command-line interface. User registration and login requests are handled by the User Management Module. Sensitive information is passed to the Encryption Module before being written to storage.

```text
User
 │
 ▼
User Management Module
 │
 ▼
Encryption Module
 │
 ▼
Storage Layer
```

## 3. Threat Model
### Master Password
Threat:
Mitigation:

### Vault at Rest
Threat:
Mitigation:

### Vault in Memory
Threat:
Mitigation:

### Interface
Threat:
Mitigation:

## 4. Design Decisions

### User Record Format

User account information will be stored in a dedicated file.

Format: username|bcrypt_hash

The master password itself will never be stored. Instead, a bcrypt hash of the password will be saved and used during authentication. This approach ensures that user passwords cannot be recovered from the stored authentication data if the user database is exposed. Because bcrypt is specifically designed for password storage, it provides stronger resistance against brute-force attacks than general-purpose hashing algorithms.

### Vault Format

Each user will have a separate vault file containing their stored credentials.

Format: service|encrypted_username|encrypted_password

Storing each user's credentials separately simplifies ownership enforcement and access control. The service name remains visible to allow efficient searching and listing of stored entries, while usernames and passwords are encrypted to protect sensitive account information.

### Cryptographic Scheme

Master passwords will be protected using bcrypt hashing. Since the original password only needs to be verified during login and does not need to be recovered, hashing provides a secure one-way protection mechanism.

Stored credentials will be protected using AES-256 encryption. Unlike passwords used for authentication, credentials must be recoverable after successful login. Encryption allows the original data to be securely restored when accessed by an authenticated user.

### Authentication 

The system will limit the number of consecutive failed login attempts. After three unsuccessful authentication attempts, the account will be temporarily locked for 30 minutes before additional login attempts are allowed.

This measure helps protect against password guessing and brute-force attacks while still allowing legitimate users to regain access after the lockout period has expired.

### Access Control

The password manager will enforce access control by associating each user with a separate vault. Users will only be able to access records stored within their own vault after successful authentication.

This design simplifies ownership verification and reduces the possibility of one user accessing another user's credentials. Every vault operation will be performed within the context of the currently authenticated user.

### Session and Credential Access

Users must authenticate with their master password before accessing their vault. An authenticated session will remain active for a maximum of 15 minutes of inactivity, after which the user is automatically logged out and required to authenticate again.

Passwords will not be displayed in plaintext through normal vault operations. Credential listings will display only service information and masked values unless the user requests to view a specific credential. Accessing stored passwords is considered a high-risk operation and requires re-authentication even within an active session. After successful verification of the master password, the requested credential is decrypted and displayed only for a short period before being hidden again.

This approach reduces the risk of credential exposure caused by unattended devices, abandoned sessions, or unauthorized access by individuals who gain temporary access to an authenticated system.

### Logging

The application will record important security-related events, such as successful logins, failed authentication attempts, credential additions, updates, and deletions.

Sensitive information including passwords, decrypted credentials, encryption keys, and password hashes will never be written to log files. Mainly useful for troubleshooting without creating additional security risks.

### Memory Handling

Sensitive data such as master passwords and decrypted credentials will be cleared from memory immediately after use.

Removing unnecessary copies of sensitive information reduces the risk of data exposure through memory inspection, application crashes, or memory leaks.

### Error Handling

The application will use generic user-facing error messages while recording more detailed information internally when necessary.

For example, authentication failures will not indicate whether the username or password was incorrect. Limiting the amount of information exposed through error messages reduces the risk of information disclosure and user enumeration attacks.