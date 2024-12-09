### JWKS Server with Authentication and JWT Functionality

## Project Overview

This project implements a JSON Web Key Set (JWKS) server with user authentication, JWT issuance, and secure key management. The server is designed to:
Enable user registration and authentication.
### Objectives
Issue JWTs that can be validated using public keys provided via a .well-known/jwks.json endpoint.
Ensure security through encrypted key storage and SQL injection protection.
Apply rate limiting to prevent abuse of the /auth endpoint.

## Key Features
 **User Management**
-**Registration**: Users can register with a unique username and email. A secure password is generated and returned.
-**Authentication**: Users can log in with their username and password to receive a JWT.


-**JWT Support**
JWT Issuance: JWTs are issued upon successful authentication, signed with a shared secret (HS256 algorithm).
JWKS Endpoint: The .well-known/jwks.json endpoint provides public keys for JWT validation.

## Security Enhancements
Encrypted Key Management: Private keys are encrypted using AES before being stored in the SQLite database.
SQL Injection Protection: All database queries use parameterized queries.
Rate Limiting: Limits the number of requests to /auth to prevent abuse.
### screenshots
![WhatsApp Image 2024-12-09 at 12 40 40 AM](https://github.com/user-attachments/assets/25cb7ec5-1a72-4efe-8986-c0667304343c)
## Coverage Report
![WhatsApp Image 2024-12-09 at 12 44 43 AM](https://github.com/user-attachments/assets/c16b65eb-4330-4bb8-b4bf-76d4f8f65c13)
