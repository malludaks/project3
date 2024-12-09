### JWKS Server with Authentication and JWT Functionality

## Project Overview

This project implements a JSON Web Key Set (JWKS) server with user authentication, JWT issuance, and secure key management. The server is designed to:
Enable user registration and authentication.
### Objectives
Issue JWTs that can be validated using public keys provided via a .well-known/jwks.json endpoint.
Ensure security through encrypted key storage and SQL injection protection.
Apply rate limiting to prevent abuse of the /auth endpoint.

## Key Features
-**User Management
Registration: Users can register with a unique username and email. A secure password is generated and returned.
Authentication: Users can log in with their username and password to receive a JWT.


JWT Support
JWT Issuance: JWTs are issued upon successful authentication, signed with a shared secret (HS256 algorithm).
JWKS Endpoint: The .well-known/jwks.json endpoint provides public keys for JWT validation.
### screenshots
## Coverage Report

Security Enhancements
Encrypted Key Management: Private keys are encrypted using AES before being stored in the SQLite database.
SQL Injection Protection: All database queries use parameterized queries.
Rate Limiting: Limits the number of requests to /auth to prevent abuse.
