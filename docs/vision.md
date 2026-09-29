# Authentication REST API — Vision

## Purpose

Build a secure, stateless REST API for user registration, login, session refresh, logout, and retrieval of the current user.

The service combines short-lived JWT access tokens with server-side Redis sessions. JWTs provide efficient authentication for API requests, while Redis provides immediate session revocation, refresh-token rotation, logout, and session expiration.

## Goals

- Provide predictable authentication endpoints with consistent JSON responses and errors.
- Protect passwords with an established password-hashing algorithm.
- Keep session credentials opaque and prevent raw tokens from being persisted or logged.
- Make logout, session expiration, and refresh rotation take effect immediately.
- Support reliable local development and demonstration through Docker Compose.
- Verify behavior with automated unit and integration tests using real PostgreSQL and Redis instances.
- Keep all project documentation in English.

## Scope

### In scope

- User registration with email and password.
- Login with normalized email and password verification.
- Fifteen-minute JWT access tokens.
- Twenty-four-hour Redis-backed sessions.
- Atomic session-token rotation during refresh.
- Logout of an individual session.
- `GET /api/me` for the authenticated user.
- PostgreSQL persistence, Redis sessions, Nginx reverse proxy, and Docker Compose.
- Liquibase migrations, Testcontainers integration tests, and an executable curl demo.

### Out of scope for version one

- Email verification and password reset.
- Social login or external identity providers.
- Multi-factor authentication.
- Rate limiting and account lockout.
- User profile editing and account deletion.
- Administrative user management.

## Product principles

- **Fail closed:** authentication must never succeed when Redis or PostgreSQL state cannot be trusted.
- **Least exposure:** never return or log passwords, JWTs, raw session tokens, or token hashes.
- **Immediate revocation:** a deleted or expired Redis session invalidates its access tokens immediately.
- **Explicit contracts:** endpoint payloads, status codes, and error codes are stable and documented.
- **Configurable time:** token and session lifetimes are configurable for tests and demos.
- **Operational clarity:** health checks, dependency errors, request IDs, and safe logs are required.

## Definition of success

The service starts with the documented Docker Compose command, exposes only Nginx to the host, passes the complete automated test suite, and passes the demo script covering authentication success, invalid credentials, token expiration, refresh rotation, TTL behavior, concurrent refresh, and logout.
