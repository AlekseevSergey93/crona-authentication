# Crona Authentication

Spring Boot authentication service with user registration, login, JWT access tokens, and opaque Redis sessions. The service provides a REST API, stores users in PostgreSQL, stores sessions in Redis, and accepts external requests through Nginx.

## Key features

- user registration and login;
- Argon2id password hashing;
- RS256-signed JWT access tokens;
- opaque session tokens with rotation on refresh;
- atomic session updates through a Redis Lua script;
- logout with immediate session invalidation;
- protected `GET /api/me`;
- a consistent JSON error format and request IDs;
- Liquibase migrations for PostgreSQL;
- safe access logging without passwords or tokens;
- a Docker Compose environment with PostgreSQL, Redis, and Nginx;
- unit and Testcontainers integration tests.

## Project modules

### `auth`

REST API and orchestration services for authentication use cases:

- `POST /api/auth/register`;
- `POST /api/auth/login`;
- `POST /api/auth/refresh`;
- `POST /api/auth/logout`.

### `user`

User domain, JPA repository, and current-user endpoint:

- `GET /api/me`.

### `common/security`

Shared security components:

- `JwtTokenService`;
- `SessionTokenService`;
- `RedisSessionRepository`;
- `BearerAuthenticationFilter`;
- Argon2id password hashing;
- active Redis session checks for protected requests.

### `common/validation`

Email normalization and password validation policies.

### `common/error` and `common/web`

Common error responses, exception handling, request IDs, security error responses, and safe access logging.

### `config`

Spring Security configuration, application properties, CORS/security policy, and production configuration validation.

### `db/changelog`

Versioned Liquibase changesets for the PostgreSQL schema.

### `nginx`

Reverse proxy for API requests. Nginx is the only service that publishes a host port.

### `scripts`

Runnable authentication demo:

```bash
./scripts/demo-auth.sh http://localhost:8088
```

## Requirements

- Java 21 or newer;
- Maven;
- Docker Desktop and Docker Compose;
- for the demo: `curl`, `jq`, and Python 3.

## Run with Docker Compose

Generate JWT RSA keys without adding them to Git:

```bash
mkdir -p secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out secrets/jwt-private.pem
openssl rsa -in secrets/jwt-private.pem -pubout \
  -out secrets/jwt-public.pem
```

Create the environment file:

```bash
cp .env.example .env
```

Start all services:

```bash
docker compose up --build
```

The API will be available through Nginx at `http://localhost:8088`.

Check the Nginx health endpoint:

```bash
curl http://localhost:8088/nginx-health
```

Run the complete authentication API demo:

```bash
ACCESS_TOKEN_TTL=5s SESSION_TTL=20s docker compose up --build -d
EXPECTED_SESSION_TTL_SECONDS=20 ACCESS_TOKEN_WAIT_SECONDS=6 \
  ./scripts/demo-auth.sh http://localhost:8088
```

Stop the environment:

```bash
docker compose down
```

## Run locally with Maven

Local execution requires running PostgreSQL and Redis instances. Configure the connections with environment variables:

```bash
export DATABASE_URL='jdbc:postgresql://localhost:5432/auth'
export DATABASE_USERNAME='auth'
export DATABASE_PASSWORD='auth'
export REDIS_HOST='localhost'
export REDIS_PORT='6379'
export JWT_PRIVATE_KEY_PATH="$PWD/secrets/jwt-private.pem"
export JWT_PUBLIC_KEY_PATH="$PWD/secrets/jwt-public.pem"
```

Start the application:

```bash
mvn spring-boot:run
```

Liquibase applies the migrations automatically during application startup.

## Testing

Run unit and integration tests:

```bash
mvn test
```

Run the Testcontainers integration suite separately:

```bash
mvn -Dtest=AuthenticationIntegrationTest test
```

Additional automated verification instructions are available in [`docs/verification.md`](docs/verification.md). The complete implementation checklist is available in [`docs/implementation-checklist.md`](docs/implementation-checklist.md).

## API contract

The application uses Spring Boot 4, Spring Web, Spring Security, Spring Data JPA, Spring Data Redis, Liquibase, and Nimbus JOSE. PostgreSQL stores users, Redis stores active sessions, and Nginx is the public reverse proxy.

Email addresses are normalized by trimming surrounding whitespace and lowercasing with `Locale.ROOT` before validation and persistence. Passwords are not trimmed or normalized. The default password policy is 12–128 Unicode code points and is configurable with `PASSWORD_MIN_LENGTH` and `PASSWORD_MAX_LENGTH`.

### Authentication endpoints

`POST /api/auth/register` and `POST /api/auth/login` accept:

```json
{
  "email": "user@example.com",
  "password": "correct horse battery staple"
}
```

Successful registration returns `201 Created`; successful login returns `200 OK`:

```json
{
  "accessToken": "<RS256 JWT>",
  "sessionToken": "<opaque token>",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

`POST /api/auth/refresh` and `POST /api/auth/logout` accept:

```json
{
  "sessionToken": "<opaque token>"
}
```

Refresh returns `200 OK` with a new access token and replacement session token. The previous session token is immediately rejected. Logout returns `204 No Content` and is idempotent for missing, malformed, expired, or already deleted sessions.

`GET /api/me` requires the HTTP `Authorization` header with the `Bearer` scheme and the access token value, and returns `200 OK`:

```json
{
  "id": "00000000-0000-0000-0000-000000000000",
  "email": "user@example.com"
}
```

### Status and error codes

| Status | Codes | Meaning |
|---|---|---|
| `201` | — | User registered |
| `200` | — | Login, refresh, or current-user request succeeded |
| `204` | — | Logout completed |
| `400` | `VALIDATION_ERROR` | Invalid JSON, email, or password |
| `401` | `INVALID_CREDENTIALS` | Login credentials are invalid |
| `401` | `INVALID_SESSION` | Refresh token is missing, malformed, expired, deleted, or replaced |
| `401` | `UNAUTHORIZED` | Access token is missing, invalid, expired, revoked, or mismatched |
| `409` | `USER_ALREADY_EXISTS` | Normalized email is already registered |
| `503` | `DEPENDENCY_UNAVAILABLE` | PostgreSQL or Redis is unavailable |
| `500` | `INTERNAL_ERROR` | Unexpected server failure |

Errors use this JSON shape:

```json
{
  "timestamp": "2026-09-30T12:00:00Z",
  "status": 401,
  "code": "UNAUTHORIZED",
  "message": "Authentication is required",
  "requestId": "request-id"
}
```

## Session design

Each login or registration creates a Redis key `auth:session:{sessionId}` with a configured 24-hour default TTL. The hash contains only:

- `userId`;
- `sessionTokenHash`, a SHA-256 digest of the opaque session token.

The session token contains a format version, the 16-byte session UUID, and 32 cryptographically secure random bytes encoded as unpadded Base64 URL text. The token is only a lookup hint plus secret; the raw token is never stored.

For refresh or logout, the application extracts the session ID from the token, loads the corresponding Redis key, and compares the submitted token digest with the stored digest. A session ID by itself is not accepted as a credential. Protected requests validate the JWT signature, issuer, and expiration, then check that the JWT session ID still exists in Redis and belongs to the JWT subject. Therefore logout or Redis expiration immediately blocks an otherwise unexpired JWT.

Refresh uses a Redis Lua compare-and-set operation. It checks the active key, positive TTL, user ID, and current digest, then replaces the digest and resets the TTL in one atomic operation. Concurrent requests using one token produce exactly one successful rotation. Ordinary API requests do not extend the TTL. Access tokens issued before refresh remain valid until their own expiration while the session remains active.

The application fails closed when Redis is unavailable: it returns `503 DEPENDENCY_UNAVAILABLE` for operations that require session persistence and never issues authentication tokens in that situation. Registration compensates a successfully persisted user if session creation fails, so an unusable account is not left behind.

## Design trade-offs and unfinished work

The session token embeds the session ID to avoid a secondary Redis index, at the cost of exposing an opaque identifier in the credential format. The identifier is not secret and cannot authorize a request without the random secret and stored digest. RSA keys are file-backed Compose secrets so the public key can be used for validation without sharing the private key with other services. Rate limiting, TLS, email verification, password reset, social login, roles, and cloud deployment are intentionally out of scope.

The remaining verification item is an explicit build/test run on the documented minimum Java 21 runtime; the current environment uses a newer JDK. The demo script requires Docker Compose, `curl`, `jq`, and Python 3 and accepts `EXPECTED_SESSION_TTL_SECONDS` and `ACCESS_TOKEN_WAIT_SECONDS` to match shortened demo lifetimes.

## Assistance disclosure

The implementation and verification were developed with significant AI coding assistance. The final design, code changes, tests, and security decisions were reviewed against the assignment requirements.

## Security

The service does not store raw session tokens in Redis or log passwords, JWTs, session tokens, token hashes, or the `Authorization` header. The production profile requires accessible RSA keys and positive TTL values.
