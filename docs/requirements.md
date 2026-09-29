# Authentication REST API — Requirements

## Technology requirements

- Java 21.
- Spring Boot 3.x with Spring Web, Spring Validation, Spring Data JPA, Spring Data Redis, and Spring Security.
- PostgreSQL 16.
- Redis 7.
- Nimbus JOSE JWT through Spring Security OAuth2 Resource Server or an equivalent maintained library.
- Argon2id through Spring Security's `PasswordEncoder`.
- Bouncy Castle runtime support for Argon2id.
- Liquibase database migrations.
- Nginx and Docker Compose.
- Maven and Testcontainers.

## Common rules

- Use UTF-8 JSON and UTC timestamps.
- Normalize emails by trimming leading/trailing whitespace and converting to lowercase using `Locale.ROOT`.
- Do not apply provider-specific email canonicalization.
- Do not trim or normalize passwords.
- Password length: 12 to 128 Unicode code points.
- Reject email values that do not contain a non-whitespace local part, `@`, and a dotted non-whitespace domain.
- Session tokens are opaque, non-JWT credentials containing at least 32 cryptographically secure random bytes, encoded as unpadded Base64 URL-safe text.
- Never persist or log raw session tokens, JWTs, passwords, password hashes, authorization headers, or Redis token hashes.
- Access-token lifetime defaults to 15 minutes.
- Redis-session TTL defaults to 24 hours.
- Both lifetimes must be configurable.

## PostgreSQL requirements

Create a `users` table:

| Column | Type | Constraints |
|---|---|---|
| `id` | `uuid` | primary key |
| `email` | `varchar(320)` | not null |
| `password_hash` | `varchar(255)` | not null |
| `created_at` | `timestamptz` | not null |
| `updated_at` | `timestamptz` | not null |

Create a database-level unique index named `users_email_uq` on normalized `email`. Convert uniqueness violations, including concurrent registration races, to `409 USER_ALREADY_EXISTS`.

Liquibase must apply the initial migration automatically during application startup. Use a versioned root changelog and include changesets for the users table, indexes, and future schema changes. Changesets must be immutable after deployment.

The user domain entity must generate its UUID in the application, normalize and validate email by trimming and lowercasing with `Locale.ROOT`, store only the password hash, and maintain UTC `created_at` and `updated_at` timestamps. Repository lookups must use normalized email values. A violation of `users_email_uq` must map to `409 USER_ALREADY_EXISTS`; unrelated integrity failures must not be reported as duplicate users.

Raw passwords must satisfy the configured 12–128 Unicode code-point policy before hashing. Passwords must not be trimmed or normalized; whitespace is valid password content.

Use a Spring-managed `Argon2PasswordEncoder` for all password hashing and verification. Generate a fresh salt for every hash and persist the complete encoded Argon2id value. Never compare hashes with string equality, and never expose or log raw passwords or password hashes.

## Redis session requirements

Use the key:

```text
auth:session:{sessionId}
```

Store a Redis hash containing:

```text
userId: <UUID>
sessionTokenHash: <HMAC-SHA-256 or SHA-256 digest>
```

Never store the raw session token. Set the configured TTL when creating a session and verify that the key remains active when reading it.

`sessionId` is a randomly generated UUID. It is not the session token and must not authorize refresh or logout by itself.

## JWT requirements

Sign access tokens with a pinned asymmetric algorithm, RS256 or ES256. Supply the private key through a secret or mounted file and validate tokens with the public key.

Every access token must contain:

```json
{
  "sub": "<userId>",
  "sid": "<sessionId>",
  "iat": 0,
  "exp": 0,
  "iss": "crona-authentication"
}
```

Protected requests must validate the signature, issuer, and expiration, then verify that the Redis session exists and that its `userId` matches `sub`. A valid JWT without an active Redis session must be rejected.

## API requirements

### `POST /api/auth/register`

Request:

```json
{ "email": "user@example.com", "password": "correct horse battery staple" }
```

Return `201 Created` with:

```json
{
  "accessToken": "<JWT>",
  "sessionToken": "<opaque-token>",
  "tokenType": "Bearer",
  "expiresIn": 900
}
```

Normalize and validate the email, validate and hash the password, persist the user, create a Redis session, and issue a JWT referencing the same session ID. Return `400 VALIDATION_ERROR` for invalid input, `409 USER_ALREADY_EXISTS` for duplicate email, and `503 DEPENDENCY_UNAVAILABLE` when a required dependency is unavailable.

### `POST /api/auth/login`

Accept the same request body as registration. On success, return `200 OK` with the same token response. Unknown users and incorrect passwords must both return `401 INVALID_CREDENTIALS`. Each successful login creates a new independent session.

### `POST /api/auth/refresh`

Request:

```json
{ "sessionToken": "<current-opaque-token>" }
```

Return `200 OK` with a new access token and a different session token. The new JWT keeps the same session ID.

Refresh must be atomic:

1. Derive the session ID from the opaque token and locate the Redis hash.
2. Compare the submitted token digest with `sessionTokenHash`.
3. On failure, change neither the token hash nor TTL.
4. On success, atomically replace the stored digest and reset TTL to exactly `SESSION_TTL`.
5. Issue credentials only after the atomic replacement succeeds.

Two concurrent refreshes using the same token must produce exactly one success. The replaced token must be rejected immediately. Missing, malformed, invalid, expired, or deleted tokens return `401 INVALID_SESSION`. A JWT or session ID alone must never authorize refresh.

### `POST /api/auth/logout`

Request:

```json
{ "sessionToken": "<current-opaque-token>" }
```

Delete the identified Redis session and return `204 No Content`. Logout must immediately block access and refresh for that session. Logout is idempotent for an already missing or expired session. Redis failure returns `503 DEPENDENCY_UNAVAILABLE`.

### `GET /api/me`

Require:

```http
Authorization: Bearer <accessToken>
```

Return `200 OK`:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "user@example.com"
}
```

Missing, malformed, expired, or tampered JWTs, missing Redis sessions, and user-ID mismatches return `401 UNAUTHORIZED`. Redis failure returns `503 DEPENDENCY_UNAVAILABLE`.

## Error contract

Return errors in this format:

```json
{
  "timestamp": "2026-09-29T08:18:24Z",
  "status": 401,
  "code": "INVALID_CREDENTIALS",
  "message": "Invalid email or password",
  "requestId": "..."
}
```

Nginx or the application must generate/propagate `requestId`. Do not reveal account existence through error messages.

## Configuration requirements

Provide `.env.example` without usable secrets:

```dotenv
SERVER_PORT=8080
DATABASE_URL=jdbc:postgresql://postgres:5432/auth
DATABASE_USERNAME=auth
DATABASE_PASSWORD=change-me
REDIS_HOST=redis
REDIS_PORT=6379
JWT_ISSUER=crona-authentication
JWT_PRIVATE_KEY_PATH=/run/secrets/jwt-private.pem
JWT_PUBLIC_KEY_PATH=/run/secrets/jwt-public.pem
ACCESS_TOKEN_TTL=PT15M
SESSION_TTL=PT24H
PASSWORD_MIN_LENGTH=12
```

## Docker Compose requirements

The Compose file must contain exactly four runtime services:

1. `app`: Java application on internal port `8080`, with an application healthcheck.
2. `postgres`: PostgreSQL 16, persistent `postgres-data` volume, and `pg_isready` healthcheck.
3. `redis`: Redis 7 with `redis-cli ping` healthcheck.
4. `nginx`: the only service with a host `ports` mapping, proxying to `app:8080`.

Use `depends_on` health conditions, a multi-stage application image, a non-root runtime user, and automatic Liquibase migrations. Document:

```bash
cp .env.example .env
docker compose up --build
```

## Tests and demo script

Provide automated backend tests covering successful authentication and important failure cases, including concurrent refresh. Include integration coverage using actual PostgreSQL and Redis instances; Testcontainers is recommended.

### Automated backend tests

Unit tests must cover:

- email normalization;
- password length validation and Argon2id hashing;
- JWT claims, signature, issuer, and expiration validation;
- cryptographically secure session-token generation and digesting;
- common error mapping and secret redaction.

Integration tests must use real PostgreSQL and Redis through Testcontainers and cover:

- successful registration and login;
- database-level email uniqueness, including concurrent duplicate registration;
- incorrect credentials;
- protected access with a valid JWT;
- missing, malformed, expired, and tampered JWTs;
- deleted and expired Redis sessions invalidating otherwise unexpired JWTs;
- refresh token rotation and preservation of the session ID;
- rejection of the previous session token after refresh;
- invalid, missing, malformed, expired, and deleted session tokens;
- session TTL behavior;
- concurrent refresh requests;
- logout and isolation of other sessions;
- controlled failures when PostgreSQL or Redis is unavailable.

### Runnable curl demo

Provide an executable `scripts/demo-auth.sh` with assertions. It must use `curl` and `jq`, or document and implement a portable alternative. It may run against a stack configured with shortened lifetimes and may inspect Redis using `docker compose exec`.

Document the exact commands:

```bash
cp .env.example .env
ACCESS_TOKEN_TTL=5s SESSION_TTL=20s docker compose up --build -d
./scripts/demo-auth.sh http://localhost:8088
```

The script must demonstrate all of the following:

1. Register a user, verify that the returned JWT immediately grants access to `/api/me`, and reject duplicate registration.
2. Reject an incorrect password.
3. Log in and call `/api/me`.
4. Reject access without valid authentication, including a tampered JWT.
5. Let an access token expire, refresh with the current session token, and call `/api/me` with the new JWT. Verify that:
   - refresh returns a different session token;
   - the previous session token is rejected;
   - the new session token works for the next refresh;
   - a successful refresh resets the session TTL to the full configured duration;
   - ordinary API requests do not extend the session TTL;
   - failed refreshes do not extend or otherwise modify the session.
6. Reject refresh with an invalid session token and after the session expires. Send two concurrent refresh requests with the same session token and verify that exactly one succeeds.
7. Log out and verify that both access and refresh fail.

For TTL assertions, the script may inspect Redis with:

```bash
docker compose exec redis redis-cli TTL "auth:session:<session-id>"
```

The script must not print passwords, JWTs, or session tokens. Cleanup must be explicit and must not remove containers or data implicitly.
