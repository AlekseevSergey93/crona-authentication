# Authentication REST API — Architecture

## Runtime topology

```text
client -> Nginx :80 -> Java application -> PostgreSQL
                                      \-> Redis
```

The runtime consists of four Docker Compose services:

- **Nginx** is the public reverse proxy and the only service exposing a host port. It proxies `/api/` to the application and forwards `Authorization`, `Content-Type`, and `X-Request-Id`.
- **Application** is a Spring Boot 3.x service running on Java 21 and listening on internal port `8080`.
- **PostgreSQL** is the source of truth for users.
- **Redis** stores active sessions and their TTLs.

The application must start only after PostgreSQL and Redis healthchecks pass. Liquibase applies the root changelog and all included changesets during startup. Redis and PostgreSQL timeouts must produce controlled dependency errors, not successful authentication.

## Application layers

Recommended package boundaries:

```text
com.cronagroup.authentication
├── auth
│   ├── controller
│   ├── service
│   ├── security
│   └── dto
├── user
│   ├── domain
│   ├── repository
│   └── service
├── session
│   ├── domain
│   ├── repository
│   └── service
├── common
│   ├── error
│   └── web
└── config
```

Controllers map HTTP requests to application services. Services coordinate validation, password hashing, persistence, session operations, and token issuance. Repositories isolate PostgreSQL and Redis access. Security filters validate JWTs and then check the corresponding active Redis session.

## User persistence

PostgreSQL contains:

```text
users
  id UUID primary key
  email VARCHAR(320) not null unique
  password_hash VARCHAR(255) not null
  created_at TIMESTAMPTZ not null
  updated_at TIMESTAMPTZ not null
```

Email is normalized before the insert. The unique database index remains the final authority for concurrent registration attempts.

## Session persistence

Redis stores:

```text
key: auth:session:{sessionId}
type: hash
fields:
  userId: UUID
  sessionTokenHash: digest
ttl: SESSION_TTL
```

The session token must contain enough opaque data to recover its session ID for lookup, for example `Base64Url(sessionId || randomSecret)`. The entire submitted token is hashed and compared; the session ID alone is never accepted as a credential.

## Authentication flow

### Registration and login

1. Normalize and validate email and password.
2. For registration, insert the user using the database unique constraint.
3. Verify the password for login.
4. Generate a random session ID and opaque session token.
5. Store the token digest and user ID in Redis with `SESSION_TTL`.
6. Issue a signed JWT containing `sub`, `sid`, `iat`, `exp`, and `iss`.
7. Return the access token and session token only after required persistence succeeds.

### Protected request

1. Extract `Authorization: Bearer <JWT>`.
2. Verify the pinned JWT signature, issuer, and expiration.
3. Extract `sub` and `sid`.
4. Load `auth:session:{sid}` from Redis.
5. Reject if the session is missing, expired, or belongs to another user.
6. Load the user from PostgreSQL and return the requested resource.

Ordinary protected requests do not update Redis TTL.

### Refresh

The application generates a replacement token and its digest, then uses a Redis Lua script or equivalent atomic compare-and-set transaction:

```text
if key does not exist: fail
if digest(currentToken) != storedDigest: fail
replace storedDigest with digest(newToken)
expire key with SESSION_TTL
return success
```

Only the request that atomically matches the current digest succeeds. A concurrent request using the replaced token fails without modifying the session. The session ID remains unchanged and is used in the new JWT.

### Logout

The application derives the session ID from the supplied session token and deletes the corresponding Redis key. Deletion immediately blocks both JWT-based access and future refresh for that session. Other session keys are unaffected.

## Error handling and observability

Use a single JSON error model with `timestamp`, `status`, `code`, `message`, and `requestId`. Map validation, authentication, duplicate-user, invalid-session, and dependency failures to stable codes.

Never log credentials or authorization headers. Safe logs may include the operation, request ID, outcome, user ID, and a redacted session identifier. Do not expose stack traces to clients.

## Docker architecture

Use a multi-stage Dockerfile:

1. Maven builder image compiles and packages the application.
2. Minimal Java runtime image runs the application as a non-root user.

Use a persistent PostgreSQL volume. Redis healthchecks must use `redis-cli ping`; PostgreSQL healthchecks must use `pg_isready`; the application healthcheck must expose a suitable internal health endpoint. Only Nginx has a host port mapping.

## Security architecture

- Use Argon2id for password hashes.
- Use cryptographically secure random generation for session IDs and session secrets.
- Use an asymmetric JWT key pair with a pinned algorithm.
- Keep private keys and database credentials outside source control.
- Store only session-token digests in Redis.
- Treat Redis as authoritative for session activity.
- Fail closed whenever a required dependency cannot be reached or its state cannot be verified.

## Verification architecture

Unit tests validate pure token, password, validation, and error logic. Testcontainers integration tests exercise the complete application against actual PostgreSQL and Redis. The curl demo runs through Nginx and verifies expiration, TTL changes, rotation, concurrent refresh, and logout from an external-client perspective.
