# Authentication REST API — Implementation Checklist

This checklist decomposes the specification and current architecture into independently verifiable technical tasks. Complete tasks in order within each phase; tasks in different phases can be parallelized when their prerequisites are satisfied.

## Phase 1 — Project foundation

- [x] **Create the Spring Boot application structure**
  - [x] Configure Spring Boot 3.x for Java 21.
  - [x] Add starters for Web, Validation, Security, JPA, and Redis.
  - [x] Add the PostgreSQL JDBC driver and test dependencies.
  - [x] Keep Liquibase as the only database migration tool.
  - [x] Add Maven test, compiler, and packaging configuration.
  - [x] Verify the project starts with an empty application context.

- [x] **Define application configuration**
  - [x] Add typed configuration for PostgreSQL, Redis, JWT, session TTL, access-token TTL, issuer, and password policy.
  - [x] Bind values from environment variables with safe local defaults where appropriate.
  - [x] Fail startup when required production secrets are missing or malformed.
  - [x] Provide `.env.example` without usable credentials or private keys.

- [x] **Add the common web foundation**
  - [x] Implement request ID generation/propagation.
  - [x] Configure JSON serialization and UTC timestamps.
  - [x] Add the common error response containing `timestamp`, `status`, `code`, `message`, and `requestId`.
  - [x] Add exception handlers for validation, authentication, duplicate users, dependency failures, and unexpected errors.
  - [x] Ensure stack traces and secrets are never returned to clients.

## Phase 2 — Database and domain model

- [x] **Configure Liquibase**
  - [x] Add a versioned root changelog under `src/main/resources/db/changelog`.
  - [x] Configure Spring Boot to run Liquibase automatically after PostgreSQL is available.
  - [x] Add a baseline changeset for the users table and unique email index.
  - [x] Treat deployed changesets as immutable.
  - [x] Add a migration changelog resource test.

- [x] **Implement the user domain**
  - [x] Create the user entity with UUID ID, normalized email, password hash, and UTC audit timestamps.
  - [x] Add the repository query for normalized email.
  - [x] Enforce `users_email_uq` at the database level.
  - [x] Map database uniqueness violations to `USER_ALREADY_EXISTS`.

- [x] **Implement email and password policies**
  - [x] Normalize email by trimming and lowercasing with `Locale.ROOT`.
  - [x] Validate email length and syntax.
  - [x] Enforce the 12–128 Unicode code-point password policy.
  - [x] Do not trim, normalize, persist, or log raw passwords.
  - [x] Add unit tests for boundary and invalid values.

- [x] **Implement password hashing**
  - [x] Configure Argon2id through Spring Security's password encoder.
  - [x] Hash passwords before persistence.
  - [x] Verify passwords without revealing whether the user exists.
  - [x] Add tests proving hashes are not reversible and invalid passwords fail.

## Phase 3 — Session and token infrastructure

- [x] **Implement session identifiers and opaque tokens**
  - [x] Generate session IDs with `UUID.randomUUID()` or an equivalent secure generator.
  - [x] Generate at least 32 cryptographically secure random token bytes.
  - [x] Encode tokens as unpadded Base64 URL-safe text.
  - [x] Define a safe opaque token format that allows recovering the session ID for lookup.
  - [x] Reject malformed tokens before Redis access.

- [x] **Implement session persistence**
  - [x] Use `auth:session:{sessionId}` Redis keys.
  - [x] Store only `userId` and the session-token digest in a Redis hash.
  - [x] Set `SESSION_TTL` when creating a session.
  - [x] Read and validate the positive Redis TTL without extending it.
  - [x] Add repository-level tests for create, read, delete, and expiration.

- [x] **Implement JWT issuance and validation**
  - [x] Configure a pinned RS256 or ES256 algorithm.
  - [x] Load the private signing key and public verification key from secrets/files.
  - [x] Issue `sub`, `sid`, `iat`, `exp`, and `iss` claims.
  - [x] Validate signature, issuer, and expiration using a maintained JWT library.
  - [x] Add tests for valid, expired, tampered, wrong-issuer, and wrong-algorithm tokens.

- [x] **Implement atomic session refresh**
  - [x] Add a Redis Lua script or equivalent atomic compare-and-set operation.
  - [x] Compare the submitted token digest with the stored digest.
  - [x] Replace the digest and reset TTL only on a successful match.
  - [x] Return failure without modifying hash or TTL for invalid/replaced/expired tokens.
  - [x] Preserve the session ID when issuing the replacement JWT.
  - [x] Add repository tests for single-use rotation and atomic compare-and-set behavior.

## Phase 4 — Authentication use cases and HTTP API

- [x] **Implement registration**
  - [x] Validate and normalize the request.
  - [x] Persist the user with an Argon2id password hash.
  - [x] Create a Redis session and issue the access token only after required persistence succeeds.
  - [x] Return `201 Created` with `accessToken`, `sessionToken`, `tokenType`, and `expiresIn`.
  - [x] Map duplicate email to `409 USER_ALREADY_EXISTS`.
  - [x] Ensure Redis failure cannot produce an authentication success.

- [x] **Implement login**
  - [x] Normalize the email and load the user.
  - [x] Verify the password using the configured encoder.
  - [x] Return the same `401 INVALID_CREDENTIALS` response for an unknown user and a wrong password.
  - [x] Create a new independent Redis session for every successful login.
  - [x] Return `200 OK` with the token response.

- [x] **Implement refresh**
  - [x] Accept only `sessionToken` in the JSON body.
  - [x] Do not use `Authorization`, JWT claims, or a standalone session ID for authorization.
  - [x] Execute the atomic rotation operation.
  - [x] Return a new access token and a different session token on success.
  - [x] Return `401 INVALID_SESSION` for all invalid, missing, expired, deleted, or replaced tokens.
  - [x] Confirm that failed refresh does not alter the token or TTL.

- [x] **Implement logout**
  - [x] Accept only `sessionToken` in the JSON body.
  - [x] Delete the identified Redis session.
  - [x] Return `204 No Content`.
  - [x] Make missing/expired-session logout idempotent.
  - [x] Map Redis unavailability to `503 DEPENDENCY_UNAVAILABLE`.

- [x] **Implement protected access and `GET /api/me`**
  - [x] Add a Bearer-token security filter or resource-server integration.
  - [x] Validate JWT claims and then perform the Redis active-session check.
  - [x] Verify Redis `userId` matches JWT `sub`.
  - [x] Load the current user and return only `id` and `email`.
  - [x] Ensure ordinary requests do not extend the session TTL.
  - [x] Return `401 UNAUTHORIZED` for missing, malformed, tampered, expired, revoked, or mismatched authentication.

## Phase 5 — Infrastructure and delivery

- [x] **Create the application Docker image**
  - [x] Use a multi-stage Dockerfile with a Maven builder and minimal JRE runtime.
  - [x] Run the application as a non-root user.
  - [x] Supply keys and credentials through environment variables or mounted secrets.
  - [x] Do not include development secrets in the image.

- [x] **Create the Docker Compose stack**
  - [x] Add exactly `app`, `postgres`, `redis`, and `nginx` runtime services.
  - [x] Expose a host port only from Nginx.
  - [x] Add PostgreSQL persistence with a named volume.
  - [x] Add PostgreSQL, Redis, and application healthchecks.
  - [x] Use healthy dependency conditions before starting the application.
  - [x] Verify `docker compose up --build` works after `.env` setup.

- [x] **Configure Nginx**
  - [x] Proxy `/api/` to the internal application port.
  - [x] Forward `Authorization`, `Content-Type`, and `X-Request-Id`.
  - [x] Generate or preserve a request ID.
  - [x] Avoid exposing application, actuator, PostgreSQL, or Redis ports publicly.
  - [x] Verify that API error responses remain valid JSON.

- [x] **Add safe operational logging**
  - [x] Log operation, request ID, outcome, and safe user/session identifiers.
  - [x] Redact passwords, JWTs, session tokens, token hashes, and authorization headers.
  - [x] Add controlled dependency timeout handling for PostgreSQL and Redis.
  - [x] Confirm Redis failure always fails closed.

## Phase 6 — Automated verification

- [x] **Add unit test coverage**
  - Cover normalization, validation, hashing, token generation, JWT claims, error mapping, and secret redaction.
  - Include boundary tests for password length and token/session lifetimes.
  - Keep unit tests independent of Docker and external services.

- [x] **Add Testcontainers integration coverage**
  - Start actual PostgreSQL and Redis containers.
  - Apply Liquibase changesets against the PostgreSQL container.
  - Test registration, login, duplicate registration, invalid credentials, `/api/me`, and dependency errors.
  - Test deleted/expired Redis sessions invalidating unexpired JWTs.
  - Test refresh rotation, TTL behavior, logout, and independent sessions.
  - Test concurrent refresh with exactly one successful response.

- [x] **Create the runnable curl demo**
  - Add executable `scripts/demo-auth.sh`.
  - Use `curl` and `jq`, or document a portable alternative.
  - Start the stack with shortened lifetimes:
    ```bash
    cp .env.example .env
    ACCESS_TOKEN_TTL=5s SESSION_TTL=20s docker compose up --build -d
    ./scripts/demo-auth.sh http://localhost:8088
    ```
  - Assert registration, duplicate registration, incorrect password, login, and `/api/me`.
  - Assert unauthenticated and tampered-JWT rejection.
  - Wait for access-token expiration, refresh, new-token access, old-token rejection, and next refresh.
  - Assert that only successful refresh resets TTL; ordinary API requests and failed refreshes do not.
  - Assert invalid/expired session rejection and exactly one successful concurrent refresh.
  - Logout and assert both access and refresh fail.
  - Use `docker compose exec redis redis-cli TTL "auth:session:<session-id>"` for TTL assertions.
  - Never print credentials and never perform implicit destructive cleanup.

## Final release gate

- [x] All tests pass with no skipped authentication-critical cases.
- [x] Liquibase starts cleanly on an empty PostgreSQL instance and does not reapply completed changesets.
- [x] `docker compose up --build` starts all four services with only Nginx exposed.
- [x] The curl demo passes against the Compose stack.
- [x] No password, JWT, raw session token, or token hash appears in source-controlled configuration, responses, or logs.
- [x] Documentation under `docs/` is complete and written in English.
