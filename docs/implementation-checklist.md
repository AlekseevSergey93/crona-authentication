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

- [ ] **Configure Liquibase**
  - Add a versioned root changelog under `src/main/resources/db/changelog`.
  - Configure Spring Boot to run Liquibase automatically after PostgreSQL is available.
  - Add a baseline changeset for the users table and unique email index.
  - Treat deployed changesets as immutable.
  - Add a migration startup test.

- [ ] **Implement the user domain**
  - Create the user entity with UUID ID, normalized email, password hash, and UTC audit timestamps.
  - Add the repository query for normalized email.
  - Enforce `users_email_uq` at the database level.
  - Map database uniqueness violations to `USER_ALREADY_EXISTS`.

- [ ] **Implement email and password policies**
  - Normalize email by trimming and lowercasing with `Locale.ROOT`.
  - Validate email length and syntax.
  - Enforce the 12–128 Unicode code-point password policy.
  - Do not trim, normalize, persist, or log raw passwords.
  - Add unit tests for boundary and invalid values.

- [ ] **Implement password hashing**
  - Configure Argon2id through Spring Security's password encoder.
  - Hash passwords before persistence.
  - Verify passwords without revealing whether the user exists.
  - Add tests proving hashes are not reversible and invalid passwords fail.

## Phase 3 — Session and token infrastructure

- [ ] **Implement session identifiers and opaque tokens**
  - Generate session IDs with `UUID.randomUUID()` or an equivalent secure generator.
  - Generate at least 32 cryptographically secure random token bytes.
  - Encode tokens as unpadded Base64 URL-safe text.
  - Define a safe opaque token format that allows recovering the session ID for lookup.
  - Reject malformed tokens before Redis access.

- [ ] **Implement session persistence**
  - Use `auth:session:{sessionId}` Redis keys.
  - Store only `userId` and the session-token digest in a Redis hash.
  - Set `SESSION_TTL` when creating a session.
  - Read and validate the positive Redis TTL without extending it.
  - Add repository-level tests for create, read, delete, and expiration.

- [ ] **Implement JWT issuance and validation**
  - Configure a pinned RS256 or ES256 algorithm.
  - Load the private signing key and public verification key from secrets/files.
  - Issue `sub`, `sid`, `iat`, `exp`, and `iss` claims.
  - Validate signature, issuer, and expiration using a maintained JWT library.
  - Add tests for valid, expired, tampered, wrong-issuer, and wrong-algorithm tokens.

- [ ] **Implement atomic session refresh**
  - Add a Redis Lua script or equivalent atomic compare-and-set operation.
  - Compare the submitted token digest with the stored digest.
  - Replace the digest and reset TTL only on a successful match.
  - Return failure without modifying hash or TTL for invalid/replaced/expired tokens.
  - Preserve the session ID when issuing the replacement JWT.
  - Add a concurrency test proving exactly one of two simultaneous refreshes succeeds.

## Phase 4 — Authentication use cases and HTTP API

- [ ] **Implement registration**
  - Validate and normalize the request.
  - Persist the user with an Argon2id password hash.
  - Create a Redis session and issue the access token only after required persistence succeeds.
  - Return `201 Created` with `accessToken`, `sessionToken`, `tokenType`, and `expiresIn`.
  - Map duplicate email to `409 USER_ALREADY_EXISTS`.
  - Ensure Redis failure cannot produce an authentication success.

- [ ] **Implement login**
  - Normalize the email and load the user.
  - Verify the password using the configured encoder.
  - Return the same `401 INVALID_CREDENTIALS` response for an unknown user and a wrong password.
  - Create a new independent Redis session for every successful login.
  - Return `200 OK` with the token response.

- [ ] **Implement refresh**
  - Accept only `sessionToken` in the JSON body.
  - Do not use `Authorization`, JWT claims, or a standalone session ID for authorization.
  - Execute the atomic rotation operation.
  - Return a new access token and a different session token on success.
  - Return `401 INVALID_SESSION` for all invalid, missing, expired, deleted, or replaced tokens.
  - Confirm that failed refresh does not alter the token or TTL.

- [ ] **Implement logout**
  - Accept only `sessionToken` in the JSON body.
  - Delete the identified Redis session.
  - Return `204 No Content`.
  - Make missing/expired-session logout idempotent.
  - Map Redis unavailability to `503 DEPENDENCY_UNAVAILABLE`.

- [ ] **Implement protected access and `GET /api/me`**
  - Add a Bearer-token security filter or resource-server integration.
  - Validate JWT claims and then perform the Redis active-session check.
  - Verify Redis `userId` matches JWT `sub`.
  - Load the current user and return only `id` and `email`.
  - Ensure ordinary requests do not extend the session TTL.
  - Return `401 UNAUTHORIZED` for missing, malformed, tampered, expired, revoked, or mismatched authentication.

## Phase 5 — Infrastructure and delivery

- [ ] **Create the application Docker image**
  - Use a multi-stage Dockerfile with a Maven builder and minimal JRE runtime.
  - Run the application as a non-root user.
  - Supply keys and credentials through environment variables or mounted secrets.
  - Do not include development secrets in the image.

- [ ] **Create the Docker Compose stack**
  - Add exactly `app`, `postgres`, `redis`, and `nginx` runtime services.
  - Expose a host port only from Nginx.
  - Add PostgreSQL persistence with a named volume.
  - Add PostgreSQL, Redis, and application healthchecks.
  - Use healthy dependency conditions before starting the application.
  - Verify `docker compose up --build` works after `.env` setup.

- [ ] **Configure Nginx**
  - Proxy `/api/` to the internal application port.
  - Forward `Authorization`, `Content-Type`, and `X-Request-Id`.
  - Generate or preserve a request ID.
  - Avoid exposing application, actuator, PostgreSQL, or Redis ports publicly.
  - Verify that API error responses remain valid JSON.

- [ ] **Add safe operational logging**
  - Log operation, request ID, outcome, and safe user/session identifiers.
  - Redact passwords, JWTs, session tokens, token hashes, and authorization headers.
  - Add controlled dependency timeout handling for PostgreSQL and Redis.
  - Confirm Redis failure always fails closed.

## Phase 6 — Automated verification

- [ ] **Add unit test coverage**
  - Cover normalization, validation, hashing, token generation, JWT claims, error mapping, and secret redaction.
  - Include boundary tests for password length and token/session lifetimes.
  - Keep unit tests independent of Docker and external services.

- [ ] **Add Testcontainers integration coverage**
  - Start actual PostgreSQL and Redis containers.
  - Apply Liquibase changesets against the PostgreSQL container.
  - Test registration, login, duplicate registration, invalid credentials, `/api/me`, and dependency errors.
  - Test deleted/expired Redis sessions invalidating unexpired JWTs.
  - Test refresh rotation, TTL behavior, logout, and independent sessions.
  - Test concurrent refresh with exactly one successful response.

- [ ] **Create the runnable curl demo**
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

- [ ] All tests pass with no skipped authentication-critical cases.
- [ ] Liquibase starts cleanly on an empty PostgreSQL instance and does not reapply completed changesets.
- [ ] `docker compose up --build` starts all four services with only Nginx exposed.
- [ ] The curl demo passes against the Compose stack.
- [ ] No password, JWT, raw session token, or token hash appears in source-controlled configuration, responses, or logs.
- [ ] Documentation under `docs/` is complete and written in English.
