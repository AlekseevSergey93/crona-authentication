# Password hashing service

## Responsibility

`PasswordHashingService` is the only application boundary responsible for converting a raw password into a persisted password hash and for verifying a login password.

## Algorithm

- Use Spring Security `Argon2PasswordEncoder`.
- Use the Argon2id variant with the library's secure default parameters.
- Use a fresh random salt for every hash.
- Store the complete encoded Argon2id string, including algorithm parameters and salt.
- Never store or log the raw password.

## Operations

### Hash

`hash(rawPassword)`:

1. Validate the raw password with the configured Unicode code-point password policy.
2. Encode it with Argon2id.
3. Return the complete encoded hash for persistence.

The method must not return the raw password or a manually assembled hash.

### Verify

`matches(rawPassword, passwordHash)` delegates verification to the established password encoder. It returns `false` for an incorrect password and must not reveal whether a user record exists. Authentication services should use the same externally visible invalid-credentials response for an unknown user and a wrong password.

## Security rules

- Keep the `PasswordEncoder` as a Spring-managed bean.
- Do not compare password hashes with plain string equality.
- Do not re-hash or mutate a password during ordinary login verification.
- Do not include raw passwords or hashes in API responses, logs, exceptions, or test output.
- Bouncy Castle is included as the Argon2 runtime provider dependency.
