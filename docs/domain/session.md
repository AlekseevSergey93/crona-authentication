# Session identity and opaque tokens

Each session has a randomly generated UUID that identifies the Redis session
record. The UUID is not a credential and must never authorize an operation by
itself.

The session credential is an opaque, unpadded Base64 URL-safe value containing:

```text
format version (1 byte) || session UUID (16 bytes) || random secret (32 bytes)
```

The secret is generated with `SecureRandom`. The token parser requires the
supported format version, the exact payload length, and canonical Base64
encoding before returning the embedded session ID. Invalid tokens are rejected
without attempting a Redis lookup.

Redis stores sessions under `auth:session:{sessionId}` as a hash containing
only `userId` and the SHA-256 `sessionTokenHash`. The configured `SESSION_TTL`
is applied when the hash is created. Reads require a positive remaining TTL and
never refresh or extend it; raw session tokens are never persisted.

Refresh uses a Redis Lua compare-and-set script. It compares the submitted
token digest with the current hash value, replaces the digest, and resets the
TTL only when the comparison succeeds. The replacement token keeps the same
session ID. Invalid, replaced, expired, or deleted tokens return failure
without changing the hash or TTL.
