# JWT service

`JwtTokenService` issues and validates access tokens using Nimbus JOSE JWT
with a pinned `RS256` algorithm.

Tokens contain:

```json
{
  "sub": "<userId>",
  "sid": "<sessionId>",
  "iat": 0,
  "exp": 0,
  "iss": "crona-authentication"
}
```

The private signing key must be a PKCS#8 PEM file and the public verification
key must be an X.509 PEM file. Paths are supplied through
`JWT_PRIVATE_KEY_PATH` and `JWT_PUBLIC_KEY_PATH`. Keys are loaded lazily on the
first issuance or validation operation, so non-production context tests do not
require production secret files.

Validation rejects malformed tokens, unsupported algorithms, invalid
signatures, wrong issuers, missing required claims, and expired tokens.
