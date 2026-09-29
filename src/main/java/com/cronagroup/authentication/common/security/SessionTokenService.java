package com.cronagroup.authentication.common.security;

import org.springframework.stereotype.Service;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

@Service
public class SessionTokenService {

    private static final byte FORMAT_VERSION = 1;
    private static final int SESSION_ID_BYTES = 16;
    private static final int SECRET_BYTES = 32;
    private static final int PAYLOAD_BYTES = 1 + SESSION_ID_BYTES + SECRET_BYTES;

    private final SecureRandom secureRandom;
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
    private final Base64.Decoder decoder = Base64.getUrlDecoder();

    public SessionTokenService() {
        this(new SecureRandom());
    }

    SessionTokenService(SecureRandom secureRandom) {
        this.secureRandom = Objects.requireNonNull(secureRandom, "secureRandom must not be null");
    }

    public SessionToken generate() {
        return generate(UUID.randomUUID());
    }

    public SessionToken generate(UUID sessionId) {
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        byte[] payload = new byte[PAYLOAD_BYTES];
        ByteBuffer buffer = ByteBuffer.wrap(payload);
        buffer.put(FORMAT_VERSION);
        buffer.putLong(sessionId.getMostSignificantBits());
        buffer.putLong(sessionId.getLeastSignificantBits());

        byte[] secret = new byte[SECRET_BYTES];
        secureRandom.nextBytes(secret);
        buffer.put(secret);

        return new SessionToken(sessionId, encoder.encodeToString(payload));
    }

    public Optional<UUID> extractSessionId(String token) {
        if (token == null || token.isEmpty() || token.indexOf('=') >= 0) {
            return Optional.empty();
        }

        final byte[] payload;
        try {
            payload = decoder.decode(token);
        } catch (IllegalArgumentException exception) {
            return Optional.empty();
        }

        if (payload.length != PAYLOAD_BYTES || !encoder.encodeToString(payload).equals(token)) {
            return Optional.empty();
        }

        ByteBuffer buffer = ByteBuffer.wrap(payload);
        if (buffer.get() != FORMAT_VERSION) {
            return Optional.empty();
        }

        return Optional.of(new UUID(buffer.getLong(), buffer.getLong()));
    }

    public String digest(String token) {
        Objects.requireNonNull(token, "token must not be null");
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(token.getBytes(java.nio.charset.StandardCharsets.US_ASCII))
            );
        } catch (java.security.NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }

    public record SessionToken(UUID sessionId, String value) {

        public SessionToken {
            Objects.requireNonNull(sessionId, "sessionId must not be null");
            Objects.requireNonNull(value, "value must not be null");
        }
    }
}
