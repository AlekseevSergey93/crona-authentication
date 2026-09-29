package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.config.ApplicationProperties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Repository;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Repository
@ConditionalOnBean(StringRedisTemplate.class)
public class RedisSessionRepository {

    private static final String KEY_PREFIX = "auth:session:";
    private static final String USER_ID_FIELD = "userId";
    private static final String TOKEN_DIGEST_FIELD = "sessionTokenHash";
    private static final RedisScript<String> ROTATE_SCRIPT = RedisScript.of("""
            local currentDigest = redis.call('HGET', KEYS[1], ARGV[1])
            if not currentDigest or currentDigest ~= ARGV[2] then
                return ''
            end

            local userId = redis.call('HGET', KEYS[1], ARGV[3])
            if not userId then
                return ''
            end

            redis.call('HSET', KEYS[1], ARGV[1], ARGV[4])
            redis.call('PEXPIRE', KEYS[1], ARGV[5])
            return userId
            """, String.class);

    private final StringRedisTemplate redisTemplate;
    private final SessionTokenService sessionTokenService;
    private final Duration sessionTtl;

    public RedisSessionRepository(
            StringRedisTemplate redisTemplate,
            SessionTokenService sessionTokenService,
            ApplicationProperties properties
    ) {
        this.redisTemplate = redisTemplate;
        this.sessionTokenService = sessionTokenService;
        this.sessionTtl = properties.getJwt().getSessionTtl();
        if (sessionTtl.isZero() || sessionTtl.isNegative() || sessionTtl.toMillis() <= 0) {
            throw new IllegalArgumentException("Session TTL must be positive");
        }
    }

    public void create(UUID userId, SessionTokenService.SessionToken token) {
        String key = key(token.sessionId());
        redisTemplate.opsForHash().putAll(key, Map.of(
                USER_ID_FIELD, userId.toString(),
                TOKEN_DIGEST_FIELD, sessionTokenService.digest(token.value())
        ));
        redisTemplate.expire(key, sessionTtl);
    }

    public Optional<SessionRecord> findByToken(String token) {
        Optional<UUID> sessionId = sessionTokenService.extractSessionId(token);
        if (sessionId.isEmpty()) {
            return Optional.empty();
        }

        Optional<SessionRecord> session = find(sessionId.get());
        if (session.isEmpty()) {
            return Optional.empty();
        }

        byte[] submittedDigest = sessionTokenService.digest(token).getBytes(StandardCharsets.US_ASCII);
        byte[] storedDigest = session.get().tokenDigest().getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(submittedDigest, storedDigest) ? session : Optional.empty();
    }

    public Optional<SessionRecord> find(UUID sessionId) {
        String key = key(sessionId);
        Map<Object, Object> values = redisTemplate.opsForHash().entries(key);
        if (values.isEmpty()) {
            return Optional.empty();
        }

        long ttlMillis = redisTemplate.getExpire(key, java.util.concurrent.TimeUnit.MILLISECONDS);
        if (ttlMillis <= 0) {
            return Optional.empty();
        }

        return Optional.of(new SessionRecord(
                sessionId,
                parseUuid(values, USER_ID_FIELD),
                requiredValue(values, TOKEN_DIGEST_FIELD),
                Duration.ofMillis(ttlMillis)
        ));
    }

    public boolean deleteByToken(String token) {
        Optional<UUID> sessionId = sessionTokenService.extractSessionId(token);
        return sessionId.isPresent() && Boolean.TRUE.equals(redisTemplate.delete(key(sessionId.get())));
    }

    public Optional<RotatedSession> rotate(String currentToken) {
        Optional<UUID> sessionId = sessionTokenService.extractSessionId(currentToken);
        if (sessionId.isEmpty()) {
            return Optional.empty();
        }

        SessionTokenService.SessionToken replacement = sessionTokenService.generate(sessionId.get());
        String rotatedUserId = redisTemplate.execute(
                ROTATE_SCRIPT,
                List.of(key(sessionId.get())),
                TOKEN_DIGEST_FIELD,
                sessionTokenService.digest(currentToken),
                USER_ID_FIELD,
                sessionTokenService.digest(replacement.value()),
                String.valueOf(sessionTtl.toMillis())
        );
        if (rotatedUserId == null || rotatedUserId.isBlank()) {
            return Optional.empty();
        }

        UUID userId = parseUuid(Map.of(USER_ID_FIELD, rotatedUserId), USER_ID_FIELD);
        return Optional.of(new RotatedSession(
                new SessionRecord(
                        sessionId.get(),
                        userId,
                        sessionTokenService.digest(replacement.value()),
                        sessionTtl
                ),
                replacement
        ));
    }

    private static String key(UUID sessionId) {
        return KEY_PREFIX + sessionId;
    }

    private static UUID parseUuid(Map<Object, Object> values, String field) {
        String value = requiredValue(values, field);
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw new IllegalStateException("Invalid UUID in Redis session field " + field, exception);
        }
    }

    private static String requiredValue(Map<Object, Object> values, String field) {
        Object value = values.get(field);
        if (!(value instanceof String string) || string.isBlank()) {
            throw new IllegalStateException("Missing or invalid Redis session field " + field);
        }
        return string;
    }

    public record SessionRecord(
            UUID sessionId,
            UUID userId,
            String tokenDigest,
            Duration remainingTtl
    ) {
    }

    public record RotatedSession(
            SessionRecord session,
            SessionTokenService.SessionToken replacementToken
    ) {
    }
}
