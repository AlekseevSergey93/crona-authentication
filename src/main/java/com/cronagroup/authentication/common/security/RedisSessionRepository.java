package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.config.ApplicationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.data.redis.RedisConnectionFailureException;
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
public class RedisSessionRepository {

    private static final String KEY_PREFIX = "auth:session:";
    private static final String USER_ID_FIELD = "userId";
    private static final String TOKEN_DIGEST_FIELD = "sessionTokenHash";
    private static final RedisScript<String> CREATE_SCRIPT = RedisScript.of("""
            redis.call('HSET', KEYS[1], ARGV[1], ARGV[2], ARGV[3], ARGV[4])
            redis.call('PEXPIRE', KEYS[1], ARGV[5])
            return '1'
            """, String.class);
    private static final RedisScript<String> ROTATE_SCRIPT = RedisScript.of("""
            local ttl = redis.call('PTTL', KEYS[1])
            if ttl <= 0 then
                return ''
            end

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

    private final ObjectProvider<StringRedisTemplate> redisTemplateProvider;
    private final SessionTokenService sessionTokenService;
    private final Duration sessionTtl;

    public RedisSessionRepository(
            ObjectProvider<StringRedisTemplate> redisTemplateProvider,
            SessionTokenService sessionTokenService,
            ApplicationProperties properties
    ) {
        this.redisTemplateProvider = redisTemplateProvider;
        this.sessionTokenService = sessionTokenService;
        this.sessionTtl = properties.getJwt().getSessionTtl();
        if (sessionTtl.isZero() || sessionTtl.isNegative() || sessionTtl.toMillis() <= 0) {
            throw new IllegalArgumentException("Session TTL must be positive");
        }
    }

    public void create(UUID userId, SessionTokenService.SessionToken token) {
        StringRedisTemplate redisTemplate = redisTemplate();
        String key = key(token.sessionId());
        String created = redisTemplate.execute(
                CREATE_SCRIPT,
                List.of(key),
                USER_ID_FIELD,
                userId.toString(),
                TOKEN_DIGEST_FIELD,
                sessionTokenService.digest(token.value()),
                String.valueOf(sessionTtl.toMillis())
        );
        if (!"1".equals(created)) {
            throw new IllegalStateException("Unable to create Redis session");
        }
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
        StringRedisTemplate redisTemplate = redisTemplate();
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
        if (sessionId.isEmpty()) {
            return false;
        }
        return Boolean.TRUE.equals(redisTemplate().delete(key(sessionId.get())));
    }

    public Optional<RotatedSession> rotate(String currentToken) {
        Optional<UUID> sessionId = sessionTokenService.extractSessionId(currentToken);
        if (sessionId.isEmpty()) {
            return Optional.empty();
        }

        StringRedisTemplate redisTemplate = redisTemplate();
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

    private StringRedisTemplate redisTemplate() {
        StringRedisTemplate redisTemplate = redisTemplateProvider.getIfAvailable();
        if (redisTemplate == null) {
            throw new RedisConnectionFailureException("Redis session persistence is unavailable");
        }
        return redisTemplate;
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
