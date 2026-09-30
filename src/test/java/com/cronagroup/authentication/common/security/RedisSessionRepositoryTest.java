package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.config.ApplicationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

class RedisSessionRepositoryTest {

    private static final UUID USER_ID = UUID.randomUUID();

    private StringRedisTemplate redisTemplate;
    private ObjectProvider<StringRedisTemplate> redisTemplateProvider;
    private HashOperations<String, Object, Object> hashOperations;
    private SessionTokenService tokenService;
    private RedisSessionRepository repository;

    @BeforeEach
    void setUp() {
        redisTemplate = mock(StringRedisTemplate.class);
        redisTemplateProvider = mock(ObjectProvider.class);
        when(redisTemplateProvider.getIfAvailable()).thenReturn(redisTemplate);
        hashOperations = mock(HashOperations.class);
        tokenService = new SessionTokenService();
        ApplicationProperties properties = new ApplicationProperties();
        properties.getJwt().setSessionTtl(Duration.ofHours(24));

        when(redisTemplate.opsForHash()).thenReturn(hashOperations);
        repository = new RedisSessionRepository(redisTemplateProvider, tokenService, properties);
    }

    @Test
    void createsHashAndTtlAtomically() {
        SessionTokenService.SessionToken token = tokenService.generate();
        doReturn("1").when(redisTemplate).execute(
                any(),
                eq(java.util.List.of("auth:session:" + token.sessionId())),
                any(Object[].class)
        );

        repository.create(USER_ID, token);

        verify(redisTemplate).execute(
                any(),
                eq(java.util.List.of("auth:session:" + token.sessionId())),
                eq("userId"),
                eq(USER_ID.toString()),
                eq("sessionTokenHash"),
                eq(tokenService.digest(token.value())),
                eq(String.valueOf(Duration.ofHours(24).toMillis()))
        );
        verify(hashOperations, never()).putAll(anyString(), anyMap());
        verify(redisTemplate, never()).expire(anyString(), any(Duration.class));
    }

    @Test
    void readsSessionOnlyWhenHashExistsAndTtlIsPositive() {
        SessionTokenService.SessionToken token = tokenService.generate();
        String key = "auth:session:" + token.sessionId();
        when(hashOperations.entries(key)).thenReturn(Map.of(
                "userId", USER_ID.toString(),
                "sessionTokenHash", tokenService.digest(token.value())
        ));
        when(redisTemplate.getExpire(key, TimeUnit.MILLISECONDS)).thenReturn(12_345L);

        assertThat(repository.find(token.sessionId()))
                .get()
                .satisfies(session -> {
                    assertThat(session.userId()).isEqualTo(USER_ID);
                    assertThat(session.tokenDigest()).isEqualTo(tokenService.digest(token.value()));
                    assertThat(session.remainingTtl()).isEqualTo(Duration.ofMillis(12_345));
                });
        verify(redisTemplate, never()).expire(anyString(), any(Duration.class));
    }

    @Test
    void rejectsMissingOrNonPositiveTtlSessions() {
        UUID sessionId = UUID.randomUUID();
        String key = "auth:session:" + sessionId;
        when(hashOperations.entries(key)).thenReturn(Map.of("userId", USER_ID.toString()));
        when(redisTemplate.getExpire(key, TimeUnit.MILLISECONDS)).thenReturn(0L);

        assertThat(repository.find(sessionId)).isEmpty();
    }

    @Test
    void validatesTokenBeforeReadingRedisAndComparesItsDigest() {
        SessionTokenService.SessionToken token = tokenService.generate();
        String key = "auth:session:" + token.sessionId();
        when(hashOperations.entries(key)).thenReturn(Map.of(
                "userId", USER_ID.toString(),
                "sessionTokenHash", tokenService.digest(token.value())
        ));
        when(redisTemplate.getExpire(key, TimeUnit.MILLISECONDS)).thenReturn(1_000L);

        assertThat(repository.findByToken(token.value())).isPresent();
        String tamperedToken = tamperSecretPart(token.value());
        assertThat(repository.findByToken(tamperedToken)).isEmpty();
        assertThat(repository.findByToken("malformed")).isEmpty();
        verify(hashOperations, times(2)).entries(key);
    }

    @Test
    void deletesOnlyTheSessionIdentifiedByAValidToken() {
        SessionTokenService.SessionToken token = tokenService.generate();
        String key = "auth:session:" + token.sessionId();
        when(redisTemplate.delete(key)).thenReturn(true);

        assertThat(repository.deleteByToken(token.value())).isTrue();
        assertThat(repository.deleteByToken("malformed")).isFalse();
        verify(redisTemplate).delete(key);
    }

    @Test
    void rotatesTokenAndPreservesSessionIdWithAtomicRedisScript() {
        SessionTokenService.SessionToken currentToken = tokenService.generate();
        String key = "auth:session:" + currentToken.sessionId();
        doReturn(USER_ID.toString()).when(redisTemplate).execute(
                any(),
                eq(java.util.List.of(key)),
                any(Object[].class)
        );

        RedisSessionRepository.RotatedSession rotated = repository.rotate(currentToken.value()).orElseThrow();

        assertThat(rotated.session().sessionId()).isEqualTo(currentToken.sessionId());
        assertThat(rotated.session().userId()).isEqualTo(USER_ID);
        assertThat(rotated.replacementToken().sessionId()).isEqualTo(currentToken.sessionId());
        assertThat(rotated.replacementToken().value()).isNotEqualTo(currentToken.value());
        assertThat(rotated.session().tokenDigest())
                .isEqualTo(tokenService.digest(rotated.replacementToken().value()));
        verify(redisTemplate).execute(
                any(),
                eq(java.util.List.of(key)),
                eq("sessionTokenHash"),
                eq(tokenService.digest(currentToken.value())),
                eq("userId"),
                eq(tokenService.digest(rotated.replacementToken().value())),
                eq(String.valueOf(Duration.ofHours(24).toMillis()))
        );
    }

    @Test
    void rejectsInvalidOrReplacedTokensWithoutExecutingRotation() {
        SessionTokenService.SessionToken currentToken = tokenService.generate();
        doReturn("").when(redisTemplate).execute(
                any(),
                anyList(),
                any(Object[].class)
        );

        assertThat(repository.rotate("malformed")).isEmpty();
        assertThat(repository.rotate(currentToken.value())).isEmpty();
        verify(redisTemplate, times(1)).execute(
                any(),
                anyList(),
                any(Object[].class)
        );
    }

    @Test
    void rejectsSessionWithoutPositiveTtlInAtomicRotation() {
        SessionTokenService.SessionToken currentToken = tokenService.generate();
        doReturn("").when(redisTemplate).execute(
                any(),
                eq(java.util.List.of("auth:session:" + currentToken.sessionId())),
                any(Object[].class)
        );

        assertThat(repository.rotate(currentToken.value())).isEmpty();
    }

    private static String tamperSecretPart(String token) {
        int index = 30;
        char current = token.charAt(index);
        char replacement = current == 'A' ? 'B' : 'A';
        return token.substring(0, index) + replacement + token.substring(index + 1);
    }
}
