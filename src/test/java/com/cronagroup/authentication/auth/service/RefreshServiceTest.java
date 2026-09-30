package com.cronagroup.authentication.auth.service;

import com.cronagroup.authentication.auth.api.SessionTokenRequest;
import com.cronagroup.authentication.auth.api.TokenResponse;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.error.InvalidSessionException;
import com.cronagroup.authentication.common.security.JwtTokenService;
import com.cronagroup.authentication.common.security.RedisSessionRepository;
import com.cronagroup.authentication.common.security.SessionTokenService;
import com.cronagroup.authentication.config.ApplicationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class RefreshServiceTest {

    private RedisSessionRepository sessionRepository;
    private ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private JwtTokenService jwtTokenService;
    private RefreshService service;

    @BeforeEach
    void setUp() {
        sessionRepository = mock(RedisSessionRepository.class);
        sessionRepositoryProvider = mock(ObjectProvider.class);
        when(sessionRepositoryProvider.getIfAvailable()).thenReturn(sessionRepository);
        jwtTokenService = mock(JwtTokenService.class);
        ApplicationProperties properties = new ApplicationProperties();
        properties.getJwt().setAccessTokenTtl(Duration.ofMinutes(15));
        service = new RefreshService(sessionRepositoryProvider, jwtTokenService, properties);
    }

    @Test
    void atomicallyRotatesSessionAndIssuesJwtForSameSessionId() {
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        SessionTokenService.SessionToken replacement =
                new SessionTokenService.SessionToken(sessionId, "new-session-token");
        RedisSessionRepository.RotatedSession rotated = new RedisSessionRepository.RotatedSession(
                new RedisSessionRepository.SessionRecord(
                        sessionId,
                        userId,
                        "new-digest",
                        Duration.ofHours(24)
                ),
                replacement
        );
        when(sessionRepository.rotate("old-session-token")).thenReturn(Optional.of(rotated));
        when(jwtTokenService.issue(userId, sessionId)).thenReturn("new-access-token");

        TokenResponse response = service.refresh(new SessionTokenRequest("old-session-token"));

        assertThat(response).isEqualTo(
                new TokenResponse("new-access-token", "new-session-token", "Bearer", 900)
        );
        verify(jwtTokenService).issue(userId, sessionId);
    }

    @Test
    void rejectsMissingMalformedExpiredDeletedOrReplacedSessions() {
        when(sessionRepository.rotate("invalid-session-token")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.refresh(null))
                .isInstanceOf(InvalidSessionException.class);
        assertThatThrownBy(() -> service.refresh(new SessionTokenRequest(null)))
                .isInstanceOf(InvalidSessionException.class);
        assertThatThrownBy(() -> service.refresh(new SessionTokenRequest("invalid-session-token")))
                .isInstanceOf(InvalidSessionException.class);

        verifyNoInteractions(jwtTokenService);
    }

    @Test
    void mapsRedisFailureWithoutIssuingJwt() {
        when(sessionRepository.rotate("session-token"))
                .thenThrow(new org.springframework.data.redis.RedisConnectionFailureException("down"));

        assertThatThrownBy(() -> service.refresh(new SessionTokenRequest("session-token")))
                .isInstanceOf(DependencyUnavailableException.class);
        verifyNoInteractions(jwtTokenService);
    }
}
