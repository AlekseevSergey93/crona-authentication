package com.cronagroup.authentication.auth.service;

import com.cronagroup.authentication.auth.api.SessionTokenRequest;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.security.RedisSessionRepository;
import com.cronagroup.authentication.common.security.SessionTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class LogoutServiceTest {

    private RedisSessionRepository sessionRepository;
    private ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private SessionTokenService sessionTokenService;
    private LogoutService service;

    @BeforeEach
    void setUp() {
        sessionRepository = mock(RedisSessionRepository.class);
        sessionRepositoryProvider = mock(ObjectProvider.class);
        when(sessionRepositoryProvider.getIfAvailable()).thenReturn(sessionRepository);
        sessionTokenService = new SessionTokenService();
        service = new LogoutService(sessionRepositoryProvider, sessionTokenService);
    }

    @Test
    void deletesValidSessionAndDoesNotRequireItToExist() {
        SessionTokenService.SessionToken token = sessionTokenService.generate();

        service.logout(new SessionTokenRequest(token.value()));
        service.logout(new SessionTokenRequest(token.value()));

        verify(sessionRepository, times(2)).deleteByToken(token.value());
    }

    @Test
    void treatsMissingAndMalformedSessionsAsIdempotentNoOps() {
        service.logout(null);
        service.logout(new SessionTokenRequest(null));
        service.logout(new SessionTokenRequest(""));
        service.logout(new SessionTokenRequest("malformed"));

        verifyNoInteractions(sessionRepositoryProvider, sessionRepository);
    }

    @Test
    void mapsRedisFailureToDependencyUnavailable() {
        SessionTokenService.SessionToken token = sessionTokenService.generate();
        doThrow(new org.springframework.data.redis.RedisConnectionFailureException("down"))
                .when(sessionRepository).deleteByToken(token.value());

        assertThatThrownBy(() -> service.logout(new SessionTokenRequest(token.value())))
                .isInstanceOf(DependencyUnavailableException.class);
    }

    @Test
    void doesNotUseStandaloneSessionIdAsCredential() {
        service.logout(new SessionTokenRequest(UUID.randomUUID().toString()));

        verifyNoInteractions(sessionRepositoryProvider, sessionRepository);
    }
}
