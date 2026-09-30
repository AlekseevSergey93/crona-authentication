package com.cronagroup.authentication.auth.service;

import com.cronagroup.authentication.auth.api.RegistrationRequest;
import com.cronagroup.authentication.auth.api.TokenResponse;
import com.cronagroup.authentication.common.error.ApiException;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.error.DuplicateUserException;
import com.cronagroup.authentication.common.security.JwtTokenService;
import com.cronagroup.authentication.common.security.PasswordHashingService;
import com.cronagroup.authentication.common.security.RedisSessionRepository;
import com.cronagroup.authentication.common.security.SessionTokenService;
import com.cronagroup.authentication.config.ApplicationProperties;
import com.cronagroup.authentication.user.domain.User;
import com.cronagroup.authentication.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.time.Duration;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class RegistrationServiceTest {

    private UserRepository userRepository;
    private PasswordHashingService passwordHashingService;
    private SessionTokenService sessionTokenService;
    private RedisSessionRepository sessionRepository;
    private ObjectProvider<UserRepository> userRepositoryProvider;
    private ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private JwtTokenService jwtTokenService;
    private RegistrationService service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        passwordHashingService = mock(PasswordHashingService.class);
        sessionTokenService = mock(SessionTokenService.class);
        sessionRepository = mock(RedisSessionRepository.class);
        userRepositoryProvider = mock(ObjectProvider.class);
        sessionRepositoryProvider = mock(ObjectProvider.class);
        when(userRepositoryProvider.getIfAvailable()).thenReturn(userRepository);
        when(sessionRepositoryProvider.getIfAvailable()).thenReturn(sessionRepository);
        jwtTokenService = mock(JwtTokenService.class);

        ApplicationProperties properties = new ApplicationProperties();
        properties.getJwt().setAccessTokenTtl(Duration.ofMinutes(15));
        service = new RegistrationService(
                userRepositoryProvider,
                passwordHashingService,
                sessionTokenService,
                sessionRepositoryProvider,
                jwtTokenService,
                properties
        );
    }

    @Test
    void persistsUserCreatesSessionAndIssuesJwtInOrder() {
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        User user = User.create("user@example.com", "hash");
        SessionTokenService.SessionToken sessionToken =
                new SessionTokenService.SessionToken(sessionId, "session-token");

        when(passwordHashingService.hash("correct horse battery staple")).thenReturn("hash");
        when(sessionTokenService.generate()).thenReturn(sessionToken);
        when(jwtTokenService.issue(any(), eq(sessionId))).thenReturn("access-token");
        doAnswer(invocation -> {
            User saved = invocation.getArgument(0);
            assertThat(saved.getEmail()).isEqualTo("user@example.com");
            assertThat(saved.getPasswordHash()).isEqualTo("hash");
            return saved;
        }).when(userRepository).saveNew(any(User.class));

        TokenResponse response = service.register(
                new RegistrationRequest(" User@Example.COM ", "correct horse battery staple")
        );

        assertThat(response).isEqualTo(new TokenResponse("access-token", "session-token", "Bearer", 900));
        verify(sessionRepository).create(any(UUID.class), same(sessionToken));
        verify(jwtTokenService).issue(any(UUID.class), eq(sessionId));
        verify(userRepository, never()).deleteById(any(UUID.class));
    }

    @Test
    void rejectsInvalidEmailOrPasswordBeforePersistence() {
        assertThatThrownBy(() -> service.register(new RegistrationRequest("invalid", "valid password")))
                .isInstanceOf(ApiException.class)
                .hasMessage("Email is invalid");
        when(passwordHashingService.hash("short"))
                .thenThrow(new IllegalArgumentException("password is too short"));
        assertThatThrownBy(() -> service.register(new RegistrationRequest("user@example.com", "short")))
                .isInstanceOf(ApiException.class)
                .hasMessage("Password is invalid");

        verifyNoInteractions(userRepository, sessionRepository, jwtTokenService);
    }

    @Test
    void mapsDuplicateEmailWithoutCreatingSession() {
        when(passwordHashingService.hash(anyString())).thenReturn("hash");
        doThrow(new DuplicateUserException()).when(userRepository).saveNew(any(User.class));

        assertThatThrownBy(() -> service.register(
                new RegistrationRequest("user@example.com", "correct horse battery staple")
        )).isInstanceOf(DuplicateUserException.class);

        verifyNoInteractions(sessionRepository, jwtTokenService);
    }

    @Test
    void failsWithoutAuthenticationSuccessWhenRedisIsUnavailable() {
        when(passwordHashingService.hash(anyString())).thenReturn("hash");
        when(sessionTokenService.generate()).thenReturn(
                new SessionTokenService.SessionToken(UUID.randomUUID(), "session-token")
        );
        doThrow(new org.springframework.data.redis.RedisConnectionFailureException("down"))
                .when(sessionRepository).create(any(UUID.class), any());

        assertThatThrownBy(() -> service.register(
                new RegistrationRequest("user@example.com", "correct horse battery staple")
        )).isInstanceOf(DependencyUnavailableException.class);

        verifyNoInteractions(jwtTokenService);
        verify(userRepository).deleteById(any(UUID.class));
    }
}
