package com.cronagroup.authentication.auth.service;

import com.cronagroup.authentication.auth.api.RegistrationRequest;
import com.cronagroup.authentication.auth.api.TokenResponse;
import com.cronagroup.authentication.common.error.ApiException;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
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
import org.springframework.http.HttpStatus;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

class LoginServiceTest {

    private UserRepository userRepository;
    private PasswordHashingService passwordHashingService;
    private SessionTokenService sessionTokenService;
    private RedisSessionRepository sessionRepository;
    private ObjectProvider<UserRepository> userRepositoryProvider;
    private ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private JwtTokenService jwtTokenService;
    private LoginService service;

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
        service = new LoginService(
                userRepositoryProvider,
                passwordHashingService,
                sessionTokenService,
                sessionRepositoryProvider,
                jwtTokenService,
                properties
        );
    }

    @Test
    void createsIndependentSessionAndReturnsTokenResponseForValidCredentials() {
        User user = User.create("user@example.com", "hash");
        SessionTokenService.SessionToken sessionToken =
                new SessionTokenService.SessionToken(UUID.randomUUID(), "session-token");
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordHashingService.matchesOrDummy("correct horse battery staple", "hash"))
                .thenReturn(true);
        when(sessionTokenService.generate()).thenReturn(sessionToken);
        when(jwtTokenService.issue(user.getId(), sessionToken.sessionId())).thenReturn("access-token");

        TokenResponse response = service.login(
                new RegistrationRequest(" User@Example.COM ", "correct horse battery staple")
        );

        assertThat(response).isEqualTo(new TokenResponse("access-token", "session-token", "Bearer", 900));
        verify(sessionRepository).create(user.getId(), sessionToken);
        verify(jwtTokenService).issue(user.getId(), sessionToken.sessionId());
    }

    @Test
    void returnsSameInvalidCredentialsErrorForUnknownUserAndWrongPassword() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());
        when(passwordHashingService.matchesOrDummy("password", null)).thenReturn(false);

        ApiException unknownUser = (ApiException) assertThatThrownBy(() -> service.login(
                new RegistrationRequest("missing@example.com", "password")
        )).isInstanceOf(ApiException.class).actual();

        User user = User.create("user@example.com", "hash");
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordHashingService.matchesOrDummy("password", "hash")).thenReturn(false);

        ApiException wrongPassword = (ApiException) assertThatThrownBy(() -> service.login(
                new RegistrationRequest("user@example.com", "password")
        )).isInstanceOf(ApiException.class).actual();

        assertThat(unknownUser.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(unknownUser.getCode()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(wrongPassword.getStatus()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(wrongPassword.getCode()).isEqualTo("INVALID_CREDENTIALS");
        assertThat(unknownUser.getMessage()).isEqualTo(wrongPassword.getMessage());
        verifyNoInteractions(sessionRepository, jwtTokenService);
    }

    @Test
    void mapsRedisFailureAndDoesNotIssueJwt() {
        User user = User.create("user@example.com", "hash");
        SessionTokenService.SessionToken sessionToken =
                new SessionTokenService.SessionToken(UUID.randomUUID(), "session-token");
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(passwordHashingService.matchesOrDummy("password", "hash")).thenReturn(true);
        when(sessionTokenService.generate()).thenReturn(sessionToken);
        doThrow(new org.springframework.data.redis.RedisConnectionFailureException("down"))
                .when(sessionRepository).create(user.getId(), sessionToken);

        assertThatThrownBy(() -> service.login(
                new RegistrationRequest("user@example.com", "password")
        )).isInstanceOf(DependencyUnavailableException.class);
        verifyNoInteractions(jwtTokenService);
    }
}
