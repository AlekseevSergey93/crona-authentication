package com.cronagroup.authentication.auth.service;

import com.cronagroup.authentication.auth.api.RegistrationRequest;
import com.cronagroup.authentication.auth.api.TokenResponse;
import com.cronagroup.authentication.common.error.ApiException;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.security.JwtTokenService;
import com.cronagroup.authentication.common.security.PasswordHashingService;
import com.cronagroup.authentication.common.security.RedisSessionRepository;
import com.cronagroup.authentication.common.security.SessionTokenService;
import com.cronagroup.authentication.common.validation.EmailPolicy;
import com.cronagroup.authentication.user.domain.User;
import com.cronagroup.authentication.user.repository.UserRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RegistrationService {

    private final ObjectProvider<UserRepository> userRepositoryProvider;
    private final PasswordHashingService passwordHashingService;
    private final SessionTokenService sessionTokenService;
    private final ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private final JwtTokenService jwtTokenService;
    private final Duration accessTokenTtl;

    public RegistrationService(
            ObjectProvider<UserRepository> userRepositoryProvider,
            PasswordHashingService passwordHashingService,
            SessionTokenService sessionTokenService,
            ObjectProvider<RedisSessionRepository> sessionRepositoryProvider,
            JwtTokenService jwtTokenService,
            com.cronagroup.authentication.config.ApplicationProperties properties
    ) {
        this.userRepositoryProvider = userRepositoryProvider;
        this.passwordHashingService = passwordHashingService;
        this.sessionTokenService = sessionTokenService;
        this.sessionRepositoryProvider = sessionRepositoryProvider;
        this.jwtTokenService = jwtTokenService;
        this.accessTokenTtl = properties.getJwt().getAccessTokenTtl();
        if (accessTokenTtl.isZero() || accessTokenTtl.isNegative()) {
            throw new IllegalArgumentException("Access token TTL must be positive");
        }
    }

    public TokenResponse register(RegistrationRequest request) {
        if (request == null) {
            throw validationError("Request body is invalid");
        }
        String normalizedEmail = normalizeEmail(request.email());
        String passwordHash = hashPassword(request.password());
        User user = User.create(normalizedEmail, passwordHash);

        try {
            UserRepository userRepository = userRepositoryProvider.getIfAvailable();
            if (userRepository == null) {
                throw new DependencyUnavailableException("User persistence is unavailable");
            }
            userRepository.saveNew(user);
        } catch (DataAccessException exception) {
            throw new DependencyUnavailableException("User persistence is unavailable");
        }

        SessionTokenService.SessionToken sessionToken = sessionTokenService.generate();
        try {
            RedisSessionRepository sessionRepository = sessionRepositoryProvider.getIfAvailable();
            if (sessionRepository == null) {
                throw new DependencyUnavailableException("Session persistence is unavailable");
            }
            sessionRepository.create(user.getId(), sessionToken);
        } catch (DataAccessException | DependencyUnavailableException exception) {
            compensateUserCreation(userRepositoryProvider.getIfAvailable(), user);
            throw new DependencyUnavailableException("Session persistence is unavailable");
        }

        String accessToken = jwtTokenService.issue(user.getId(), sessionToken.sessionId());
        return new TokenResponse(
                accessToken,
                sessionToken.value(),
                "Bearer",
                accessTokenTtl.toSeconds()
        );
    }

    private static void compensateUserCreation(UserRepository userRepository, User user) {
        if (userRepository == null) {
            throw new DependencyUnavailableException("User persistence is unavailable");
        }
        try {
            userRepository.deleteById(user.getId());
        } catch (DataAccessException exception) {
            throw new DependencyUnavailableException("User persistence is unavailable");
        }
    }

    private static String normalizeEmail(String email) {
        try {
            return EmailPolicy.normalizeAndValidate(email);
        } catch (IllegalArgumentException exception) {
            throw validationError("Email is invalid");
        }
    }

    private String hashPassword(String password) {
        if (password == null) {
            throw validationError("Password is invalid");
        }
        try {
            return passwordHashingService.hash(password);
        } catch (IllegalArgumentException exception) {
            throw validationError("Password is invalid");
        }
    }

    private static ApiException validationError(String message) {
        return new ApiException(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", message);
    }
}
