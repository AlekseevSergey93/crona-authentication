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
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Optional;

@Service
@ConditionalOnBean({UserRepository.class, RedisSessionRepository.class})
public class LoginService {

    private static final String INVALID_CREDENTIALS_MESSAGE = "Invalid email or password";

    private final UserRepository userRepository;
    private final PasswordHashingService passwordHashingService;
    private final SessionTokenService sessionTokenService;
    private final RedisSessionRepository sessionRepository;
    private final JwtTokenService jwtTokenService;
    private final Duration accessTokenTtl;

    public LoginService(
            UserRepository userRepository,
            PasswordHashingService passwordHashingService,
            SessionTokenService sessionTokenService,
            RedisSessionRepository sessionRepository,
            JwtTokenService jwtTokenService,
            com.cronagroup.authentication.config.ApplicationProperties properties
    ) {
        this.userRepository = userRepository;
        this.passwordHashingService = passwordHashingService;
        this.sessionTokenService = sessionTokenService;
        this.sessionRepository = sessionRepository;
        this.jwtTokenService = jwtTokenService;
        this.accessTokenTtl = properties.getJwt().getAccessTokenTtl();
        if (accessTokenTtl.isZero() || accessTokenTtl.isNegative()) {
            throw new IllegalArgumentException("Access token TTL must be positive");
        }
    }

    public TokenResponse login(RegistrationRequest request) {
        if (request == null || request.password() == null) {
            throw invalidCredentials();
        }
        String normalizedEmail = normalizeEmail(request.email());

        Optional<User> user;
        try {
            user = userRepository.findByEmail(normalizedEmail);
        } catch (DataAccessException exception) {
            throw new DependencyUnavailableException("User persistence is unavailable");
        }

        User existingUser = user.orElse(null);
        boolean passwordMatches = passwordHashingService.matchesOrDummy(
                request.password(),
                existingUser == null ? null : existingUser.getPasswordHash()
        );
        if (existingUser == null || !passwordMatches) {
            throw invalidCredentials();
        }

        SessionTokenService.SessionToken sessionToken = sessionTokenService.generate();
        try {
            sessionRepository.create(existingUser.getId(), sessionToken);
        } catch (DataAccessException exception) {
            throw new DependencyUnavailableException("Session persistence is unavailable");
        }

        String accessToken = jwtTokenService.issue(existingUser.getId(), sessionToken.sessionId());
        return new TokenResponse(
                accessToken,
                sessionToken.value(),
                "Bearer",
                accessTokenTtl.toSeconds()
        );
    }

    private static String normalizeEmail(String email) {
        try {
            return EmailPolicy.normalizeAndValidate(email);
        } catch (IllegalArgumentException exception) {
            throw new ApiException(HttpStatus.BAD_REQUEST, "VALIDATION_ERROR", "Email is invalid");
        }
    }

    private static ApiException invalidCredentials() {
        return new ApiException(
                HttpStatus.UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                INVALID_CREDENTIALS_MESSAGE
        );
    }
}
