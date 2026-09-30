package com.cronagroup.authentication.auth.service;

import com.cronagroup.authentication.auth.api.SessionTokenRequest;
import com.cronagroup.authentication.auth.api.TokenResponse;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.error.InvalidSessionException;
import com.cronagroup.authentication.common.security.JwtTokenService;
import com.cronagroup.authentication.common.security.RedisSessionRepository;
import com.cronagroup.authentication.config.ApplicationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class RefreshService {

    private final ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private final JwtTokenService jwtTokenService;
    private final Duration accessTokenTtl;

    public RefreshService(
            ObjectProvider<RedisSessionRepository> sessionRepositoryProvider,
            JwtTokenService jwtTokenService,
            ApplicationProperties properties
    ) {
        this.sessionRepositoryProvider = sessionRepositoryProvider;
        this.jwtTokenService = jwtTokenService;
        this.accessTokenTtl = properties.getJwt().getAccessTokenTtl();
        if (accessTokenTtl.isZero() || accessTokenTtl.isNegative()) {
            throw new IllegalArgumentException("Access token TTL must be positive");
        }
    }

    public TokenResponse refresh(SessionTokenRequest request) {
        if (request == null || request.sessionToken() == null) {
            throw new InvalidSessionException();
        }

        RedisSessionRepository.RotatedSession rotated;
        try {
            RedisSessionRepository sessionRepository = sessionRepositoryProvider.getIfAvailable();
            if (sessionRepository == null) {
                throw new DependencyUnavailableException("Session persistence is unavailable");
            }
            rotated = sessionRepository.rotate(request.sessionToken()).orElse(null);
        } catch (DataAccessException exception) {
            throw new DependencyUnavailableException("Session persistence is unavailable");
        }
        if (rotated == null) {
            throw new InvalidSessionException();
        }

        String accessToken = jwtTokenService.issue(
                rotated.session().userId(),
                rotated.session().sessionId()
        );
        return new TokenResponse(
                accessToken,
                rotated.replacementToken().value(),
                "Bearer",
                accessTokenTtl.toSeconds()
        );
    }
}
