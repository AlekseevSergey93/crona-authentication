package com.cronagroup.authentication.auth.service;

import com.cronagroup.authentication.auth.api.SessionTokenRequest;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.security.RedisSessionRepository;
import com.cronagroup.authentication.common.security.SessionTokenService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.stereotype.Service;

@Service
public class LogoutService {

    private final ObjectProvider<RedisSessionRepository> sessionRepositoryProvider;
    private final SessionTokenService sessionTokenService;

    public LogoutService(
            ObjectProvider<RedisSessionRepository> sessionRepositoryProvider,
            SessionTokenService sessionTokenService
    ) {
        this.sessionRepositoryProvider = sessionRepositoryProvider;
        this.sessionTokenService = sessionTokenService;
    }

    public void logout(SessionTokenRequest request) {
        if (request == null
                || request.sessionToken() == null
                || sessionTokenService.extractSessionId(request.sessionToken()).isEmpty()) {
            return;
        }

        RedisSessionRepository sessionRepository = sessionRepositoryProvider.getIfAvailable();
        if (sessionRepository == null) {
            throw new DependencyUnavailableException("Session persistence is unavailable");
        }

        try {
            sessionRepository.deleteByToken(request.sessionToken());
        } catch (DataAccessException exception) {
            throw new DependencyUnavailableException("Session persistence is unavailable");
        }
    }
}
