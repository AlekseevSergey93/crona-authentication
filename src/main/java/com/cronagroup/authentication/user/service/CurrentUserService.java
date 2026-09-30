package com.cronagroup.authentication.user.service;

import com.cronagroup.authentication.common.error.ApiException;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.security.AuthenticatedUser;
import com.cronagroup.authentication.user.api.CurrentUserResponse;
import com.cronagroup.authentication.user.domain.User;
import com.cronagroup.authentication.user.repository.UserRepository;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class CurrentUserService {

    private final ObjectProvider<UserRepository> userRepositoryProvider;

    public CurrentUserService(ObjectProvider<UserRepository> userRepositoryProvider) {
        this.userRepositoryProvider = userRepositoryProvider;
    }

    public CurrentUserResponse get(AuthenticatedUser authenticatedUser) {
        if (authenticatedUser == null) {
            throw unauthorized();
        }

        UserRepository userRepository = userRepositoryProvider.getIfAvailable();
        if (userRepository == null) {
            throw new DependencyUnavailableException("User persistence is unavailable");
        }

        try {
            return userRepository.findById(authenticatedUser.userId())
                    .map(user -> new CurrentUserResponse(user.getId(), user.getEmail()))
                    .orElseThrow(CurrentUserService::unauthorized);
        } catch (DataAccessException exception) {
            throw new DependencyUnavailableException("User persistence is unavailable");
        }
    }

    private static ApiException unauthorized() {
        return new ApiException(HttpStatus.UNAUTHORIZED, "UNAUTHORIZED", "Authentication is required");
    }
}
