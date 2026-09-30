package com.cronagroup.authentication.user.api;

import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.security.AuthenticatedUser;
import com.cronagroup.authentication.user.service.CurrentUserService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class CurrentUserController {

    private final ObjectProvider<CurrentUserService> currentUserServiceProvider;

    public CurrentUserController(ObjectProvider<CurrentUserService> currentUserServiceProvider) {
        this.currentUserServiceProvider = currentUserServiceProvider;
    }

    @GetMapping("/me")
    public ResponseEntity<CurrentUserResponse> me(Authentication authentication) {
        CurrentUserService currentUserService = currentUserServiceProvider.getIfAvailable();
        if (currentUserService == null) {
            throw new DependencyUnavailableException("User persistence is unavailable");
        }
        AuthenticatedUser authenticatedUser = authentication != null
                && authentication.getPrincipal() instanceof AuthenticatedUser principal
                ? principal
                : null;
        return ResponseEntity.ok(currentUserService.get(authenticatedUser));
    }
}
