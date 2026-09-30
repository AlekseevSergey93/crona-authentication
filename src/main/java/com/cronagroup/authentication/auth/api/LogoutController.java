package com.cronagroup.authentication.auth.api;

import com.cronagroup.authentication.auth.service.LogoutService;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class LogoutController {

    private final ObjectProvider<LogoutService> logoutServiceProvider;

    public LogoutController(ObjectProvider<LogoutService> logoutServiceProvider) {
        this.logoutServiceProvider = logoutServiceProvider;
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestBody(required = false) SessionTokenRequest request
    ) {
        LogoutService logoutService = logoutServiceProvider.getIfAvailable();
        if (logoutService == null) {
            throw new DependencyUnavailableException("Logout dependencies are unavailable");
        }
        logoutService.logout(request);
        return ResponseEntity.noContent().build();
    }
}
