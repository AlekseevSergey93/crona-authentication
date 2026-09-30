package com.cronagroup.authentication.auth.api;

import com.cronagroup.authentication.auth.service.RefreshService;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class RefreshController {

    private final ObjectProvider<RefreshService> refreshServiceProvider;

    public RefreshController(ObjectProvider<RefreshService> refreshServiceProvider) {
        this.refreshServiceProvider = refreshServiceProvider;
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(
            @RequestBody(required = false) SessionTokenRequest request
    ) {
        RefreshService refreshService = refreshServiceProvider.getIfAvailable();
        if (refreshService == null) {
            throw new DependencyUnavailableException("Refresh dependencies are unavailable");
        }
        return ResponseEntity.ok(refreshService.refresh(request));
    }
}
