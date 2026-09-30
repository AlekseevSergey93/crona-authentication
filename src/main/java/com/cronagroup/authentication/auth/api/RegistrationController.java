package com.cronagroup.authentication.auth.api;

import com.cronagroup.authentication.auth.service.RegistrationService;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/auth")
public class RegistrationController {

    private final ObjectProvider<RegistrationService> registrationServiceProvider;

    public RegistrationController(ObjectProvider<RegistrationService> registrationServiceProvider) {
        this.registrationServiceProvider = registrationServiceProvider;
    }

    @PostMapping("/register")
    public ResponseEntity<TokenResponse> register(@Valid @RequestBody RegistrationRequest request) {
        RegistrationService registrationService = registrationServiceProvider.getIfAvailable();
        if (registrationService == null) {
            throw new DependencyUnavailableException("Registration dependencies are unavailable");
        }
        TokenResponse response = registrationService.register(request);
        return ResponseEntity
                .created(URI.create("/api/auth/register"))
                .body(response);
    }
}
