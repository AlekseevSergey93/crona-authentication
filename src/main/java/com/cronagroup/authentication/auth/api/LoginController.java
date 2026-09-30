package com.cronagroup.authentication.auth.api;

import com.cronagroup.authentication.auth.service.LoginService;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import jakarta.validation.Valid;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
public class LoginController {

    private final ObjectProvider<LoginService> loginServiceProvider;

    public LoginController(ObjectProvider<LoginService> loginServiceProvider) {
        this.loginServiceProvider = loginServiceProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody RegistrationRequest request) {
        LoginService loginService = loginServiceProvider.getIfAvailable();
        if (loginService == null) {
            throw new DependencyUnavailableException("Login dependencies are unavailable");
        }
        return ResponseEntity.ok(loginService.login(request));
    }
}
