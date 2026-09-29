package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.common.validation.PasswordPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class PasswordHashingService {

    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;

    public PasswordHashingService(
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy
    ) {
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
    }

    public String hash(String rawPassword) {
        passwordPolicy.validate(rawPassword);
        return passwordEncoder.encode(rawPassword);
    }

    public boolean matches(String rawPassword, String passwordHash) {
        Objects.requireNonNull(rawPassword, "rawPassword must not be null");
        Objects.requireNonNull(passwordHash, "passwordHash must not be null");
        return passwordEncoder.matches(rawPassword, passwordHash);
    }
}
