package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.common.validation.PasswordPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

@Service
public class PasswordHashingService {

    private final PasswordEncoder passwordEncoder;
    private final PasswordPolicy passwordPolicy;
    private final String dummyPasswordHash;

    public PasswordHashingService(
            PasswordEncoder passwordEncoder,
            PasswordPolicy passwordPolicy
    ) {
        this.passwordEncoder = passwordEncoder;
        this.passwordPolicy = passwordPolicy;
        this.dummyPasswordHash = passwordEncoder.encode("authentication-dummy-password");
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

    public boolean matchesOrDummy(String rawPassword, String passwordHash) {
        Objects.requireNonNull(rawPassword, "rawPassword must not be null");
        return passwordEncoder.matches(
                rawPassword,
                passwordHash == null ? dummyPasswordHash : passwordHash
        );
    }
}
