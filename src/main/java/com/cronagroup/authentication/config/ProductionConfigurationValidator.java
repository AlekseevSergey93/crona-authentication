package com.cronagroup.authentication.config;

import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;

@Component
@Profile("prod")
public class ProductionConfigurationValidator {

    private final ApplicationProperties properties;

    public ProductionConfigurationValidator(ApplicationProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void validate() {
        ApplicationProperties.Jwt jwt = properties.getJwt();
        requireReadableFile(jwt.getPrivateKeyPath(), "app.jwt.private-key-path");
        requireReadableFile(jwt.getPublicKeyPath(), "app.jwt.public-key-path");

        if (jwt.getAccessTokenTtl().isZero() || jwt.getAccessTokenTtl().isNegative()) {
            throw new IllegalStateException("app.jwt.access-token-ttl must be positive");
        }
        if (jwt.getSessionTtl().isZero() || jwt.getSessionTtl().isNegative()) {
            throw new IllegalStateException("app.jwt.session-ttl must be positive");
        }
        if (properties.getPassword().getMinLength() > properties.getPassword().getMaxLength()) {
            throw new IllegalStateException("app.password.min-length must not exceed max-length");
        }
    }

    private void requireReadableFile(String value, String propertyName) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(propertyName + " is required when the prod profile is active");
        }

        Path path = Path.of(value);
        if (!Files.isRegularFile(path) || !Files.isReadable(path)) {
            throw new IllegalStateException(propertyName + " must point to a readable file");
        }
    }
}
