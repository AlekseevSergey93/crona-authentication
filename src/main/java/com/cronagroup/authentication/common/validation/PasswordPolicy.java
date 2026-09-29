package com.cronagroup.authentication.common.validation;

import com.cronagroup.authentication.config.ApplicationProperties;
import org.springframework.stereotype.Component;

import java.util.Objects;

@Component
public class PasswordPolicy {

    private final int minLength;
    private final int maxLength;

    public PasswordPolicy(ApplicationProperties properties) {
        this.minLength = properties.getPassword().getMinLength();
        this.maxLength = properties.getPassword().getMaxLength();
        if (minLength < 1 || maxLength < minLength) {
            throw new IllegalStateException("Invalid password policy configuration");
        }
    }

    public void validate(String password) {
        Objects.requireNonNull(password, "password must not be null");

        int codePointLength = password.codePointCount(0, password.length());
        if (codePointLength < minLength || codePointLength > maxLength) {
            throw new IllegalArgumentException(
                    "password length must be between " + minLength + " and " + maxLength + " Unicode code points"
            );
        }
    }

    public int getMinLength() {
        return minLength;
    }

    public int getMaxLength() {
        return maxLength;
    }
}
