package com.cronagroup.authentication.common.validation;

import java.util.Locale;
import java.util.regex.Pattern;

public final class EmailPolicy {

    public static final int MAX_LENGTH = 320;
    private static final Pattern EMAIL_PATTERN =
            Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

    private EmailPolicy() {
    }

    public static String normalizeAndValidate(String email) {
        if (email == null) {
            throw new IllegalArgumentException("email must not be null");
        }

        String normalized = email.trim().toLowerCase(Locale.ROOT);
        if (normalized.isBlank()) {
            throw new IllegalArgumentException("email must not be blank");
        }
        if (normalized.codePointCount(0, normalized.length()) > MAX_LENGTH) {
            throw new IllegalArgumentException("email must not exceed " + MAX_LENGTH + " characters");
        }
        if (!EMAIL_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("email has an invalid format");
        }
        return normalized;
    }
}
