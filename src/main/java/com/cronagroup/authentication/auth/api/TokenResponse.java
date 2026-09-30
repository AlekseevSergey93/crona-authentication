package com.cronagroup.authentication.auth.api;

public record TokenResponse(
        String accessToken,
        String sessionToken,
        String tokenType,
        long expiresIn
) {
}
