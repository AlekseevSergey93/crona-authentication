package com.cronagroup.authentication.common.security;

import java.util.UUID;

public record AuthenticatedUser(
        UUID userId,
        UUID sessionId
) {
}
