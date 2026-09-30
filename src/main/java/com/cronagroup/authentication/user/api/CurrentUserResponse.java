package com.cronagroup.authentication.user.api;

import java.util.UUID;

public record CurrentUserResponse(
        UUID id,
        String email
) {
}
