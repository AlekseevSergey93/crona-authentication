package com.cronagroup.authentication.auth.api;

import jakarta.validation.constraints.NotBlank;

public record RegistrationRequest(
        @NotBlank String email,
        @NotBlank String password
) {
}
