package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.common.validation.PasswordPolicy;
import com.cronagroup.authentication.config.ApplicationProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class PasswordHashingServiceTest {

    private PasswordHashingService service;

    @BeforeEach
    void setUp() {
        service = new PasswordHashingService(
                Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8(),
                new PasswordPolicy(new ApplicationProperties())
        );
    }

    @Test
    void hashesPasswordWithArgon2idAndMatchesOnlyOriginalPassword() {
        String rawPassword = "correct horse battery staple";

        String hash = service.hash(rawPassword);

        assertThat(hash).startsWith("$argon2id$");
        assertThat(hash).isNotEqualTo(rawPassword);
        assertThat(service.matches(rawPassword, hash)).isTrue();
        assertThat(service.matches("incorrect horse battery staple", hash)).isFalse();
    }

    @Test
    void generatesDifferentHashesForSamePassword() {
        String rawPassword = "correct horse battery staple";

        String firstHash = service.hash(rawPassword);
        String secondHash = service.hash(rawPassword);

        assertThat(firstHash).isNotEqualTo(secondHash);
        assertThat(service.matches(rawPassword, firstHash)).isTrue();
        assertThat(service.matches(rawPassword, secondHash)).isTrue();
    }

    @Test
    void validatesPasswordPolicyBeforeHashing() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> service.hash("too-short"));
    }
}
