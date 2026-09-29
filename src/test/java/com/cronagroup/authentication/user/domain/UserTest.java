package com.cronagroup.authentication.user.domain;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class UserTest {

    @Test
    void normalizesEmailWhenCreatingUser() {
        User user = User.create("  User@Example.COM ", "argon2-hash");

        assertThat(user.getEmail()).isEqualTo("user@example.com");
        assertThat(user.getId()).isNotNull();
    }

    @Test
    void rejectsBlankOrOversizedEmail() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> User.create("   ", "argon2-hash"));

        String oversizedEmail = "a".repeat(321);
        assertThatIllegalArgumentException()
                .isThrownBy(() -> User.create(oversizedEmail, "argon2-hash"));
    }

    @Test
    void initializesAndUpdatesUtcTimestamps() throws Exception {
        User user = User.create("user@example.com", "argon2-hash");
        Method initialize = User.class.getDeclaredMethod("initializeTimestamps");
        initialize.setAccessible(true);
        initialize.invoke(user);

        assertThat(user.getCreatedAt()).isNotNull();
        assertThat(user.getUpdatedAt()).isNotNull();

        var firstUpdatedAt = user.getUpdatedAt();
        Thread.sleep(1);

        Method update = User.class.getDeclaredMethod("updateTimestamp");
        update.setAccessible(true);
        update.invoke(user);

        assertThat(user.getUpdatedAt()).isAfter(firstUpdatedAt);
        assertThat(user.getCreatedAt()).isBeforeOrEqualTo(user.getUpdatedAt());
    }
}
