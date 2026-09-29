package com.cronagroup.authentication.common.validation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class EmailPolicyTest {

    @Test
    void trimsAndLowercasesEmail() {
        assertThat(EmailPolicy.normalizeAndValidate("  User@Example.COM "))
                .isEqualTo("user@example.com");
    }

    @Test
    void rejectsInvalidEmailFormat() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> EmailPolicy.normalizeAndValidate("user@example"));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> EmailPolicy.normalizeAndValidate("user @example.com"));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> EmailPolicy.normalizeAndValidate("user@example.com@other.com"));
    }

    @Test
    void rejectsEmailLongerThanMaximum() {
        String oversizedEmail = "a".repeat(310) + "@example.com";

        assertThatIllegalArgumentException()
                .isThrownBy(() -> EmailPolicy.normalizeAndValidate(oversizedEmail));
    }
}
