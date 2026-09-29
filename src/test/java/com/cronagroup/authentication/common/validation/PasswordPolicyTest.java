package com.cronagroup.authentication.common.validation;

import com.cronagroup.authentication.config.ApplicationProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class PasswordPolicyTest {

    private final PasswordPolicy policy = new PasswordPolicy(new ApplicationProperties());

    @Test
    void acceptsPasswordWithinConfiguredCodePointBounds() {
        policy.validate("a".repeat(12));
        policy.validate("😀".repeat(12));

        assertThat(policy.getMinLength()).isEqualTo(12);
        assertThat(policy.getMaxLength()).isEqualTo(128);
    }

    @Test
    void rejectsPasswordOutsideConfiguredCodePointBounds() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> policy.validate("a".repeat(11)));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> policy.validate("a".repeat(129)));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> policy.validate("😀".repeat(11)));
    }

    @Test
    void rejectsNullPassword() {
        assertThatNullPointerException()
                .isThrownBy(() -> policy.validate(null));
    }
}
