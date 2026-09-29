package com.cronagroup.authentication.common.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class SessionTokenServiceTest {

    private SessionTokenService service;

    @BeforeEach
    void setUp() {
        service = new SessionTokenService();
    }

    @Test
    void generatesUrlSafeUnpaddedTokenWithAtLeast32RandomBytes() {
        SessionTokenService.SessionToken generated = service.generate();

        assertThat(generated.value()).matches("[A-Za-z0-9_-]+");
        assertThat(generated.value()).doesNotContain("=");
        assertThat(Base64.getUrlDecoder().decode(generated.value())).hasSize(49);
    }

    @Test
    void recoversSessionIdFromGeneratedToken() {
        SessionTokenService.SessionToken generated = service.generate();

        assertThat(service.extractSessionId(generated.value()))
                .contains(generated.sessionId());
    }

    @Test
    void generatesIndependentSessionIdsAndTokens() {
        SessionTokenService.SessionToken first = service.generate();
        SessionTokenService.SessionToken second = service.generate();

        assertThat(second.sessionId()).isNotEqualTo(first.sessionId());
        assertThat(second.value()).isNotEqualTo(first.value());
    }

    @Test
    void rejectsMalformedTokensBeforeTheyCanBeUsedForLookup() {
        SessionTokenService.SessionToken generated = service.generate();
        char replacement = generated.value().charAt(0) == 'A' ? 'B' : 'A';
        String tamperedToken = replacement + generated.value().substring(1);

        assertThat(service.extractSessionId(null)).isEmpty();
        assertThat(service.extractSessionId("not-a-token")).isEmpty();
        assertThat(service.extractSessionId(generated.value() + "=")).isEmpty();
        assertThat(service.extractSessionId(tamperedToken)).isEmpty();
        assertThat(service.extractSessionId("")).isEmpty();
    }

    @Test
    void doesNotAcceptPayloadWithUnsupportedVersion() {
        byte[] payload = Base64.getUrlDecoder().decode(service.generate().value());
        payload[0] = 2;
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);

        assertThat(service.extractSessionId(token)).isEmpty();
    }

    @Test
    void preservesUuidBitsWhenRecoveringSessionId() {
        SessionTokenService.SessionToken generated = service.generate();
        UUID recovered = service.extractSessionId(generated.value()).orElseThrow();

        assertThat(recovered.getMostSignificantBits()).isEqualTo(generated.sessionId().getMostSignificantBits());
        assertThat(recovered.getLeastSignificantBits()).isEqualTo(generated.sessionId().getLeastSignificantBits());
    }
}
