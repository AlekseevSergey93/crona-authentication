package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.config.ApplicationProperties;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class JwtTokenServiceTest {

    @TempDir
    Path tempDir;

    private ApplicationProperties properties;
    private JwtTokenService service;
    private UUID userId;
    private UUID sessionId;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();

        Path privateKey = tempDir.resolve("jwt-private.pem");
        Path publicKey = tempDir.resolve("jwt-public.pem");
        Files.writeString(privateKey, pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
        Files.writeString(publicKey, pem("PUBLIC KEY", keyPair.getPublic().getEncoded()));

        properties = new ApplicationProperties();
        properties.getJwt().setIssuer("test-issuer");
        properties.getJwt().setPrivateKeyPath(privateKey.toString());
        properties.getJwt().setPublicKeyPath(publicKey.toString());
        properties.getJwt().setAccessTokenTtl(Duration.ofMinutes(5));
        service = new JwtTokenService(properties);
        userId = UUID.randomUUID();
        sessionId = UUID.randomUUID();
    }

    @Test
    void issuesAndValidatesRs256TokenWithRequiredClaims() {
        String token = service.issue(userId, sessionId);

        JwtTokenService.AccessTokenClaims claims = service.validate(token);

        assertThat(claims.userId()).isEqualTo(userId);
        assertThat(claims.sessionId()).isEqualTo(sessionId);
        assertThat(claims.issuer()).isEqualTo("test-issuer");
        assertThat(claims.issuedAt()).isBeforeOrEqualTo(Instant.now());
        assertThat(claims.expiresAt()).isAfter(Instant.now());
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .claim("sid", sessionId.toString())
                .issueTime(Date.from(Instant.now().minusSeconds(120)))
                .expirationTime(Date.from(Instant.now().minusSeconds(60)))
                .issuer("test-issuer")
                .build());

        assertThatIllegalArgumentException().isThrownBy(() -> service.validate(token));
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        String token = sign(new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .claim("sid", sessionId.toString())
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .issuer("wrong-issuer")
                .build());

        assertThatIllegalArgumentException().isThrownBy(() -> service.validate(token));
    }

    @Test
    void rejectsTamperedSignature() {
        String token = service.issue(userId, sessionId);
        String[] parts = token.split("\\.");
        char replacement = parts[2].charAt(0) == 'A' ? 'B' : 'A';
        parts[2] = replacement + parts[2].substring(1);

        assertThatIllegalArgumentException().isThrownBy(() -> service.validate(String.join(".", parts)));
    }

    @Test
    void rejectsWrongSigningAlgorithm() throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .claim("sid", sessionId.toString())
                .issueTime(new Date())
                .expirationTime(Date.from(Instant.now().plusSeconds(300)))
                .issuer("test-issuer")
                .build();
        SignedJWT token = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
        token.sign(new MACSigner(new byte[32]));

        assertThatIllegalArgumentException().isThrownBy(() -> service.validate(token.serialize()));
    }

    @Test
    void rejectsMalformedAndMissingTokens() {
        assertThatIllegalArgumentException().isThrownBy(() -> service.validate(null));
        assertThatIllegalArgumentException().isThrownBy(() -> service.validate("not-a-jwt"));
    }

    private String sign(JWTClaimsSet claims) throws Exception {
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                claims
        );
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair keyPair = generator.generateKeyPair();
        jwt.sign(new RSASSASigner(keyPair.getPrivate()));

        // Replace the service's public key file with the matching key for this test token.
        Files.writeString(
                Path.of(properties.getJwt().getPublicKeyPath()),
                pem("PUBLIC KEY", keyPair.getPublic().getEncoded())
        );
        return jwt.serialize();
    }

    private static String pem(String type, byte[] encoded) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }
}
