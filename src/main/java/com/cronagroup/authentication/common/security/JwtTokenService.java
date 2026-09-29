package com.cronagroup.authentication.common.security;

import com.cronagroup.authentication.config.ApplicationProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Objects;
import java.util.UUID;

@Service
public class JwtTokenService {

    private static final JWSAlgorithm SIGNING_ALGORITHM = JWSAlgorithm.RS256;
    private static final String TYPE = "JWT";

    private final ApplicationProperties.Jwt properties;
    private volatile RSAPrivateKey privateKey;
    private volatile RSAPublicKey publicKey;

    public JwtTokenService(ApplicationProperties properties) {
        this.properties = Objects.requireNonNull(properties, "properties must not be null").getJwt();
    }

    public String issue(UUID userId, UUID sessionId) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(sessionId, "sessionId must not be null");
        if (properties.getAccessTokenTtl().isZero() || properties.getAccessTokenTtl().isNegative()) {
            throw new IllegalStateException("app.jwt.access-token-ttl must be positive");
        }

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plus(properties.getAccessTokenTtl());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(userId.toString())
                .claim("sid", sessionId.toString())
                .issueTime(Date.from(issuedAt))
                .expirationTime(Date.from(expiresAt))
                .issuer(properties.getIssuer())
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(SIGNING_ALGORITHM).type(JOSEObjectType.JWT).build(),
                claims
        );
        try {
            jwt.sign(new RSASSASigner(loadPrivateKey()));
            return jwt.serialize();
        } catch (JOSEException exception) {
            throw new IllegalStateException("Unable to sign access token", exception);
        }
    }

    public AccessTokenClaims validate(String serializedToken) {
        if (serializedToken == null || serializedToken.isBlank()) {
            throw invalidToken();
        }

        final SignedJWT jwt;
        try {
            jwt = SignedJWT.parse(serializedToken);
        } catch (java.text.ParseException exception) {
            throw invalidToken(exception);
        }

        if (!SIGNING_ALGORITHM.equals(jwt.getHeader().getAlgorithm())
                || !TYPE.equals(jwt.getHeader().getType() == null ? null : jwt.getHeader().getType().getType())) {
            throw invalidToken();
        }

        try {
            JWSVerifier verifier = new RSASSAVerifier(loadPublicKey());
            if (!jwt.verify(verifier)) {
                throw invalidToken();
            }
        } catch (JOSEException exception) {
            throw invalidToken(exception);
        }

        try {
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            String issuer = claims.getIssuer();
            String subject = claims.getSubject();
            String sessionId = claims.getStringClaim("sid");
            Date issuedAt = claims.getIssueTime();
            Date expiresAt = claims.getExpirationTime();
            Instant now = Instant.now();

            if (!Objects.equals(properties.getIssuer(), issuer)
                    || subject == null
                    || sessionId == null
                    || issuedAt == null
                    || expiresAt == null
                    || !expiresAt.toInstant().isAfter(now)) {
                throw invalidToken();
            }

            return new AccessTokenClaims(
                    UUID.fromString(subject),
                    UUID.fromString(sessionId),
                    issuedAt.toInstant(),
                    expiresAt.toInstant(),
                    issuer
            );
        } catch (java.text.ParseException | IllegalArgumentException exception) {
            throw invalidToken(exception);
        }
    }

    private RSAPrivateKey loadPrivateKey() {
        RSAPrivateKey key = privateKey;
        if (key == null) {
            synchronized (this) {
                key = privateKey;
                if (key == null) {
                    privateKey = key = (RSAPrivateKey) readKey(
                            properties.getPrivateKeyPath(),
                            "PRIVATE KEY",
                            encoded -> KeyFactory.getInstance("RSA")
                                    .generatePrivate(new PKCS8EncodedKeySpec(encoded))
                    );
                }
            }
        }
        return key;
    }

    private RSAPublicKey loadPublicKey() {
        RSAPublicKey key = publicKey;
        if (key == null) {
            synchronized (this) {
                key = publicKey;
                if (key == null) {
                    publicKey = key = (RSAPublicKey) readKey(
                            properties.getPublicKeyPath(),
                            "PUBLIC KEY",
                            encoded -> KeyFactory.getInstance("RSA")
                                    .generatePublic(new X509EncodedKeySpec(encoded))
                    );
                }
            }
        }
        return key;
    }

    private static Key readKey(
            String pathValue,
            String pemType,
            KeyParser keyParser
    ) {
        if (pathValue == null || pathValue.isBlank()) {
            throw new IllegalStateException("JWT " + pemType.toLowerCase() + " path is required");
        }

        try {
            String pem = Files.readString(Path.of(pathValue), StandardCharsets.US_ASCII);
            String begin = "-----BEGIN " + pemType + "-----";
            String end = "-----END " + pemType + "-----";
            if (!pem.contains(begin) || !pem.contains(end)) {
                throw new IllegalStateException("JWT key must be a PEM " + pemType + " key");
            }

            String encoded = pem
                    .replace(begin, "")
                    .replace(end, "")
                    .replaceAll("\\s", "");
            byte[] der = Base64.getDecoder().decode(encoded);
            return keyParser.parse(der);
        } catch (IllegalArgumentException | java.io.IOException | java.security.GeneralSecurityException exception) {
            throw new IllegalStateException("Unable to load JWT " + pemType.toLowerCase() + " key", exception);
        }
    }

    private static IllegalArgumentException invalidToken() {
        return new IllegalArgumentException("Invalid access token");
    }

    private static IllegalArgumentException invalidToken(Exception cause) {
        return new IllegalArgumentException("Invalid access token", cause);
    }

    private interface KeyParser {
        Key parse(byte[] encoded) throws java.security.GeneralSecurityException;
    }

    public record AccessTokenClaims(
            UUID userId,
            UUID sessionId,
            Instant issuedAt,
            Instant expiresAt,
            String issuer
    ) {
    }
}
