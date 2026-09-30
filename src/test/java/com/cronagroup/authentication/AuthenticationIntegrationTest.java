package com.cronagroup.authentication;

import com.cronagroup.authentication.common.security.SessionTokenService;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Testcontainers
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AuthenticationIntegrationTest {

    private static final String PASSWORD = "correct horse battery staple";
    private static final Duration SESSION_TTL = Duration.ofSeconds(30);

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:16-alpine")
                    .withDatabaseName("auth")
                    .withUsername("auth")
                    .withPassword("auth");

    @Container
    static final GenericContainer<?> REDIS =
            new GenericContainer<>("redis:7-alpine")
                    .withExposedPorts(6379)
                    .withCommand("redis-server", "--appendonly", "yes");

    private static final KeyMaterial KEY_MATERIAL = KeyMaterial.create();

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private StringRedisTemplate redisTemplate;

    @Autowired
    private SessionTokenService sessionTokenService;

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("app.database.url", POSTGRES::getJdbcUrl);
        registry.add("app.database.username", POSTGRES::getUsername);
        registry.add("app.database.password", POSTGRES::getPassword);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("app.redis.host", REDIS::getHost);
        registry.add("app.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("app.jwt.private-key-path", () -> KEY_MATERIAL.privateKey().toString());
        registry.add("app.jwt.public-key-path", () -> KEY_MATERIAL.publicKey().toString());
        registry.add("app.jwt.access-token-ttl", () -> "PT5S");
        registry.add("app.jwt.session-ttl", () -> SESSION_TTL.toString());
        registry.add("spring.liquibase.enabled", () -> "true");
    }

    @AfterAll
    static void deleteKeyMaterial() throws IOException {
        Files.deleteIfExists(KEY_MATERIAL.privateKey());
        Files.deleteIfExists(KEY_MATERIAL.publicKey());
    }

    @Test
    @Order(1)
    void appliesLiquibaseAndCompletesRegistrationLoginAndDuplicateChecks() throws Exception {
        String email = uniqueEmail();

        String registration = mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(request(email, PASSWORD)))
                .andExpect(status().isCreated())
                .andExpect(content().contentTypeCompatibleWith("application/json"))
                .andReturn().getResponse().getContentAsString();

        String accessToken = json(registration, "$.accessToken");
        String sessionToken = json(registration, "$.sessionToken");

        mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(request(email, PASSWORD)))
                .andExpect(status().isConflict())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("USER_ALREADY_EXISTS")));

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(request(email, "wrong password")))
                .andExpect(status().isUnauthorized())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("INVALID_CREDENTIALS")));

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString(email)));

        String login = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(request(email, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer " + json(login, "$.accessToken")))
                .andExpect(status().isOk());

        assertThat(sessionTokenService.extractSessionId(sessionToken)).isPresent();
    }

    @Test
    @Order(2)
    void rotatesRefreshTokenAndKeepsOnlyTheReplacementActive() throws Exception {
        String email = uniqueEmail();
        String login = register(email);
        String oldAccessToken = json(login, "$.accessToken");
        String oldSessionToken = json(login, "$.sessionToken");
        UUID sessionId = sessionTokenService.extractSessionId(oldSessionToken).orElseThrow();
        String key = "auth:session:" + sessionId;

        long beforeRefresh = redisTemplate.getExpire(key);
        String refreshed = mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + oldSessionToken + "\"}"))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        String newAccessToken = json(refreshed, "$.accessToken");
        String newSessionToken = json(refreshed, "$.sessionToken");
        assertThat(newSessionToken).isNotEqualTo(oldSessionToken);
        assertThat(sessionTokenService.extractSessionId(newSessionToken)).contains(sessionId);
        assertThat(redisTemplate.getExpire(key)).isGreaterThanOrEqualTo(SESSION_TTL.toSeconds() - 1);
        assertThat(redisTemplate.getExpire(key)).isLessThanOrEqualTo(SESSION_TTL.toSeconds());

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + oldSessionToken + "\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + newAccessToken))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + oldAccessToken))
                .andExpect(status().isOk());
    }

    @Test
    @Order(3)
    void ordinaryAccessDoesNotExtendTtlAndLogoutInvalidatesJwtAndSession() throws Exception {
        String login = register(uniqueEmail());
        String accessToken = json(login, "$.accessToken");
        String sessionToken = json(login, "$.sessionToken");
        UUID sessionId = sessionTokenService.extractSessionId(sessionToken).orElseThrow();
        String key = "auth:session:" + sessionId;

        Thread.sleep(1100);
        long beforeMe = redisTemplate.getExpire(key);
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
        long afterMe = redisTemplate.getExpire(key);
        assertThat(afterMe).isLessThanOrEqualTo(beforeMe);

        mockMvc.perform(post("/api/auth/logout")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + sessionToken + "\"}"))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + sessionToken + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(4)
    void expiredRedisSessionInvalidatesAnOtherwiseUnexpiredJwt() throws Exception {
        String login = register(uniqueEmail());
        String accessToken = json(login, "$.accessToken");
        String sessionToken = json(login, "$.sessionToken");
        UUID sessionId = sessionTokenService.extractSessionId(sessionToken).orElseThrow();

        redisTemplate.expire("auth:session:" + sessionId, Duration.ofMillis(1));
        Thread.sleep(100);

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + sessionToken + "\"}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    void rejectsInvalidRefreshCredentialsAndKeepsOtherSessionsActive() throws Exception {
        String email = uniqueEmail();
        String firstLogin = register(email);
        String firstAccessToken = json(firstLogin, "$.accessToken");
        String firstSessionToken = json(firstLogin, "$.sessionToken");
        String secondLogin = mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(request(email, PASSWORD)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        String secondAccessToken = json(secondLogin, "$.accessToken");
        String secondSessionToken = json(secondLogin, "$.sessionToken");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"malformed\"}"))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\""
                                + sessionTokenService.extractSessionId(firstSessionToken).orElseThrow()
                                + "\"}"))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(post("/api/auth/logout")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + firstSessionToken + "\"}"))
                .andExpect(status().isNoContent());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + firstAccessToken))
                .andExpect(status().isUnauthorized());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + secondAccessToken))
                .andExpect(status().isOk());
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + secondSessionToken + "\"}"))
                .andExpect(status().isOk());
    }

    @Test
    @Order(5)
    void rejectsTamperedJwt() throws Exception {
        String registration = register(uniqueEmail());
        String accessToken = json(registration, "$.accessToken");
        String[] tokenParts = accessToken.split("\\.");
        char[] signature = tokenParts[2].toCharArray();
        signature[5] = signature[5] == 'A' ? 'B' : 'A';
        tokenParts[2] = new String(signature);
        String tampered = String.join(".", tokenParts);

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(7)
    void mapsRedisUnavailableToDependencyError() throws Exception {
        String email = uniqueEmail();
        register(email);
        REDIS.stop();

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content(request(email, PASSWORD)))
                .andExpect(status().isServiceUnavailable())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("DEPENDENCY_UNAVAILABLE")));
    }

    @Test
    @Order(6)
    void concurrentRefreshAllowsExactlyOneRequest() throws Exception {
        String login = register(uniqueEmail());
        String sessionToken = json(login, "$.sessionToken");

        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<Integer> first = executor.submit(() -> refreshStatus(sessionToken));
            Future<Integer> second = executor.submit(() -> refreshStatus(sessionToken));

            assertThat(java.util.List.of(first.get(), second.get()))
                    .containsExactlyInAnyOrder(200, 401);
        } finally {
            executor.shutdownNow();
        }
    }

    private int refreshStatus(String sessionToken) throws Exception {
        return mockMvc.perform(post("/api/auth/refresh")
                        .contentType("application/json")
                        .content("{\"sessionToken\":\"" + sessionToken + "\"}"))
                .andReturn().getResponse().getStatus();
    }

    private String register(String email) throws Exception {
        return mockMvc.perform(post("/api/auth/register")
                        .contentType("application/json")
                        .content(request(email, PASSWORD)))
                .andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString();
    }

    private static String request(String email, String password) {
        return "{\"email\":\"" + email + "\",\"password\":\"" + password + "\"}";
    }

    private static String json(String body, String path) {
        return JsonPath.read(body, path);
    }

    private static String uniqueEmail() {
        return "integration-" + UUID.randomUUID() + "@example.com";
    }

    private record KeyMaterial(Path privateKey, Path publicKey) {

        private static KeyMaterial create() {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair keyPair = generator.generateKeyPair();
                Path privateKey = Files.createTempFile("crona-auth-test-private-", ".pem");
                Path publicKey = Files.createTempFile("crona-auth-test-public-", ".pem");
                Files.writeString(privateKey, pem("PRIVATE KEY", keyPair.getPrivate().getEncoded()));
                Files.writeString(publicKey, pem("PUBLIC KEY", keyPair.getPublic().getEncoded()));
                return new KeyMaterial(privateKey, publicKey);
            } catch (Exception exception) {
                throw new ExceptionInInitializerError(exception);
            }
        }

        private static String pem(String type, byte[] encoded) {
            String body = Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded);
            return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
        }
    }
}
