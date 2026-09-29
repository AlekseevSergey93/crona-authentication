package com.cronagroup.authentication.config;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class LiquibaseChangelogResourceTest {

    @Test
    void rootChangelogIncludesInitialUsersChangeset() throws IOException {
        String rootChangelog = readResource("db/changelog/db.changelog-master.yaml");

        assertThat(rootChangelog)
                .contains("db/changelog/changesets/001-create-users.yaml");
    }

    @Test
    void initialUsersChangesetDefinesExpectedSchema() throws IOException {
        String usersChangeset = readResource("db/changelog/changesets/001-create-users.yaml");

        assertThat(usersChangeset)
                .contains("id: 001-create-users")
                .contains("tableName: users")
                .contains("name: email")
                .contains("indexName: users_email_uq")
                .contains("unique: true")
                .contains("tableName: users");
    }

    private String readResource(String path) throws IOException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(path)) {
            assertThat(inputStream).as("Resource %s", path).isNotNull();
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
