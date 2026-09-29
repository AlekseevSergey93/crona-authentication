package com.cronagroup.authentication;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import static org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration.class;
import static org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration.class;
import static org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration.class;
import static org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration.class;
import static org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration.class;

@SpringBootTest(
        classes = AuthenticationApplication.class,
        properties = {
                "spring.autoconfigure.exclude="
                        + "org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.liquibase.LiquibaseAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration,"
                        + "org.springframework.boot.autoconfigure.orm.jpa.HibernateJpaAutoConfiguration"
        }
)
class AuthenticationApplicationContextTest {

    @Test
    void contextLoads() {
    }
}
