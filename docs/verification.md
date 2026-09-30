# Automated verification

Run the independent unit and service tests with:

```bash
mvn test
```

The integration suite starts PostgreSQL 16 and Redis 7 with Testcontainers. It applies the Liquibase changelog to an empty database and verifies registration, duplicate registration, invalid credentials, protected access, session expiration, refresh rotation, TTL behavior, logout, Redis dependency failures, and concurrent refresh:

```bash
mvn -Dtest=AuthenticationIntegrationTest test
```

The runnable Compose demonstration requires Docker, `curl`, `jq`, and Python 3. From the repository root:

```bash
cp .env.example .env
ACCESS_TOKEN_TTL=5s SESSION_TTL=20s docker compose up --build -d
./scripts/demo-auth.sh http://localhost:8088
```

The script stores responses only in a private temporary directory, does not print credentials or tokens, performs no implicit cleanup of Compose resources, and exits on the first failed assertion. Stop the manually started stack explicitly when finished:

```bash
docker compose down
```
