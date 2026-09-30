# Crona Authentication

Spring Boot authentication service with user registration, login, JWT access tokens, and opaque Redis sessions. The service provides a REST API, stores users in PostgreSQL, stores sessions in Redis, and accepts external requests through Nginx.

## Key features

- user registration and login;
- Argon2id password hashing;
- RS256-signed JWT access tokens;
- opaque session tokens with rotation on refresh;
- atomic session updates through a Redis Lua script;
- logout with immediate session invalidation;
- protected `GET /api/me`;
- a consistent JSON error format and request IDs;
- Liquibase migrations for PostgreSQL;
- safe access logging without passwords or tokens;
- a Docker Compose environment with PostgreSQL, Redis, and Nginx;
- unit and Testcontainers integration tests.

## Project modules

### `auth`

REST API and orchestration services for authentication use cases:

- `POST /api/auth/register`;
- `POST /api/auth/login`;
- `POST /api/auth/refresh`;
- `POST /api/auth/logout`.

### `user`

User domain, JPA repository, and current-user endpoint:

- `GET /api/me`.

### `common/security`

Shared security components:

- `JwtTokenService`;
- `SessionTokenService`;
- `RedisSessionRepository`;
- `BearerAuthenticationFilter`;
- Argon2id password hashing;
- active Redis session checks for protected requests.

### `common/validation`

Email normalization and password validation policies.

### `common/error` and `common/web`

Common error responses, exception handling, request IDs, security error responses, and safe access logging.

### `config`

Spring Security configuration, application properties, CORS/security policy, and production configuration validation.

### `db/changelog`

Versioned Liquibase changesets for the PostgreSQL schema.

### `nginx`

Reverse proxy for API requests. Nginx is the only service that publishes a host port.

### `scripts`

Runnable authentication demo:

```bash
./scripts/demo-auth.sh http://localhost:8088
```

## Requirements

- Java 21 or newer;
- Maven;
- Docker Desktop and Docker Compose;
- for the demo: `curl`, `jq`, and Python 3.

## Run with Docker Compose

Generate JWT RSA keys without adding them to Git:

```bash
mkdir -p secrets
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
  -out secrets/jwt-private.pem
openssl rsa -in secrets/jwt-private.pem -pubout \
  -out secrets/jwt-public.pem
```

Create the environment file:

```bash
cp .env.example .env
```

Start all services:

```bash
docker compose up --build
```

The API will be available through Nginx at `http://localhost:8088`.

Check the Nginx health endpoint:

```bash
curl http://localhost:8088/nginx-health
```

Run the complete authentication API demo:

```bash
ACCESS_TOKEN_TTL=5s SESSION_TTL=20s docker compose up --build -d
./scripts/demo-auth.sh http://localhost:8088
```

Stop the environment:

```bash
docker compose down
```

## Run locally with Maven

Local execution requires running PostgreSQL and Redis instances. Configure the connections with environment variables:

```bash
export DATABASE_URL='jdbc:postgresql://localhost:5432/auth'
export DATABASE_USERNAME='auth'
export DATABASE_PASSWORD='auth'
export REDIS_HOST='localhost'
export REDIS_PORT='6379'
export JWT_PRIVATE_KEY_PATH="$PWD/secrets/jwt-private.pem"
export JWT_PUBLIC_KEY_PATH="$PWD/secrets/jwt-public.pem"
```

Start the application:

```bash
mvn spring-boot:run
```

Liquibase applies the migrations automatically during application startup.

## Testing

Run unit and integration tests:

```bash
mvn test
```

Run the Testcontainers integration suite separately:

```bash
mvn -Dtest=AuthenticationIntegrationTest test
```

Additional automated verification instructions are available in [`docs/verification.md`](docs/verification.md). The complete implementation checklist is available in [`docs/implementation-checklist.md`](docs/implementation-checklist.md).

## Security

The service does not store raw session tokens in Redis or log passwords, JWTs, session tokens, token hashes, or the `Authorization` header. The production profile requires accessible RSA keys and positive TTL values.
