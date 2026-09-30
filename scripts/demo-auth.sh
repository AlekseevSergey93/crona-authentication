#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8088}"
BASE_URL="${BASE_URL%/}"
EXPECTED_SESSION_TTL_SECONDS="${EXPECTED_SESSION_TTL_SECONDS:-20}"
ACCESS_TOKEN_WAIT_SECONDS="${ACCESS_TOKEN_WAIT_SECONDS:-6}"
AUTHORIZATION_HEADER="Authorization"
BEARER_SCHEME="Bearer"

for command in curl jq python3 docker; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command is missing: $command" >&2
    exit 1
  fi
done

EMAIL="demo-$(date +%s)-$$@example.com"
PASSWORD='correct horse battery staple'
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/crona-auth-demo.XXXXXX")"
trap 'rm -rf "$WORK_DIR"' EXIT
umask 077

request() {
  local expected_status="$1"
  local output_file="$2"
  shift 2
  local actual_status
  actual_status="$(curl --silent --show-error --output "$output_file" --write-out '%{http_code}' "$@")"
  if [[ "$actual_status" != "$expected_status" ]]; then
    echo "Unexpected HTTP status: expected $expected_status, got $actual_status" >&2
    exit 1
  fi
}

json_value() {
  jq -er "$1" "$2"
}

assert_contains() {
  local file="$1"
  local value="$2"
  jq -e --arg value "$value" 'tostring | contains($value)' "$file" >/dev/null
}

tamper_token() {
  local token="$1"
  python3 - "$token" <<'PY'
import sys

parts = sys.argv[1].split(".")
signature = list(parts[2])
signature[5] = "A" if signature[5] != "A" else "B"
parts[2] = "".join(signature)
print(".".join(parts))
PY
}

token_header() {
  printf '%s: %s %s' "$AUTHORIZATION_HEADER" "$BEARER_SCHEME" "$1"
}

session_id_from_token() {
  python3 - "$1" <<'PY'
import base64
import sys
import uuid

payload = base64.urlsafe_b64decode(sys.argv[1] + "===")
print(uuid.UUID(bytes=payload[1:17]))
PY
}

wait_for_api() {
  for _ in {1..30}; do
    if curl --silent --fail "$BASE_URL/nginx-health" >/dev/null 2>&1; then
      return
    fi
    sleep 1
  done
  echo "Nginx did not become ready" >&2
  exit 1
}

redis_ttl() {
  docker compose exec -T redis sh -c '
    if [ -n "$REDIS_PASSWORD" ]; then
      redis-cli -a "$REDIS_PASSWORD" TTL "$1"
    else
      redis-cli TTL "$1"
    fi
  ' sh "$1"
}

wait_for_api

request 201 "$WORK_DIR/register.json" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/api/auth/register"
ACCESS_TOKEN="$(json_value '.accessToken' "$WORK_DIR/register.json")"
SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/register.json")"
SESSION_ID="$(session_id_from_token "$SESSION_TOKEN")"

request 409 "$WORK_DIR/duplicate.json" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/api/auth/register"
assert_contains "$WORK_DIR/duplicate.json" 'USER_ALREADY_EXISTS'

request 401 "$WORK_DIR/bad-login.json" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"wrong password\"}" \
  "$BASE_URL/api/auth/login"
assert_contains "$WORK_DIR/bad-login.json" 'INVALID_CREDENTIALS'

TTL_BEFORE_ME="$(redis_ttl "auth:session:$SESSION_ID")"
request 200 "$WORK_DIR/me.json" \
  -H "$(token_header "$ACCESS_TOKEN")" \
  "$BASE_URL/api/me"
jq -e --arg email "$EMAIL" '.email == $email' "$WORK_DIR/me.json" >/dev/null

request 200 "$WORK_DIR/login.json" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/api/auth/login"
LOGIN_ACCESS_TOKEN="$(json_value '.accessToken' "$WORK_DIR/login.json")"
LOGIN_SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/login.json")"
LOGIN_SESSION_ID="$(session_id_from_token "$LOGIN_SESSION_TOKEN")"
request 200 "$WORK_DIR/login-me.json" \
  -H "$(token_header "$LOGIN_ACCESS_TOKEN")" \
  "$BASE_URL/api/me"

TTL_AFTER_ME="$(redis_ttl "auth:session:$SESSION_ID")"
(( TTL_AFTER_ME <= TTL_BEFORE_ME ))
LOGIN_TTL="$(redis_ttl "auth:session:$LOGIN_SESSION_ID")"
(( LOGIN_TTL > 0 ))

request 401 "$WORK_DIR/no-auth.json" "$BASE_URL/api/me"
TAMPERED_ACCESS_TOKEN="$(tamper_token "$ACCESS_TOKEN")"
request 401 "$WORK_DIR/tampered.json" \
  -H "$(token_header "$TAMPERED_ACCESS_TOKEN")" \
  "$BASE_URL/api/me"

TTL_BEFORE="$(redis_ttl "auth:session:$SESSION_ID")"
request 200 "$WORK_DIR/refreshed.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"
NEW_ACCESS_TOKEN="$(json_value '.accessToken' "$WORK_DIR/refreshed.json")"
NEW_SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/refreshed.json")"
[[ "$NEW_SESSION_TOKEN" != "$SESSION_TOKEN" ]]

TTL_AFTER_REFRESH="$(redis_ttl "auth:session:$SESSION_ID")"
(( TTL_AFTER_REFRESH > 0 ))
(( TTL_AFTER_REFRESH >= EXPECTED_SESSION_TTL_SECONDS - 2 ))

request 401 "$WORK_DIR/old-refresh.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"

TTL_AFTER_FAILED_REFRESH="$(redis_ttl "auth:session:$SESSION_ID")"
(( TTL_AFTER_FAILED_REFRESH <= TTL_AFTER_REFRESH ))

request 200 "$WORK_DIR/refreshed-me.json" \
  -H "$(token_header "$NEW_ACCESS_TOKEN")" \
  "$BASE_URL/api/me"

sleep "$ACCESS_TOKEN_WAIT_SECONDS"
request 401 "$WORK_DIR/expired-access.json" \
  -H "$(token_header "$NEW_ACCESS_TOKEN")" \
  "$BASE_URL/api/me"

request 200 "$WORK_DIR/second-refresh.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$NEW_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"
SECOND_SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/second-refresh.json")"

request 401 "$WORK_DIR/missing-refresh.json" \
  -H 'Content-Type: application/json' \
  -d '{}' \
  "$BASE_URL/api/auth/refresh"
request 401 "$WORK_DIR/malformed-refresh.json" \
  -H 'Content-Type: application/json' \
  -d '{"sessionToken":"not-a-session-token"}' \
  "$BASE_URL/api/auth/refresh"

CONCURRENT_DIR="$WORK_DIR/concurrent"
mkdir "$CONCURRENT_DIR"
for index in 1 2; do
  (
    curl --silent --show-error --output "$CONCURRENT_DIR/$index.json" --write-out '%{http_code}' \
      -H 'Content-Type: application/json' \
      -d "{\"sessionToken\":\"$SECOND_SESSION_TOKEN\"}" \
      "$BASE_URL/api/auth/refresh" >"$CONCURRENT_DIR/$index.status"
  ) &
done
wait
SUCCESS_COUNT="$(grep -l '^200$' "$CONCURRENT_DIR"/*.status | wc -l | tr -d ' ')"
[[ "$SUCCESS_COUNT" == "1" ]]
FAILURE_COUNT="$(grep -l '^401$' "$CONCURRENT_DIR"/*.status | wc -l | tr -d ' ')"
[[ "$FAILURE_COUNT" == "1" ]]

SUCCESS_STATUS_FILE="$(grep -l '^200$' "$CONCURRENT_DIR"/*.status)"
SUCCESS_RESPONSE_FILE="${SUCCESS_STATUS_FILE%.status}.json"
WINNING_ACCESS_TOKEN="$(json_value '.accessToken' "$SUCCESS_RESPONSE_FILE")"
WINNING_SESSION_TOKEN="$(json_value '.sessionToken' "$SUCCESS_RESPONSE_FILE")"
[[ "$WINNING_SESSION_TOKEN" != "$SECOND_SESSION_TOKEN" ]]

request 204 "$WORK_DIR/logout.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$WINNING_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/logout"
request 401 "$WORK_DIR/logout-me.json" \
  -H "$(token_header "$WINNING_ACCESS_TOKEN")" \
  "$BASE_URL/api/me"
request 401 "$WORK_DIR/logout-refresh.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$WINNING_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"

EXPIRED_EMAIL="expired-$(date +%s)-$$@example.com"
request 201 "$WORK_DIR/expired-register.json" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EXPIRED_EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/api/auth/register"
EXPIRED_SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/expired-register.json")"
sleep "$((EXPECTED_SESSION_TTL_SECONDS + 1))"
request 401 "$WORK_DIR/expired-session.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$EXPIRED_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"

echo "Authentication demo passed."
