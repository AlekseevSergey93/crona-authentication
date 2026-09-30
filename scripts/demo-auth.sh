#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-http://localhost:8088}"
BASE_URL="${BASE_URL%/}"

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

wait_for_api

redis_ttl() {
  docker compose exec -T redis sh -c '
    if [ -n "$REDIS_PASSWORD" ]; then
      redis-cli -a "$REDIS_PASSWORD" TTL "$1"
    else
      redis-cli TTL "$1"
    fi
  ' sh "$1"
}

request 201 "$WORK_DIR/register.json" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/api/auth/register"
ACCESS_TOKEN="$(json_value '.accessToken' "$WORK_DIR/register.json")"
SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/register.json")"

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

request 200 "$WORK_DIR/me.json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  "$BASE_URL/api/me"
jq -e --arg email "$EMAIL" '.email == $email' "$WORK_DIR/me.json" >/dev/null

request 401 "$WORK_DIR/no-auth.json" "$BASE_URL/api/me"
request 401 "$WORK_DIR/tampered.json" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}tampered" \
  "$BASE_URL/api/me"

SESSION_ID="$(python3 - "$SESSION_TOKEN" <<'PY'
import base64
import sys
import uuid

payload = base64.urlsafe_b64decode(sys.argv[1] + "===")
print(uuid.UUID(bytes=payload[1:17]))
PY
)"

TTL_BEFORE="$(redis_ttl "auth:session:$SESSION_ID")"
request 200 "$WORK_DIR/refreshed.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"
NEW_ACCESS_TOKEN="$(json_value '.accessToken' "$WORK_DIR/refreshed.json")"
NEW_SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/refreshed.json")"
[[ "$NEW_SESSION_TOKEN" != "$SESSION_TOKEN" ]]

TTL_AFTER_REFRESH="$(redis_ttl "auth:session:$SESSION_ID")"
(( TTL_AFTER_REFRESH > 0 && TTL_AFTER_REFRESH >= TTL_BEFORE - 1 ))

request 401 "$WORK_DIR/old-refresh.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"

TTL_AFTER_FAILED_REFRESH="$(redis_ttl "auth:session:$SESSION_ID")"
(( TTL_AFTER_FAILED_REFRESH <= TTL_AFTER_REFRESH ))

request 200 "$WORK_DIR/refreshed-me.json" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  "$BASE_URL/api/me"

sleep 6
request 401 "$WORK_DIR/expired-access.json" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN" \
  "$BASE_URL/api/me"

request 200 "$WORK_DIR/second-refresh.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$NEW_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"
SECOND_ACCESS_TOKEN="$(json_value '.accessToken' "$WORK_DIR/second-refresh.json")"
SECOND_SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/second-refresh.json")"

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

request 204 "$WORK_DIR/logout.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$SECOND_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/logout"
request 401 "$WORK_DIR/logout-me.json" \
  -H "Authorization: Bearer $SECOND_ACCESS_TOKEN" \
  "$BASE_URL/api/me"
request 401 "$WORK_DIR/logout-refresh.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$SECOND_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"

EXPIRED_EMAIL="expired-$(date +%s)-$$@example.com"
request 201 "$WORK_DIR/expired-register.json" \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"$EXPIRED_EMAIL\",\"password\":\"$PASSWORD\"}" \
  "$BASE_URL/api/auth/register"
EXPIRED_SESSION_TOKEN="$(json_value '.sessionToken' "$WORK_DIR/expired-register.json")"
sleep 21
request 401 "$WORK_DIR/expired-session.json" \
  -H 'Content-Type: application/json' \
  -d "{\"sessionToken\":\"$EXPIRED_SESSION_TOKEN\"}" \
  "$BASE_URL/api/auth/refresh"

echo "Authentication demo passed."
