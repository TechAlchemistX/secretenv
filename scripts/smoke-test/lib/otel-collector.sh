# SPDX-License-Identifier: AGPL-3.0-only
#
# Helpers to lifecycle a local OTel collector (Jaeger all-in-one)
# for the v0.17 OTel smoke section. Source from run-tests.sh:
#
#   . "$_here/lib/otel-collector.sh"
#
# Public functions:
#   otel_start                — start the collector container (idempotent)
#   otel_wait_ready           — poll until the OTLP gRPC + HTTP query API are live
#   otel_stop                 — stop + rm the container (idempotent)
#   otel_query_traces SERVICE — curl Jaeger's `/api/traces?service=...` and emit JSON
#   otel_query_latest_trace SERVICE OPERATION
#                             — fetch the most-recent trace for a (service, span-name) pair
#   otel_reset                — fast restart (stop + start + wait) so each test gets clean state
#
# Required external: docker, curl, jq.
#
# Why Jaeger all-in-one vs. the OTel Collector binary: Jaeger has a
# built-in query API at port 16686 that returns JSON, no extra
# config file required. The OTel Collector binary needs a YAML
# config + a separate query backend; Jaeger is one container, one
# port mapping, one curl URL.

# Lock the image tag so this smoke is reproducible across operator
# machines. Bump deliberately + re-baseline assertions.
OTEL_JAEGER_IMAGE="${OTEL_JAEGER_IMAGE:-jaegertracing/all-in-one:1.62}"
OTEL_JAEGER_CONTAINER="${OTEL_JAEGER_CONTAINER:-secretenv-smoke-jaeger}"

# Ports — set so the smoke matches the build plan + the env vars the
# CLI honours by default (4317 for OTLP gRPC; 16686 for the query UI).
OTEL_OTLP_GRPC_PORT="${OTEL_OTLP_GRPC_PORT:-4317}"
OTEL_OTLP_HTTP_PORT="${OTEL_OTLP_HTTP_PORT:-4318}"
OTEL_JAEGER_QUERY_PORT="${OTEL_JAEGER_QUERY_PORT:-16686}"

# Wait budget for the collector to come up. Slow CI VMs may need
# longer; tune via env if necessary.
OTEL_WAIT_TIMEOUT_SECS="${OTEL_WAIT_TIMEOUT_SECS:-30}"

otel_require_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "FATAL: docker not on PATH; OTel smoke section requires it" >&2
        return 127
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "FATAL: docker daemon not running; start Docker Desktop or dockerd" >&2
        return 1
    fi
}

otel_start() {
    otel_require_docker || return $?
    # Idempotent: if a container by our name is already running, leave it.
    if docker ps --format '{{.Names}}' | grep -qx "$OTEL_JAEGER_CONTAINER"; then
        return 0
    fi
    # Tolerate stopped-but-not-removed leftovers.
    docker rm -f "$OTEL_JAEGER_CONTAINER" >/dev/null 2>&1 || true
    docker run -d --rm \
        --name "$OTEL_JAEGER_CONTAINER" \
        -e COLLECTOR_OTLP_ENABLED=true \
        -p "${OTEL_OTLP_GRPC_PORT}:4317" \
        -p "${OTEL_OTLP_HTTP_PORT}:4318" \
        -p "${OTEL_JAEGER_QUERY_PORT}:16686" \
        "$OTEL_JAEGER_IMAGE" >/dev/null
}

otel_wait_ready() {
    local deadline=$((SECONDS + OTEL_WAIT_TIMEOUT_SECS))
    while (( SECONDS < deadline )); do
        # The query API answers `/api/services` once the collector is
        # ready to accept spans + serve queries. Cheaper + more
        # reliable than scraping container logs.
        if curl -sf "http://127.0.0.1:${OTEL_JAEGER_QUERY_PORT}/api/services" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "FATAL: Jaeger query API never came up at http://127.0.0.1:${OTEL_JAEGER_QUERY_PORT}/" >&2
    return 1
}

otel_stop() {
    # `docker run --rm` means stop is enough; also handle the case
    # where Docker is gone (operator already cleaned up).
    docker stop "$OTEL_JAEGER_CONTAINER" >/dev/null 2>&1 || true
    docker rm -f "$OTEL_JAEGER_CONTAINER" >/dev/null 2>&1 || true
}

otel_reset() {
    otel_stop
    otel_start || return $?
    otel_wait_ready || return $?
}

# Print all traces for a given service. Used as a building block by
# the section-36 assertions. Caller jq-greps the result.
otel_query_traces() {
    local service="$1"
    local limit="${2:-20}"
    curl -sf \
        "http://127.0.0.1:${OTEL_JAEGER_QUERY_PORT}/api/traces?service=${service}&limit=${limit}"
}

# Fetch the most-recent trace whose root operation matches OPERATION.
# Jaeger's API doesn't filter by operation directly without a query
# parameter, but `operation=<name>` is supported.
otel_query_latest_trace() {
    local service="$1"
    local operation="$2"
    curl -sf \
        "http://127.0.0.1:${OTEL_JAEGER_QUERY_PORT}/api/traces?service=${service}&operation=${operation}&limit=1"
}

# Cross-attribute span value lookup against a query response. Returns
# the value (stripped) or empty string. Used by the per-attribute
# assertions in section 36.
otel_span_attr() {
    local json="$1"
    local span_name="$2"
    local attr_key="$3"
    printf '%s' "$json" | jq -r \
        --arg op "$span_name" \
        --arg key "$attr_key" \
        '.data[]?.spans[]? | select(.operationName == $op) | .tags[]? | select(.key == $key) | .value' \
        | head -1
}

# True (exit 0) iff the JSON response contains a span named `span_name`
# carrying attribute `attr_key`. Used for negative-presence checks
# (e.g. SEC-INV-19: `redact.alias_name` must be absent).
otel_span_has_attr() {
    local json="$1"
    local span_name="$2"
    local attr_key="$3"
    local found
    found=$(otel_span_attr "$json" "$span_name" "$attr_key")
    [[ -n "$found" ]]
}
