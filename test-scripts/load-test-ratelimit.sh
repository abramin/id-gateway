#!/usr/bin/env bash
#
# Rate Limit Load Tests
#
# Three test scenarios for performance validation:
# 1. Sustained throughput - single IP, high request rate
# 2. High cardinality - many unique IPs
# 3. Burst load - sudden traffic spike
#
# Prerequisites:
# - Server running on localhost:8080
# - 'hey' or 'wrk' load testing tool (optional, falls back to curl)
# - jq for JSON parsing
#
# Usage:
#   ./load-test-ratelimit.sh [scenario] [duration]
#
# Scenarios: sustained | cardinality | burst | all
# Duration: time in seconds (default: 60)

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
DURATION="${2:-60}"
SCENARIO="${1:-all}"
CONCURRENCY="${CONCURRENCY:-50}"
RPS="${RPS:-100}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check for load testing tools
HAS_HEY=false
HAS_WRK=false
command -v hey >/dev/null 2>&1 && HAS_HEY=true
command -v wrk >/dev/null 2>&1 && HAS_WRK=true

if ! $HAS_HEY && ! $HAS_WRK; then
    log_warn "Neither 'hey' nor 'wrk' found. Using curl (slower, less accurate)"
    log_info "Install hey: go install github.com/rakyll/hey@latest"
    log_info "Install wrk: brew install wrk (macOS) or apt install wrk (Linux)"
fi

# Setup: Create test client and get tokens
setup_test_session() {
    log_info "Setting up test session..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    TOKENGEN="$SCRIPT_DIR/../bin/tokengen"

    if [ ! -x "$TOKENGEN" ]; then
        log_info "Building tokengen..."
        (cd "$SCRIPT_DIR/.." && go build -o bin/tokengen ./cmd/tokengen)
    fi

    ADMIN_TOKEN=$("$TOKENGEN" admin -json | jq -r '.token')
    TIMESTAMP=$(date +%s)

    # Create tenant
    TENANT_RESPONSE=$(curl -sS -X POST "$BASE_URL/admin/tenants" \
        -H "X-Admin-Token: $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"name\":\"LoadTest Tenant $TIMESTAMP\"}")
    TENANT_ID=$(echo "$TENANT_RESPONSE" | jq -r '.tenant_id')

    if [ "$TENANT_ID" = "null" ] || [ -z "$TENANT_ID" ]; then
        log_error "Failed to create tenant: $TENANT_RESPONSE"
        exit 1
    fi

    # Create client
    CLIENT_RESPONSE=$(curl -sS -X POST "$BASE_URL/admin/clients" \
        -H "X-Admin-Token: $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"tenant_id\": \"$TENANT_ID\",
            \"name\": \"LoadTest Client $TIMESTAMP\",
            \"redirect_uris\": [\"http://localhost:3000/callback\"],
            \"allowed_grants\": [\"authorization_code\"],
            \"allowed_scopes\": [\"openid\", \"profile\"]
        }")
    CLIENT_ID=$(echo "$CLIENT_RESPONSE" | jq -r '.client_id')

    if [ "$CLIENT_ID" = "null" ] || [ -z "$CLIENT_ID" ]; then
        log_error "Failed to create client: $CLIENT_RESPONSE"
        exit 1
    fi

    # Get auth code and access token
    AUTH_RESPONSE=$(curl -sS -X POST "$BASE_URL/auth/authorize" \
        -H "Content-Type: application/json" \
        -d "{
            \"email\": \"loadtest-$TIMESTAMP@example.com\",
            \"client_id\": \"$CLIENT_ID\",
            \"redirect_uri\": \"http://localhost:3000/callback\",
            \"scopes\": [\"openid\", \"profile\"],
            \"state\": \"test\"
        }")
    AUTH_CODE=$(echo "$AUTH_RESPONSE" | jq -r '.code')

    TOKEN_RESPONSE=$(curl -sS -X POST "$BASE_URL/auth/token" \
        -H "Content-Type: application/json" \
        -d "{
            \"grant_type\": \"authorization_code\",
            \"client_id\": \"$CLIENT_ID\",
            \"code\": \"$AUTH_CODE\",
            \"redirect_uri\": \"http://localhost:3000/callback\"
        }")
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

    if [ "$ACCESS_TOKEN" = "null" ] || [ -z "$ACCESS_TOKEN" ]; then
        log_error "Failed to get access token"
        exit 1
    fi

    log_info "Test session ready (client: $CLIENT_ID)"
    export ACCESS_TOKEN CLIENT_ID ADMIN_TOKEN
}

# Scenario 1: Sustained throughput from single IP
test_sustained_throughput() {
    log_info "=== Scenario 1: Sustained Throughput ==="
    log_info "Testing ${RPS} req/sec for ${DURATION}s from single IP"
    log_info "Expected: ~${RPS} req/sec throughput, some 429s after hitting IP limit"
    echo ""

    local total_requests=$((RPS * DURATION))

    if $HAS_HEY; then
        hey -n "$total_requests" -c "$CONCURRENCY" -q "$RPS" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "$BASE_URL/auth/userinfo" 2>&1 | tee /tmp/loadtest-sustained.txt
    elif $HAS_WRK; then
        wrk -t4 -c"$CONCURRENCY" -d"${DURATION}s" -R"$RPS" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "$BASE_URL/auth/userinfo" 2>&1 | tee /tmp/loadtest-sustained.txt
    else
        # Fallback to curl loop
        local start_time=$(date +%s)
        local requests=0
        local success=0
        local rate_limited=0

        while [ $(($(date +%s) - start_time)) -lt "$DURATION" ]; do
            for _ in $(seq 1 10); do
                status=$(curl -s -o /dev/null -w "%{http_code}" \
                    -H "Authorization: Bearer $ACCESS_TOKEN" \
                    "$BASE_URL/auth/userinfo")
                ((requests++))
                if [ "$status" = "200" ]; then
                    ((success++))
                elif [ "$status" = "429" ]; then
                    ((rate_limited++))
                fi
            done
        done

        echo "Total requests: $requests"
        echo "Successful (200): $success"
        echo "Rate limited (429): $rate_limited"
        echo "Duration: $DURATION seconds"
        echo "Avg req/sec: $((requests / DURATION))"
    fi

    echo ""
}

# Scenario 2: High cardinality - many unique "IPs" via X-Forwarded-For
test_high_cardinality() {
    log_info "=== Scenario 2: High Cardinality ==="
    log_info "Testing with ${RPS} unique IPs over ${DURATION}s"
    log_info "Expected: Memory growth proportional to unique IPs, then LRU eviction"
    echo ""

    local start_time=$(date +%s)
    local requests=0
    local success=0
    local rate_limited=0
    local ip_counter=0

    # Note: This test simulates different client IPs using X-Forwarded-For
    # The server must be configured to trust this header for the test to work
    while [ $(($(date +%s) - start_time)) -lt "$DURATION" ]; do
        for _ in $(seq 1 "$RPS"); do
            ((ip_counter++))
            # Generate pseudo-random IP from counter
            local ip="10.$((ip_counter / 65536 % 256)).$((ip_counter / 256 % 256)).$((ip_counter % 256))"

            status=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "X-Forwarded-For: $ip" \
                "$BASE_URL/health" 2>/dev/null || echo "000")
            ((requests++))

            if [ "$status" = "200" ]; then
                ((success++))
            elif [ "$status" = "429" ]; then
                ((rate_limited++))
            fi
        done
        sleep 1
    done

    echo "Total requests: $requests"
    echo "Unique IPs simulated: $ip_counter"
    echo "Successful (200): $success"
    echo "Rate limited (429): $rate_limited"
    echo "Duration: $DURATION seconds"
    echo ""
}

# Scenario 3: Burst load
test_burst_load() {
    log_info "=== Scenario 3: Burst Load ==="
    log_info "Testing sudden burst of $((RPS * 5)) req/sec for 10s"
    log_info "Expected: Initial success, then 429s as limits kick in"
    echo ""

    local burst_rps=$((RPS * 5))
    local burst_duration=10
    local total_requests=$((burst_rps * burst_duration))

    if $HAS_HEY; then
        hey -n "$total_requests" -c "$((CONCURRENCY * 2))" \
            -H "Authorization: Bearer $ACCESS_TOKEN" \
            "$BASE_URL/auth/userinfo" 2>&1 | tee /tmp/loadtest-burst.txt
    else
        local start_time=$(date +%s)
        local requests=0
        local success=0
        local rate_limited=0

        # Fire requests as fast as possible
        for _ in $(seq 1 "$total_requests"); do
            status=$(curl -s -o /dev/null -w "%{http_code}" \
                -H "Authorization: Bearer $ACCESS_TOKEN" \
                "$BASE_URL/auth/userinfo" &)
            ((requests++))

            # Check if burst duration exceeded
            if [ $(($(date +%s) - start_time)) -ge "$burst_duration" ]; then
                break
            fi
        done
        wait

        echo "Total requests attempted: $requests"
        echo "Duration: $burst_duration seconds"
    fi

    echo ""
}

# Print memory stats from metrics endpoint (if available)
print_metrics() {
    log_info "=== Server Metrics ==="

    # Try to fetch Prometheus metrics
    if curl -s "$BASE_URL/metrics" >/dev/null 2>&1; then
        echo "Rate limit bucket entries:"
        curl -s "$BASE_URL/metrics" 2>/dev/null | grep -E "credo_ratelimit" || echo "  (no ratelimit metrics found)"
    else
        echo "  (metrics endpoint not available)"
    fi
    echo ""
}

# Main
main() {
    echo "============================================"
    echo "  Rate Limit Load Test Suite"
    echo "============================================"
    echo "Target: $BASE_URL"
    echo "Duration: ${DURATION}s per scenario"
    echo "Concurrency: $CONCURRENCY"
    echo "Target RPS: $RPS"
    echo ""

    setup_test_session
    echo ""

    case "$SCENARIO" in
        sustained)
            test_sustained_throughput
            ;;
        cardinality)
            test_high_cardinality
            ;;
        burst)
            test_burst_load
            ;;
        all)
            test_sustained_throughput
            test_high_cardinality
            test_burst_load
            ;;
        *)
            log_error "Unknown scenario: $SCENARIO"
            echo "Usage: $0 [sustained|cardinality|burst|all] [duration_seconds]"
            exit 1
            ;;
    esac

    print_metrics

    log_info "Load test complete!"
}

main "$@"
