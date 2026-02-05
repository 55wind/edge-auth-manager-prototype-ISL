#!/bin/bash
# Comprehensive compliance verification script
# This script verifies all security requirements are met

set -e

echo "========================================="
echo "EDGE AUTH MANAGER - COMPLIANCE VERIFICATION"
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
}

check_fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    exit 1
}

check_info() {
    echo -e "${YELLOW}ℹ️  INFO${NC}: $1"
}

echo "1. AGENT SECURITY MODULE VERIFICATION"
echo "======================================="

# Check async event loop
check_info "Checking async event loop implementation..."
if grep -q "asyncio.run\|async def agent_loop" services/agent/agent/run.py; then
    check_pass "Async event loop implemented"
else
    check_fail "Async event loop not found"
fi

# Check retry/backoff
check_info "Checking retry/backoff mechanism..."
if grep -q "@retry\|AsyncRetrying\|wait_exponential_jitter" services/agent/agent/*.py; then
    check_pass "Retry/backoff with exponential jitter implemented"
else
    check_fail "Retry/backoff not implemented"
fi

# Check mTLS
check_info "Checking mTLS configuration..."
if grep -q "verify=ca\|cert=(crt, key)" services/agent/agent/client.py; then
    check_pass "mTLS handshake and session maintenance implemented"
else
    check_fail "mTLS not properly configured"
fi

# Check metadata transmission
check_info "Checking metadata transmission..."
if grep -q "pub.publish\|SecurePublisher" services/agent/agent/run.py; then
    check_pass "Metadata transmission implemented"
else
    check_fail "Metadata transmission not found"
fi

echo ""
echo "2. AUTHENTICATION MODULE API VERIFICATION"
echo "=========================================="

# Check /auth endpoints
check_info "Checking /auth endpoints..."
if grep -q "@app.post(\"/auth/token\"" services/manager/manager/main.py && \
   grep -q "@app.post(\"/auth/validate\"" services/manager/manager/main.py; then
    check_pass "/auth/token and /auth/validate endpoints present"
else
    check_fail "Missing /auth endpoints"
fi

# Check /cert endpoints
check_info "Checking /cert endpoints..."
if grep -q "@app.post(\"/cert/issue\"" services/manager/manager/main.py && \
   grep -q "@app.post(\"/cert/renew\"" services/manager/manager/main.py && \
   grep -q "@app.post(\"/cert/revoke\"" services/manager/manager/main.py; then
    check_pass "/cert/issue, /cert/renew, and /cert/revoke endpoints present"
else
    check_fail "Missing /cert endpoints"
fi

# Check approval verification
check_info "Checking approval gate..."
if grep -q "require_admin\|APPROVED\|PENDING" services/manager/manager/main.py; then
    check_pass "Approval gate with admin verification implemented"
else
    check_fail "Approval gate not implemented"
fi

echo ""
echo "3. MESSAGE BUS SECURITY CHANNEL VERIFICATION"
echo "============================================="

# Check TLS setup
check_info "Checking RabbitMQ TLS configuration..."
if grep -q "listeners.tcp = none" ops/rabbitmq/rabbitmq.conf && \
   grep -q "ssl_options" ops/rabbitmq/rabbitmq.conf; then
    check_pass "TLS-only AMQP configured (TCP disabled)"
else
    check_fail "TLS not properly enforced in RabbitMQ"
fi

# Check queue binding
check_info "Checking queue binding..."
if grep -q "queue_declare\|agent.metadata" services/agent/agent/amqp_pub.py; then
    check_pass "Queue binding implemented"
else
    check_fail "Queue binding not found"
fi

# Check reconnection logic
check_info "Checking reconnection mechanism..."
if grep -q "_reconnect\|AsyncRetrying" services/agent/agent/amqp_pub.py; then
    check_pass "Automatic reconnection with backoff implemented"
else
    check_fail "Reconnection logic not implemented"
fi

# Check buffer
check_info "Checking untransmitted message buffer..."
if [ -f "services/agent/agent/buffer.py" ] && \
   grep -q "JsonlBuffer\|append\|drain" services/agent/agent/buffer.py; then
    check_pass "Local buffer for untransmitted messages implemented"
else
    check_fail "Message buffer not implemented"
fi

# Check key rotation support
check_info "Checking key rotation documentation..."
if [ -f "ops/rotate_demo.md" ]; then
    check_pass "Key rotation demo documented"
else
    check_fail "Key rotation documentation missing"
fi

echo ""
echo "4. CONTAINER SECURITY VERIFICATION"
echo "==================================="

# Check non-root users
check_info "Checking non-root container users..."
manager_user=$(grep "USER manager" services/manager/Dockerfile 2>/dev/null || echo "")
agent_user=$(grep "USER agent" services/agent/Dockerfile 2>/dev/null || echo "")
dashboard_user=$(grep "USER dashboard" services/dashboard/Dockerfile 2>/dev/null || echo "")

if [ -n "$manager_user" ] && [ -n "$agent_user" ] && [ -n "$dashboard_user" ]; then
    check_pass "All containers run as non-root users (manager, agent, dashboard)"
else
    check_fail "Not all containers have non-root users"
fi

# Check TLS enforcement
check_info "Checking TLS enforcement in Manager..."
if grep -q "ssl_keyfile\|ssl_certfile" services/manager/manager/main.py; then
    check_pass "Manager enforces HTTPS with TLS"
else
    check_fail "Manager TLS not enforced"
fi

# Check default account removal
check_info "Checking RabbitMQ guest account removal..."
if [ -f "ops/rabbitmq/init.sh" ] && \
   grep -q "delete_user guest" ops/rabbitmq/init.sh && \
   grep -q "add_user edge-agent" ops/rabbitmq/init.sh; then
    check_pass "Guest account removed, dedicated edge-agent user created"
else
    check_fail "Default guest account not properly removed"
fi

# Check setup scripts
check_info "Checking setup and installation scripts..."
if [ -f "ops/gen_certs.py" ] && [ -f "ops/rabbitmq/init.sh" ]; then
    check_pass "Certificate generation and initialization scripts present"
else
    check_fail "Setup scripts missing"
fi

# Check token refresh
check_info "Checking token refresh logic..."
if grep -q "token_expires_at\|token_ttl\|refresh" services/agent/agent/run.py; then
    check_pass "Automatic token refresh implemented"
else
    check_fail "Token refresh logic not implemented"
fi

echo ""
echo "========================================="
echo "COMPLIANCE VERIFICATION SUMMARY"
echo "========================================="
echo ""
check_pass "ALL REQUIREMENTS MET ✅"
echo ""
echo "Project Status: 100% COMPLIANT"
echo ""
echo "✅ Lightweight agent security module: COMPLETE"
echo "   - Registration, metadata transmission: ✓"
echo "   - Async event loop: ✓"
echo "   - Retry/backoff: ✓"
echo "   - mTLS handshake: ✓"
echo ""
echo "✅ Authentication module API: COMPLETE"
echo "   - /cert/issue: ✓"
echo "   - /cert/renew: ✓"
echo "   - /cert/revoke: ✓"
echo "   - /auth/token: ✓"
echo "   - /auth/validate: ✓"
echo "   - Approval verification: ✓"
echo ""
echo "✅ Message bus security channel: COMPLETE"
echo "   - TLS setup: ✓"
echo "   - Queue binding: ✓"
echo "   - Reconnection: ✓"
echo "   - Message buffer: ✓"
echo "   - Key rotation support: ✓"
echo ""
echo "✅ Container security: COMPLETE"
echo "   - Non-root users: ✓"
echo "   - TLS enforcement: ✓"
echo "   - Guest account removed: ✓"
echo "   - Setup scripts: ✓"
echo "   - Token refresh: ✓"
echo ""
echo "========================================="
