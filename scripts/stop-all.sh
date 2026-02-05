#!/bin/bash
# 모든 서비스 중지 스크립트
# 사용법: ./scripts/stop-all.sh

cd "$(dirname "$0")/.."

echo "=== 모든 서비스 중지 ==="

# Server 서비스 중지
if [ -f "docker-compose.server.yml" ]; then
    echo "Server 서비스 중지..."
    docker compose -f docker-compose.server.yml down 2>/dev/null || true
fi

# Agent 서비스 중지
if [ -f "docker-compose.agent.yml" ]; then
    echo "Agent 서비스 중지..."
    docker compose -f docker-compose.agent.yml down 2>/dev/null || true
fi

# 기본 docker-compose 중지
if [ -f "docker-compose.yml" ]; then
    echo "기본 서비스 중지..."
    docker compose down 2>/dev/null || true
fi

echo ""
echo "=== 완료 ==="
