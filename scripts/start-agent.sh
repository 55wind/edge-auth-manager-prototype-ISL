#!/bin/bash
# LattePanda #1 Agent (latte-001) 시작 스크립트
# 사용법: SERVER_IP=<PC-IP> ./scripts/start-agent.sh

set -e

echo "=== Edge Agent #1 (latte-001) 시작 ==="

# 프로젝트 루트로 이동
cd "$(dirname "$0")/.."

# SERVER_IP 확인
if [ -z "$SERVER_IP" ]; then
    echo "[!] SERVER_IP 환경변수를 설정하세요:"
    echo "    export SERVER_IP=<PC의 IP>"
    echo "    또는"
    echo "    SERVER_IP=<PC의 IP> ./scripts/start-agent.sh"
    exit 1
fi

echo "Server IP: $SERVER_IP"
echo "Device ID: latte-001"
echo "Sensor Type: temperature"

# 인증서 확인
if [ ! -d "certs" ]; then
    echo "[!] 인증서가 없습니다. PC(Server)에서 certs 폴더를 복사하세요."
    exit 1
fi

# 서버 연결 테스트
echo "[1/4] 서버 연결 테스트..."
if nc -zv "$SERVER_IP" 8443 2>&1 | grep -q "succeeded\|open"; then
    echo "  Manager (8443): OK"
else
    echo "  Manager (8443): 연결 실패"
    echo "  Server가 실행 중인지 확인하세요."
fi

if nc -zv "$SERVER_IP" 5671 2>&1 | grep -q "succeeded\|open"; then
    echo "  RabbitMQ (5671): OK"
else
    echo "  RabbitMQ (5671): 연결 실패"
fi

echo "[2/4] 데이터 디렉토리 생성..."
mkdir -p data/agent_buffer_001
mkdir -p data/agent_buffer_002

echo "[3/4] Docker 이미지 빌드..."
docker compose -f docker-compose.agent.yml build

echo "[4/4] Agent 시작..."
docker compose -f docker-compose.agent.yml up -d

echo ""
echo "=== Agent 시작 완료 ==="
echo ""
echo "로그 확인: docker compose -f docker-compose.agent.yml logs -f"
