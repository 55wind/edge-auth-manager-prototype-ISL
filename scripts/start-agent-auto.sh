#!/bin/bash
# LattePanda #1 Agent (latte-001, 온도 센서) 시작 스크립트
# 사용법: ./scripts/start-agent-auto.sh

set -e

echo "=== Edge Agent #1 (latte-001) 시작 ==="

cd "$(dirname "$0")/.."

# 인증서 확인
if [ ! -d "certs" ]; then
    echo "[!] 인증서가 없습니다. PC(Server)에서 certs 폴더를 복사하세요."
    exit 1
fi

# SERVER_IP가 설정되지 않은 경우 입력 받기
if [ -z "$SERVER_IP" ]; then
    echo ""
    echo "PC(Server)의 IP 주소를 입력하세요."
    echo "(PC에서 ./scripts/show-ip.sh 로 확인 가능)"
    echo ""
    read -p "Server IP: " SERVER_IP
    export SERVER_IP
fi

echo ""
echo "Server IP: $SERVER_IP"
echo "Device ID: latte-001"
echo "Sensor Type: temperature"
echo ""

# 연결 테스트
echo "[1/4] 서버 연결 테스트..."
if nc -zv -w 3 "$SERVER_IP" 8443 2>&1 | grep -qE "succeeded|open|Connected"; then
    echo "  Manager (8443): OK"
else
    echo "  Manager (8443): 연결 실패 - 계속 진행합니다."
fi

echo "[2/4] 데이터 디렉토리 생성..."
mkdir -p data/agent_buffer_001

echo "[3/4] Docker 이미지 빌드..."
docker compose -f docker-compose.agent.yml build

echo "[4/4] Agent 시작..."
docker compose -f docker-compose.agent.yml up

echo ""
echo "=== Agent 종료됨 ==="
