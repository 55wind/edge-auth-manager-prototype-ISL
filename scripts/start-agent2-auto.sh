#!/bin/bash
# LattePanda #2 Agent (latte-002) 시작 스크립트
# 사용법: ./scripts/start-agent2-auto.sh

set -e

echo "=== Edge Agent #2 (latte-002) 시작 ==="

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
echo "Device ID: latte-002"
echo "Sensor Type: humidity"
echo ""

echo "[1/3] 데이터 디렉토리 생성..."
mkdir -p data/agent_buffer_002

echo "[2/3] Docker 이미지 빌드..."
docker compose -f docker-compose.agent2.yml build

echo "[3/3] Agent 시작..."
docker compose -f docker-compose.agent2.yml up

echo ""
echo "=== Agent 종료됨 ==="
