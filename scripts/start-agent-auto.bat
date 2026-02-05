@echo off
REM LattePanda #1 Agent (latte-001, 온도 센서) 시작 스크립트 (Windows)
REM 사용법: scripts\start-agent-auto.bat

echo === Edge Agent #1 (latte-001) 시작 ===

cd /d "%~dp0\.."

REM 인증서 확인
if not exist "certs" (
    echo [!] 인증서가 없습니다. PC(Server)에서 certs 폴더를 복사하세요.
    pause
    exit /b 1
)

REM SERVER_IP가 설정되지 않은 경우 입력 받기
if "%SERVER_IP%"=="" (
    echo.
    echo PC(Server)의 IP 주소를 입력하세요.
    echo (PC에서 scripts\show-ip.bat 로 확인 가능)
    echo.
    set /p SERVER_IP="Server IP: "
)

echo.
echo Server IP: %SERVER_IP%
echo Device ID: latte-001
echo Sensor Type: temperature
echo.

echo [1/3] 데이터 디렉토리 생성...
if not exist "data\agent_buffer_001" mkdir "data\agent_buffer_001"

echo [2/3] Docker 이미지 빌드...
docker compose -f docker-compose.agent.yml build

echo [3/3] Agent 시작...
docker compose -f docker-compose.agent.yml up

echo.
echo === Agent 종료됨 ===
pause
