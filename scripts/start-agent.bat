@echo off
REM LattePanda #1 Agent (latte-001) 시작 스크립트 (Windows)
REM 사용법: set SERVER_IP=<PC-IP> && scripts\start-agent.bat

echo === Edge Agent #1 (latte-001) 시작 ===

cd /d "%~dp0\.."

REM SERVER_IP 확인
if "%SERVER_IP%"=="" (
    echo [!] SERVER_IP 환경변수를 설정하세요:
    echo     set SERVER_IP=^<PC의 IP^>
    echo     scripts\start-agent.bat
    echo.
    set /p SERVER_IP="PC(Server) IP를 입력하세요: "
)

echo Server IP: %SERVER_IP%
echo Device ID: latte-001
echo Sensor Type: temperature

REM 인증서 확인
if not exist "certs" (
    echo [!] 인증서가 없습니다. PC(Server)에서 certs 폴더를 복사하세요.
    pause
    exit /b 1
)

echo [1/3] 데이터 디렉토리 생성...
if not exist "data\agent_buffer_001" mkdir "data\agent_buffer_001"
if not exist "data\agent_buffer_002" mkdir "data\agent_buffer_002"

echo [2/3] Docker 이미지 빌드...
docker compose -f docker-compose.agent.yml build

echo [3/3] Agent 시작...
docker compose -f docker-compose.agent.yml up -d

echo.
echo === Agent 시작 완료 ===
echo.
echo 로그 확인: docker compose -f docker-compose.agent.yml logs -f
echo.
pause
