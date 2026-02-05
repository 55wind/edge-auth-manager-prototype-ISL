@echo off
REM 모든 서비스 중지 스크립트 (Windows)
REM 사용법: scripts\stop-all.bat

cd /d "%~dp0\.."

echo === 모든 서비스 중지 ===

REM Server 서비스 중지
if exist "docker-compose.server.yml" (
    echo Server 서비스 중지...
    docker compose -f docker-compose.server.yml down 2>nul
)

REM Agent 서비스 중지
if exist "docker-compose.agent.yml" (
    echo Agent 서비스 중지...
    docker compose -f docker-compose.agent.yml down 2>nul
)

REM 기본 docker-compose 중지
if exist "docker-compose.yml" (
    echo 기본 서비스 중지...
    docker compose down 2>nul
)

echo.
echo === 완료 ===
pause
