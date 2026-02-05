@echo off
REM PC (Server) 시작 스크립트 (Windows)
REM Manager, RabbitMQ, Dashboard를 시작합니다.
REM 사용법: scripts\start-server.bat

echo === PC Server 시작 ===

cd /d "%~dp0\.."

REM 인증서 확인
if not exist "certs" (
    echo [!] 인증서가 없습니다. 먼저 인증서를 생성하세요:
    echo     cd ops ^&^& python gen_certs.py --out ../certs
    pause
    exit /b 1
)

echo [1/3] 데이터 디렉토리 생성...
if not exist "data" mkdir data

echo [2/3] Docker 이미지 빌드...
docker compose -f docker-compose.server.yml build

echo [3/3] 서비스 시작...
docker compose -f docker-compose.server.yml up -d

echo.
echo === 서비스 시작 완료 ===
echo.
echo 서비스 상태:
docker compose -f docker-compose.server.yml ps
echo.
echo 접속 정보:
echo   - Dashboard: http://localhost:8501
echo   - Manager API: https://localhost:8443
echo   - RabbitMQ: http://localhost:15672
echo.
echo IP 확인: scripts\show-ip.bat
echo 이 IP를 LattePanda에 알려주세요!
echo.
echo 로그 확인: docker compose -f docker-compose.server.yml logs -f
echo.
pause
