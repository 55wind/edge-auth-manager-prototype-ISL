@echo off
REM 현재 IP 주소 확인 스크립트 (Windows)
REM 사용법: scripts\show-ip.bat

echo === 현재 IP 주소 ===
echo.

for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4"') do (
    set IP=%%a
    goto :found
)

:found
set IP=%IP: =%
echo 이 장비의 IP: %IP%
echo.
echo 다른 장비에서 사용할 명령어:
echo   set SERVER_IP=%IP%
echo.
echo Dashboard 접속 URL:
echo   http://%IP%:8501
echo.
pause
