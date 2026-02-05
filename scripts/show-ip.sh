#!/bin/bash
# 현재 IP 주소 확인 스크립트
# 사용법: ./scripts/show-ip.sh

echo "=== 현재 IP 주소 ==="
echo ""

# Linux
if command -v ip &> /dev/null; then
    IP=$(ip route get 1 | awk '{print $7; exit}')
    echo "이 장비의 IP: $IP"
    echo ""
    echo "다른 장비에서 사용할 명령어:"
    echo "  export SERVER_IP=$IP"
    echo ""
    echo "Dashboard 접속 URL:"
    echo "  http://$IP:8501"
elif command -v hostname &> /dev/null; then
    IP=$(hostname -I | awk '{print $1}')
    echo "이 장비의 IP: $IP"
    echo ""
    echo "다른 장비에서 사용할 명령어:"
    echo "  export SERVER_IP=$IP"
    echo ""
    echo "Dashboard 접속 URL:"
    echo "  http://$IP:8501"
fi
