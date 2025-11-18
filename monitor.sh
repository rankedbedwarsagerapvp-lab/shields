#!/bin/bash
# Мониторинг системы динамической маршрутизации

API_URL="http://localhost:8080"

# Цвета
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

clear
echo -e "${BLUE}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Shield Dynamic Routing - Monitor           ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════╝${NC}"
echo ""

# Функция для получения статистики
get_stats() {
    curl -s "$API_URL/api/stats" | jq -r '
        "Total Connections: \(.data.total_connections)",
        "Active Connections: \(.data.active_connections)",
        "Blocked Connections: \(.data.blocked_connections)",
        "Emergency Mode: \(.data.emergency_mode)",
        "Protection Disabled: \(.data.protection_disabled)"
    '
}

# Функция для получения активных портов
get_active_ports() {
    netstat -tuln 2>/dev/null | grep "LISTEN" | grep -E ":(256[0-9]{2}|30[0-9]{3})" | wc -l
}

# Функция для получения маршрутов (требует аутентификации)
get_routes_count() {
    # Это требует cookie, но для мониторинга можем просто показать порты
    echo "N/A (требуется аутентификация)"
}

# Основной цикл мониторинга
while true; do
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')]${NC}"
    echo ""

    # Статистика Shield
    echo -e "${GREEN}Shield Statistics:${NC}"
    get_stats
    echo ""

    # Активные порты
    echo -e "${GREEN}Active Ports:${NC}"
    ACTIVE_PORTS=$(get_active_ports)
    echo "Listening on dynamic ports: $ACTIVE_PORTS"
    echo ""

    # HAProxy статус
    echo -e "${GREEN}HAProxy Status:${NC}"
    if systemctl is-active --quiet haproxy 2>/dev/null; then
        echo -e "${GREEN}✓ Running${NC}"
    else
        if pgrep haproxy > /dev/null; then
            echo -e "${GREEN}✓ Running (not via systemd)${NC}"
        else
            echo -e "${RED}✗ Not running${NC}"
        fi
    fi
    echo ""

    # Использование портов
    echo -e "${GREEN}Port Usage:${NC}"
    echo "Range 25600-25699:"
    netstat -tuln 2>/dev/null | grep -E ":256[0-9]{2}" | grep "LISTEN" | wc -l | xargs echo "  Active:"
    echo "Range 30000-30099:"
    netstat -tuln 2>/dev/null | grep -E ":300[0-9]{2}" | grep "LISTEN" | wc -l | xargs echo "  Active:"
    echo ""

    # Топ процессов по памяти (shield и haproxy)
    echo -e "${GREEN}Process Resources:${NC}"
    ps aux | grep -E "(shield|haproxy)" | grep -v grep | awk '{printf "  %s: CPU=%s%% MEM=%s%%\n", $11, $3, $4}' | head -5
    echo ""

    # Последние подключения (из логов если доступны)
    echo -e "${GREEN}Recent Activity:${NC}"
    if [ -f "/var/log/shield/shield.log" ]; then
        tail -3 /var/log/shield/shield.log
    else
        echo "  Log file not found"
    fi
    echo ""

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "Обновление через 5 секунд... (Ctrl+C для выхода)"
    sleep 5
    clear
done

