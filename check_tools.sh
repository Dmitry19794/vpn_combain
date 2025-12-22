#!/bin/bash
# check_tools.sh - Проверяет установку всех необходимых инструментов

set +e  # Не прерываем скрипт при ошибках

INSTALL_DIR="/opt/vpn/bin"
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "🔍 Checking VPN Scanner Tools Installation..."
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Счетчики
TOTAL=0
SUCCESS=0
FAILED=0

# Функция проверки
check_tool() {
    local tool_name=$1
    local tool_path=$2
    local check_cmd=$3
    
    TOTAL=$((TOTAL + 1))
    
    echo -n "Checking ${tool_name}... "
    
    if [ -f "$tool_path" ]; then
        # Проверяем что файл исполняемый
        if [ -x "$tool_path" ]; then
            # Пробуем запустить
            if eval "$check_cmd" &>/dev/null; then
                echo -e "${GREEN}✅ OK${NC}"
                
                # Получаем версию
                version=$(eval "$check_cmd" 2>&1 | head -1)
                echo "   📍 Path: $tool_path"
                echo "   📦 Version: $version"
                
                SUCCESS=$((SUCCESS + 1))
            else
                echo -e "${YELLOW}⚠️  INSTALLED BUT NOT WORKING${NC}"
                echo "   📍 Path: $tool_path"
                echo "   ❌ Command failed: $check_cmd"
                FAILED=$((FAILED + 1))
            fi
        else
            echo -e "${YELLOW}⚠️  NOT EXECUTABLE${NC}"
            echo "   📍 Path: $tool_path"
            echo "   💡 Run: chmod +x $tool_path"
            FAILED=$((FAILED + 1))
        fi
    else
        echo -e "${RED}❌ NOT FOUND${NC}"
        echo "   📍 Expected path: $tool_path"
        FAILED=$((FAILED + 1))
    fi
    
    echo ""
}

# Проверяем Masscan (системный)
check_tool "Masscan" "/usr/bin/masscan" "masscan --version"

# Проверяем Naabu
check_tool "Naabu" "${INSTALL_DIR}/naabu" "${INSTALL_DIR}/naabu -version"

# Проверяем Httpx
check_tool "Httpx" "${INSTALL_DIR}/httpx" "${INSTALL_DIR}/httpx -version"

# Проверяем Nuclei
check_tool "Nuclei" "${INSTALL_DIR}/nuclei" "${INSTALL_DIR}/nuclei -version"

# Проверяем Nuclei templates
echo -n "Checking Nuclei Templates... "
TEMPLATES_DIR="$HOME/.nuclei-templates"
if [ -d "$TEMPLATES_DIR" ]; then
    TEMPLATE_COUNT=$(find "$TEMPLATES_DIR" -name "*.yaml" -o -name "*.yml" 2>/dev/null | wc -l)
    if [ "$TEMPLATE_COUNT" -gt 0 ]; then
        echo -e "${GREEN}✅ OK${NC}"
        echo "   📍 Path: $TEMPLATES_DIR"
        echo "   📦 Templates: $TEMPLATE_COUNT files"
        SUCCESS=$((SUCCESS + 1))
    else
        echo -e "${YELLOW}⚠️  EMPTY${NC}"
        echo "   📍 Path: $TEMPLATES_DIR"
        echo "   💡 Run: ${INSTALL_DIR}/nuclei -update-templates"
        FAILED=$((FAILED + 1))
    fi
else
    echo -e "${RED}❌ NOT FOUND${NC}"
    echo "   📍 Expected path: $TEMPLATES_DIR"
    echo "   💡 Run: ${INSTALL_DIR}/nuclei -update-templates"
    FAILED=$((FAILED + 1))
fi
TOTAL=$((TOTAL + 1))
echo ""

# Проверяем Proxy Checker (Go)
check_tool "Proxy Checker" "/opt/vpn/proxy/proxy_checker" "/opt/vpn/proxy/proxy_checker --help"

# Проверяем VPN Checker (Go)
check_tool "VPN Checker" "/opt/vpn/checker/checker" "/opt/vpn/checker/checker --help"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📊 Summary:"
echo "   Total tools checked: $TOTAL"
echo -e "   ${GREEN}✅ Working: $SUCCESS${NC}"
echo -e "   ${RED}❌ Failed: $FAILED${NC}"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tools are installed and working!${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Update configuration: nano /opt/vpn/config.json"
    echo "  2. Start services: ./start_all.sh"
    echo "  3. Open UI: http://localhost:8000"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tools need attention${NC}"
    echo ""
    echo "To fix issues:"
    echo "  • Re-run installer: sudo ./install_tools.sh"
    echo "  • Check permissions: sudo chown -R \$USER:$USER /opt/vpn"
    echo "  • Verify paths: ls -la /opt/vpn/bin/"
    exit 1
fi
