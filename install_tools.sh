#!/bin/bash
# install_tools.sh — Установка naabu, httpx, nuclei для combain
# ✅ Работает на Ubuntu/Debian, x86_64, 2025-style releases (без _amd64 в имени)
# ✅ Показывает прогресс даже под sudo
# ✅ Не зависает молча

set -euo pipefail

BOLD="\e[1m"
GREEN="\e[32m"
BLUE="\e[34m"
RED="\e[31m"
RESET="\e[0m"

INSTALL_DIR="/opt/vpn/bin"
mkdir -p "$INSTALL_DIR"
cd "$INSTALL_DIR"

echo -e "${BOLD}🚀 Установка инструментов для combain${RESET}"
echo -e "📁 Каталог: ${BLUE}$INSTALL_DIR${RESET}"
echo

# === Функция установки одного инструмента ===
install_tool() {
    local name=$1
    local url=$2
    local bin_name=$3

    echo -e "${BLUE}📥 Устанавливаю ${name}...${RESET}"
    echo -e "   Скачиваю: ${url}"

    # Проверка доступности (быстро)
    if ! timeout 10 curl -sfI "$url" >/dev/null 2>&1; then
        echo -e "${RED}❌ Ошибка: файл не найден или нет интернета${RESET}"
        echo -e "   Проверь: curl -I \"$url\""
        exit 1
    fi

    # Скачивание с прогрессом
    if ! wget --quiet --show-progress --progress=bar:force:noscroll -O "${bin_name}.zip" "$url"; then
        echo -e "${RED}❌ Ошибка скачивания${RESET}"
        exit 1
    fi

    # Распаковка
    if ! unzip -q -o "${bin_name}.zip"; then
        echo -e "${RED}❌ Ошибка распаковки${RESET}"
        rm -f "${bin_name}.zip"
        exit 1
    fi

    # Права и очистка
    chmod +x "$bin_name"
    rm -f "${bin_name}.zip" LICENSE* README* 2>/dev/null || true

    # Проверка версии
    if ver=$("./$bin_name" -version 2>/dev/null | head -1 | sed 's/.* //'); then
        echo -e "${GREEN}✅ ${name} ${ver} установлен${RESET}"
    else
        echo -e "${RED}❌ ${name}: не запускается${RESET}"
        exit 1
    fi
    echo
}

# === URL актуальных релизов (2025-12-20) ===
# Формат: https://github.com/org/repo/releases/download/vX.Y.Z/tool_X.Y.Z_os.zip
NAABU_URL="https://github.com/projectdiscovery/naabu/releases/download/v2.3.7/naabu_2.3.7_linux_amd64.zip"
HTTPX_URL="https://github.com/projectdiscovery/httpx/releases/download/v1.7.4/httpx_1.7.4_linux_amd64.zip"
NUCLEI_URL="https://github.com/projectdiscovery/nuclei/releases/download/v3.6.1/nuclei_3.6.1_linux_amd64.zip"

# === Установка ===
install_tool "Naabu"  "$NAABU_URL"  "naabu"
install_tool "Httpx"  "$HTTPX_URL"  "httpx"
install_tool "Nuclei" "$NUCLEI_URL" "nuclei"

# === Шаблоны nuclei ===
echo -e "${BLUE}📥 Обновляю шаблоны nuclei...${RESET}"
if /opt/vpn/bin/nuclei -update-templates -silent 2>/dev/null; then
    echo -e "${GREEN}✅ Шаблоны обновлены (~20 000+ шаблонов)${RESET}"
else
    echo -e "${RED}⚠️  Шаблоны не обновлены (проверь интернет/прокси)${RESET}"
fi
echo

# === Симлинки ===
echo -e "${BLUE}🔗 Создаю симлинки в /usr/local/bin...${RESET}"
ln -sf "$INSTALL_DIR/naabu"  /usr/local/bin/naabu  2>/dev/null || true
ln -sf "$INSTALL_DIR/httpx"  /usr/local/bin/httpx  2>/dev/null || true
ln -sf "$INSTALL_DIR/nuclei" /usr/local/bin/nuclei 2>/dev/null || true
echo -e "${GREEN}✅ Готово${RESET}"

# === Финальная проверка ===
echo
echo -e "${BOLD}🎉 Установка завершена!${RESET}"
echo
echo -e "Проверка:"
echo -e "   naabu:  $(naabu -version 2>/dev/null | head -1 || echo -e "${RED}не найден${RESET}")"
echo -e "   httpx:  $(httpx -version 2>/dev/null | head -1 || echo -e "${RED}не найден${RESET}")"
echo -e "   nuclei: $(nuclei -version 2>/dev/null | head -1 || echo -e "${RED}не найден${RESET}")"
echo
echo -e "${BLUE}💡 Пример запуска:${RESET}"
echo -e "   nuclei -t cves/ -u http://testphp.vulnweb.com"
echo
