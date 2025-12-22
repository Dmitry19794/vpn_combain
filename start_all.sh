#!/bin/bash
# start_all.sh — Запуск всех сервисов VPN Scanner (обновленная версия)

set -e

# ============================================
# CONFIGURATION
# ============================================

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WEB_DIR="$BASE_DIR/web"
WORKER_PID_FILE="$BASE_DIR/logs/celery-worker.pid"
BEAT_PID_FILE="$BASE_DIR/logs/celery-beat.pid"
FASTAPI_PID_FILE="$BASE_DIR/logs/fastapi.pid"

# Auto-detect PostgreSQL port
if ss -tuln | grep -q ':5434\s'; then
    export PGPORT=5434
    echo "ℹ️  Detected PostgreSQL on port 5434"
else
    export PGPORT=5432
    echo "ℹ️  Using default PostgreSQL port 5432"
fi

# ============================================
# COLORS
# ============================================

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ============================================
# BANNER
# ============================================

clear
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                    VPN SCANNER v2.0                        ║"
echo "║              Masscan → Httpx → Nuclei → Brute              ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# ============================================
# PRE-FLIGHT CHECKS
# ============================================

echo "🔍 Running pre-flight checks..."
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}❌ Python3 not found${NC}"
    exit 1
fi
echo -e "${GREEN}✅ Python3: $(python3 --version)${NC}"

# Check Redis
if ! pgrep redis-server &> /dev/null; then
    echo -e "${YELLOW}⚠️  Redis not running, attempting to start...${NC}"
    sudo systemctl start redis-server 2>/dev/null || sudo service redis-server start 2>/dev/null || {
        echo -e "${RED}❌ Failed to start Redis${NC}"
        echo "   Please start Redis manually: sudo systemctl start redis-server"
        exit 1
    }
    sleep 2
fi
echo -e "${GREEN}✅ Redis: Running${NC}"

# Check PostgreSQL
if ! pgrep postgres &> /dev/null; then
    echo -e "${YELLOW}⚠️  PostgreSQL not running, attempting to start...${NC}"
    sudo systemctl start postgresql 2>/dev/null || sudo service postgresql start 2>/dev/null || {
        echo -e "${RED}❌ Failed to start PostgreSQL${NC}"
        echo "   Please start PostgreSQL manually: sudo systemctl start postgresql"
        exit 1
    }
    sleep 2
fi
echo -e "${GREEN}✅ PostgreSQL: Running on port $PGPORT${NC}"

# Check scanning tools
echo ""
echo "🔧 Checking scanning tools..."
TOOLS_OK=true

if [ ! -f "/opt/vpn/bin/naabu" ]; then
    echo -e "${YELLOW}⚠️  Naabu not found${NC}"
    TOOLS_OK=false
fi

if [ ! -f "/opt/vpn/bin/httpx" ]; then
    echo -e "${YELLOW}⚠️  Httpx not found${NC}"
    TOOLS_OK=false
fi

if [ ! -f "/opt/vpn/bin/nuclei" ]; then
    echo -e "${YELLOW}⚠️  Nuclei not found${NC}"
    TOOLS_OK=false
fi

if [ "$TOOLS_OK" = false ]; then
    echo ""
    echo -e "${YELLOW}⚠️  Some scanning tools are missing${NC}"
    echo "   You can still run the scanner with Masscan only"
    echo "   To install missing tools: sudo ./install_tools.sh"
    echo ""
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    echo -e "${GREEN}✅ All scanning tools present${NC}"
fi

echo ""

# ============================================
# PYTHON VENV
# ============================================

echo "🐍 Setting up Python environment..."

if [ ! -d "$BASE_DIR/env" ]; then
    echo "   Creating virtual environment..."
    python3 -m venv "$BASE_DIR/env"
    source "$BASE_DIR/env/bin/activate"
    
    echo "   Installing dependencies..."
    pip install --upgrade pip setuptools wheel --quiet
    pip install celery[redis]==5.3.4 fastapi==0.104.1 uvicorn==0.24.0 \
        redis==5.0.1 psycopg2-binary==2.9.9 psutil==5.9.6 \
        jinja2==3.1.2 python-multipart==0.0.6 pydantic==2.5.0 --quiet
    
    echo -e "${GREEN}✅ Virtual environment created${NC}"
else
    source "$BASE_DIR/env/bin/activate"
    echo -e "${GREEN}✅ Virtual environment activated${NC}"
fi

# ============================================
# CREATE CONFIG IF NOT EXISTS
# ============================================

CONFIG_FILE="$BASE_DIR/config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    echo ""
    echo "📝 Creating default configuration..."
    cat > "$CONFIG_FILE" << 'EOF'
{
  "scanner": {
    "engine": "masscan",
    "rate": 10000,
    "workers": 64,
    "timeout": 5,
    "retries": 2
  },
  "httpx": {
    "enabled": true,
    "timeout": 10,
    "threads": 50,
    "extract_title": true,
    "tech_detect": true,
    "status_code": true,
    "headers": true
  },
  "detection": {
    "mode": "nuclei-then-checker",
    "timeout": 15,
    "nuclei": {
      "templates": ["vpn", "cves"],
      "severity": ["info", "low", "medium", "high", "critical"],
      "concurrent": 25
    },
    "checker": {
      "min_workers": 10,
      "max_workers": 100,
      "verify_ssl": false
    }
  },
  "brute": {
    "enabled": true,
    "timeout": 30,
    "max_attempts": 3
  },
  "paths": {
    "bin_dir": "/opt/vpn/bin",
    "templates_dir": "~/.nuclei-templates",
    "output_dir": "/tmp/vpn_scan_results"
  }
}
EOF
    echo -e "${GREEN}✅ Configuration created at $CONFIG_FILE${NC}"
fi

# ============================================
# CLEANUP FUNCTION
# ============================================

cleanup() {
    echo ""
    echo "🛑 Stopping all services..."
    
    if [ -f "$FASTAPI_PID_FILE" ]; then
        kill -TERM "$(cat "$FASTAPI_PID_FILE")" 2>/dev/null || true
        rm -f "$FASTAPI_PID_FILE"
        echo "   ✓ FastAPI stopped"
    fi
    
    if [ -f "$WORKER_PID_FILE" ]; then
        kill -TERM "$(cat "$WORKER_PID_FILE")" 2>/dev/null || true
        rm -f "$WORKER_PID_FILE"
        echo "   ✓ Celery Worker stopped"
    fi
    
    if [ -f "$BEAT_PID_FILE" ]; then
        kill -TERM "$(cat "$BEAT_PID_FILE")" 2>/dev/null || true
        rm -f "$BEAT_PID_FILE"
        echo "   ✓ Celery Beat stopped"
    fi
    
    # Cleanup any remaining processes
    pkill -f "celery -A celery_app.tasks" 2>/dev/null || true
    pkill -f uvicorn 2>/dev/null || true
    
    echo -e "${GREEN}✅ All services stopped${NC}"
}

trap cleanup EXIT INT TERM

# ============================================
# CREATE LOG DIRECTORY
# ============================================

mkdir -p "$BASE_DIR/logs"
mkdir -p "/tmp/vpn_scan_results"

# ============================================
# START SERVICES
# ============================================

echo ""
echo "🚀 Starting services..."
echo ""

# ---------- Celery Worker ----------
echo -n "📦 Starting Celery Worker... "
cd "$BASE_DIR"

# Определяем какой файл tasks использовать
if [ -f "$BASE_DIR/celery_app/tasks.py" ]; then
    TASKS_MODULE="celery_app.tasks"
    echo "(using NEW pipeline)"
else
    TASKS_MODULE="celery_app.tasks"
    echo "(using LEGACY pipeline)"
fi

celery -A $TASKS_MODULE worker \
    --loglevel=info \
    --concurrency=4 \
    --max-tasks-per-child=50 \
    --prefetch-multiplier=1 \
    > "$BASE_DIR/logs/celery-worker.log" 2>&1 &

WORKER_PID=$!
echo $WORKER_PID > "$WORKER_PID_FILE"
sleep 3

if ! kill -0 "$WORKER_PID" 2>/dev/null; then
    echo -e "${RED}❌ Failed to start Celery Worker${NC}"
    tail -20 "$BASE_DIR/logs/celery-worker.log"
    exit 1
fi
echo -e "${GREEN}✅ Celery Worker started (PID: $WORKER_PID)${NC}"

# ---------- Celery Beat ----------
echo -n "⏰ Starting Celery Beat... "
celery -A $TASKS_MODULE beat \
    --loglevel=info \
    > "$BASE_DIR/logs/celery-beat.log" 2>&1 &

BEAT_PID=$!
echo $BEAT_PID > "$BEAT_PID_FILE"
sleep 2

if ! kill -0 "$BEAT_PID" 2>/dev/null; then
    echo -e "${RED}❌ Failed to start Celery Beat${NC}"
    tail -20 "$BASE_DIR/logs/celery-beat.log"
    exit 1
fi
echo -e "${GREEN}✅ Celery Beat started (PID: $BEAT_PID)${NC}"

# ---------- FastAPI ----------
echo -n "🌐 Starting FastAPI... "
cd "$BASE_DIR"

PYTHONPATH="$BASE_DIR" uvicorn web.main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload \
    --log-level info \
    > "$BASE_DIR/logs/fastapi.log" 2>&1 &

FASTAPI_PID=$!
echo $FASTAPI_PID > "$FASTAPI_PID_FILE"
sleep 5

if ! kill -0 "$FASTAPI_PID" 2>/dev/null; then
    echo -e "${RED}❌ Failed to start FastAPI${NC}"
    tail -20 "$BASE_DIR/logs/fastapi.log"
    exit 1
fi
echo -e "${GREEN}✅ FastAPI started (PID: $FASTAPI_PID)${NC}"

# ============================================
# SUMMARY
# ============================================

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${GREEN}✅ All services are running!${NC}"
echo ""
echo "🌐 Web UI:         http://localhost:8000"
echo "🎯 Settings:       http://localhost:8000/#settings"
echo "❤️  Health Check:  http://localhost:8000/health"
echo ""
echo "📊 Service PIDs:"
echo "   FastAPI:        $FASTAPI_PID"
echo "   Celery Worker:  $WORKER_PID"
echo "   Celery Beat:    $BEAT_PID"
echo ""
echo "📄 Log Files:"
echo "   Worker:   tail -f logs/celery-worker.log"
echo "   Beat:     tail -f logs/celery-beat.log"
echo "   FastAPI:  tail -f logs/fastapi.log"
echo ""
echo "⚙️  Configuration: $CONFIG_FILE"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "${BLUE}🛑 Press Ctrl+C to stop all services${NC}"
echo ""

# Ждем сигнала остановки
wait
