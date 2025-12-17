#!/bin/bash

# Auto-detect PGPORT: if PostgreSQL listens on :5434 → use it, else 5432
if ss -tuln | grep -q ':5434\s'; then
    export PGPORT=5434
    echo "ℹ️ Detected PostgreSQL on port 5434"
else
    export PGPORT=5432
    echo "ℹ️ Using default PostgreSQL port 5432"
fi

# start_all.sh — запуск FastAPI + Celery Worker + Celery Beat

set -e

BASE_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
WEB_DIR="$BASE_DIR/web"

WORKER_PID_FILE="$BASE_DIR/logs/celery-worker.pid"
BEAT_PID_FILE="$BASE_DIR/logs/celery-beat.pid"
FASTAPI_PID_FILE="$BASE_DIR/logs/fastapi.pid"

echo "🚀 Starting VPN Scanner Services..."

# ---------- Python venv ----------
if [ ! -d "$BASE_DIR/env" ]; then
    echo "⚠️ Virtual environment not found. Creating..."
    python3 -m venv "$BASE_DIR/env"
    source "$BASE_DIR/env/bin/activate"
    pip install --upgrade pip setuptools wheel
    pip install celery[redis]==5.3.4 fastapi==0.104.1 uvicorn==0.24.0 \
        redis==5.0.1 psycopg2-binary==2.9.9 psutil==5.9.6 \
        jinja2==3.1.2 python-multipart==0.0.6
else
    source "$BASE_DIR/env/bin/activate"
fi

# ---------- Cleanup ----------
cleanup() {
    echo ""
    echo "🛑 Stopping all services..."

    if [ -f "$FASTAPI_PID_FILE" ]; then
        kill -TERM "$(cat "$FASTAPI_PID_FILE")" 2>/dev/null || true
        rm -f "$FASTAPI_PID_FILE"
    fi

    if [ -f "$WORKER_PID_FILE" ]; then
        kill -TERM "$(cat "$WORKER_PID_FILE")" 2>/dev/null || true
        rm -f "$WORKER_PID_FILE"
    fi

    if [ -f "$BEAT_PID_FILE" ]; then
        kill -TERM "$(cat "$BEAT_PID_FILE")" 2>/dev/null || true
        rm -f "$BEAT_PID_FILE"
    fi

    pkill -f "celery -A celery_app.tasks" 2>/dev/null || true
    pkill -f uvicorn 2>/dev/null || true

    echo "✅ All services stopped"
}

trap cleanup EXIT INT TERM

mkdir -p "$BASE_DIR/logs"

# ---------- Celery Worker ----------
echo "📦 Starting Celery Worker..."
cd "$BASE_DIR"

celery -A celery_app.tasks worker \
    --loglevel=info \
    --concurrency=4 \
    --max-tasks-per-child=50 \
    > "$BASE_DIR/logs/celery-worker.log" 2>&1 &

WORKER_PID=$!
echo $WORKER_PID > "$WORKER_PID_FILE"

sleep 3

if ! kill -0 "$WORKER_PID" 2>/dev/null; then
    echo "❌ Failed to start Celery Worker"
    cat "$BASE_DIR/logs/celery-worker.log"
    exit 1
fi

echo "✅ Celery Worker started (PID: $WORKER_PID)"

# ---------- Celery Beat ----------
echo "⏰ Starting Celery Beat..."
cd "$BASE_DIR"

celery -A celery_app.tasks beat \
    --loglevel=info \
    > "$BASE_DIR/logs/celery-beat.log" 2>&1 &

BEAT_PID=$!
echo $BEAT_PID > "$BEAT_PID_FILE"

sleep 2

if ! kill -0 "$BEAT_PID" 2>/dev/null; then
    echo "❌ Failed to start Celery Beat"
    cat "$BASE_DIR/logs/celery-beat.log"
    exit 1
fi

echo "✅ Celery Beat started (PID: $BEAT_PID)"

# ---------- FastAPI ----------
echo "🌐 Starting FastAPI..."
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
    echo "❌ Failed to start FastAPI"
    cat "$BASE_DIR/logs/fastapi.log"
    exit 1
fi

echo "✅ FastAPI started (PID: $FASTAPI_PID)"

# ---------- Summary ----------
echo ""
echo "✅ All services are running!"
echo ""
echo "🌐 UI:       http://localhost:8000"
echo "❤️ Health:   http://localhost:8000/health"
echo ""
echo "📄 Logs:"
echo "  Worker:   tail -f logs/celery-worker.log"
echo "  Beat:     tail -f logs/celery-beat.log"
echo "  FastAPI:  tail -f logs/fastapi.log"
echo ""
echo "🛑 Press Ctrl+C to stop all services."
echo ""

wait
