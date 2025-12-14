#!/bin/bash
# ============================================
# start_fastapi.sh
# Запуск FastAPI приложения
# ============================================

cd /home/argentum/GolandProjects/vpn/vpn/web

# source venv/bin/activate

uvicorn main:app \
    --host 0.0.0.0 \
    --port 8000 \
    --reload
