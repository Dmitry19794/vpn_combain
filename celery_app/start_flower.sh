#!/bin/bash
# ============================================
# start_flower.sh
# Запуск Flower для мониторинга Celery
# ============================================

cd /home/argentum/GolandProjects/vpn/vpn/celery_app

# source venv/bin/activate

celery -A tasks flower \
    --port=5555 \
    --broker=redis://localhost:6379/0

# Flower будет доступен на http://localhost:5555
