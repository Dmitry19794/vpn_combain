#!/bin/bash
# ============================================
# start_celery_beat.sh
# Запуск Celery beat для периодических задач
# ============================================

cd /home/argentum/GolandProjects/vpn/vpn/celery_app

# source venv/bin/activate

celery -A tasks beat \
    --loglevel=info \
    --scheduler=celery.beat:PersistentScheduler
