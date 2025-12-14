#!/bin/bash
# ============================================
# start_celery_worker.sh
# Запуск Celery worker для сканирования
# ============================================

# Переходим в директорию с приложением
cd /home/argentum/GolandProjects/vpn/vpn/celery_app

# Активируем виртуальное окружение (если используется)
# source env/bin/activate

# pip install --upgrade pip setuptools wheel
# pip install celery[redis]==5.3.4
# pip install fastapi==0.104.1 uvicorn==0.24.0 redis==5.0.1 \
#            #psycopg2-binary==2.9.9 psutil==5.9.6 flower==2.0.1 \
#            #jinja2==3.1.2 python-multipart==0.0.6

# Запускаем Celery worker
celery -A tasks worker \
    --loglevel=info \
    --concurrency=4 \
    --hostname=scanner@%h \
    --queues=default \
    --max-tasks-per-child=50 \
    --time-limit=3600 \
    --soft-time-limit=3300
