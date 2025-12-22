#!/bin/bash

SESSION_NAME="vpn"

# Удаляем старую сессию, если есть (осторожно!)
tmux kill-session -t "$SESSION_NAME" 2>/dev/null || true

# Создаём новую сессию в фоне (-d), первое окно — proxy
tmux new-session -d -s "$SESSION_NAME" -n proxy

# Окно 0: proxy_checker
tmux send-keys -t "$SESSION_NAME":0 \
  'cd /opt/vpn/proxy/proxy_checker && ./proxy_checker' Enter

# Окно 1: FastAPI
tmux new-window -t "$SESSION_NAME" -n api
tmux send-keys -t "$SESSION_NAME":1 \
  'cd /opt/vpn && /opt/vpn/env/bin/uvicorn main:app --host 0.0.0.0 --port 8000' Enter

# Окно 2: Celery worker
tmux new-window -t "$SESSION_NAME" -n worker
tmux send-keys -t "$SESSION_NAME":2 \
  'cd /opt/vpn && /opt/vpn/env/bin/celery -A celery_app worker --loglevel=INFO' Enter

# Окно 3: Celery beat
tmux new-window -t "$SESSION_NAME" -n beat
tmux send-keys -t "$SESSION_NAME":3 \
  'cd /opt/vpn && /opt/vpn/env/bin/celery -A celery_app beat --loglevel=INFO' Enter

echo "✅ Сессия '$SESSION_NAME' создана с 4 окнами: proxy, api, worker, beat"
echo "Подключайтесь: tmux attach -t $SESSION_NAME"
