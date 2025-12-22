#!/bin/bash
tmux kill-session -t monitor 2>/dev/null

tmux new-session -d -s monitor -n main 'bash'        # 0

tmux split-window -h -p 50                            # 0 | 1
tmux split-window -t 0 -v -p 50                       # 0 (верх), 2 (низ)
tmux split-window -t 1 -v -p 50                       # 1 (верх), 3 (низ)
tmux split-window -t 3 -v -p 50                       # 3 (верх), 4 (низ)

tmux send-keys -t 0 'cd /opt/vpn/logs && tail -F fastapi.log 2>/dev/null || echo "fastapi"' C-m
tmux send-keys -t 1 'cd /opt/vpn/logs && tail -F celery-worker.log 2>/dev/null || echo "worker"' C-m
tmux send-keys -t 2 'cd /opt/vpn/logs && tail -F celery-beat.log 2>/dev/null || echo "beat"' C-m
tmux send-keys -t 3 'btop 2>/dev/null || htop || echo "btop/htop"' C-m
tmux send-keys -t 4 'cd /opt/vpn && exec bash' C-m

echo "✅ 5 панелей. Ctrl+↑↓←→ — переключение."
