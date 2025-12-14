#!/bin/bash
# ============================================
# install_services.sh
# Установка systemd сервисов
# ============================================

# Создаём необходимые директории
sudo mkdir -p /var/run/celery
sudo mkdir -p /var/log/celery
sudo chown -R argentum:argentum /var/run/celery
sudo chown -R argentum:argentum /var/log/celery

# Копируем service файлы
sudo cp /tmp/celery-worker.service /etc/systemd/system/
sudo cp /tmp/celery-beat.service /etc/systemd/system/
sudo cp /tmp/fastapi-vpn.service /etc/systemd/system/

# Перезагружаем systemd
sudo systemctl daemon-reload

# Включаем автозапуск
sudo systemctl enable celery-worker
sudo systemctl enable celery-beat
sudo systemctl enable fastapi-vpn

# Запускаем сервисы
sudo systemctl start celery-worker
sudo systemctl start celery-beat
sudo systemctl start fastapi-vpn

# Проверяем статус
sudo systemctl status celery-worker
sudo systemctl status celery-beat
sudo systemctl status fastapi-vpn

echo "✅ Services installed and started"
echo "📊 Monitor with: sudo journalctl -u celery-worker -f"
echo "🌸 Flower UI: celery -A tasks flower --port=5555"
