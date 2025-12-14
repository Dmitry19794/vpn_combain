#!/bin/bash
# ============================================
# install_dependencies.sh
# Установка зависимостей
# ============================================

# Обновляем систему
sudo apt update

# Устанавливаем Redis
sudo apt install -y redis-server
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Устанавливаем Python зависимости
pip install -r requirements.txt

# Проверяем Redis
redis-cli ping  # Должно вернуть PONG

echo "✅ Dependencies installed"
