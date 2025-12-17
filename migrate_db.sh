#!/bin/bash

# ===== НАСТРОЙКИ =====
LOCAL_PG_HOST="localhost"
LOCAL_PG_PORT="5434"
LOCAL_PG_USER="brute"
LOCAL_PG_PASS="securepass123"
LOCAL_DB_NAME="brute_system"

REMOTE_HOST="213.171.31.97"
REMOTE_USER="admin"
REMOTE_PG_HOST="localhost"
REMOTE_PG_PORT="5434"
REMOTE_PG_USER="brute"
REMOTE_PG_PASS="securepass123"
REMOTE_DB_NAME="brute_system"

DUMP_FILE="brute_system.sql"

# ===== 1. Локальный дамп — с флагами для максимальной совместимости =====
echo "📥 Делаю SQL-дамп БД с $LOCAL_PG_HOST:$LOCAL_PG_PORT..."
export PGPASSWORD="$LOCAL_PG_PASS"
pg_dump -h "$LOCAL_PG_HOST" -p "$LOCAL_PG_PORT" -U "$LOCAL_PG_USER" -d "$LOCAL_DB_NAME" \
  --inserts \
  --no-owner \
  --no-privileges \
  --no-tablespaces \
  --exclude-table-data='celery_taskmeta' \
  --exclude-table-data='celery_tasksetmeta' \
  --exclude-table-data='app_errors' \
  -f "$DUMP_FILE"

if [ $? -ne 0 ]; then
    echo "❌ Ошибка создания дампа"
    exit 1
fi

echo "✅ Дамп создан: $DUMP_FILE ($(/bin/ls -lh "$DUMP_FILE" | awk '{print $5}'))"

# Убираем из SQL опасные строки (CREATE EXTENSION, ALTER DATABASE и т.п.)
sed -i '/^CREATE EXTENSION/d' "$DUMP_FILE"
sed -i '/^COMMENT ON EXTENSION/d' "$DUMP_FILE"
sed -i '/^ALTER DATABASE/d' "$DUMP_FILE"
sed -i '/^SELECT pg_catalog\.set_config/d' "$DUMP_FILE"

# ===== 2. Копируем на сервер =====
echo "📤 Копирую $DUMP_FILE на $REMOTE_USER@$REMOTE_HOST..."
scp "$DUMP_FILE" "$REMOTE_USER@$REMOTE_HOST:/tmp/"

if [ $? -ne 0 ]; then
    echo "❌ Ошибка копирования"
    exit 1
fi

# ===== 3. Восстановление на сервере — ЧИСТАЯ ВЕРСИЯ =====
echo "⚙️ Восстанавливаю БД на сервере (порт $REMOTE_PG_PORT)..."

ssh "$REMOTE_USER@$REMOTE_HOST" "
    cd /tmp

    # Проверка PostgreSQL
    if ! ss -tuln | grep -q ':5434 '; then
        echo '⚠️ Порт 5434 не слушается. Проверьте postgresql.conf.'
        exit 1
    fi

    # === 3.1 Создаём расширения ОТ ИМЕНИ postgres (раз и навсегда) ===
    echo '🔧 Устанавливаем расширения (от postgres)...'
    sudo -u postgres psql -p 5434 -c \"CREATE EXTENSION IF NOT EXISTS \\\"uuid-ossp\\\";\" template1 2>/dev/null || true
    sudo -u postgres psql -p 5434 -c \"CREATE EXTENSION IF NOT EXISTS \\\"pgcrypto\\\";\" template1 2>/dev/null || true

    # === 3.2 Создаём роль и БД ===
    echo '🔧 Создаём БД и роль...'
    sudo -u postgres psql -p 5434 -c \"CREATE USER $REMOTE_PG_USER WITH PASSWORD '$REMOTE_PG_PASS';\" 2>/dev/null || true
    sudo -u postgres psql -p 5434 -c \"CREATE DATABASE $REMOTE_DB_NAME OWNER $REMOTE_PG_USER ENCODING 'UTF8' TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C';\" 2>/dev/null || true
    sudo -u postgres psql -p 5434 -c \"GRANT ALL PRIVILEGES ON DATABASE $REMOTE_DB_NAME TO $REMOTE_PG_USER;\" 2>/dev/null || true

    # === 3.3 Проверяем подключение ===
    export PGPASSWORD='$REMOTE_PG_PASS'
    if ! psql -h $REMOTE_PG_HOST -p $REMOTE_PG_PORT -U $REMOTE_PG_USER -d $REMOTE_DB_NAME -c 'SELECT 1;' >/dev/null 2>&1; then
        echo '❌ Не удаётся подключиться как $REMOTE_PG_USER.'
        echo '→ Проверьте pg_hba.conf: host $REMOTE_DB_NAME $REMOTE_PG_USER 127.0.0.1/32 md5'
        exit 1
    fi

    # === 3.4 Восстанавливаем ===
    echo '📥 Восстанавливаю SQL-дамп...'
    psql -h $REMOTE_PG_HOST -p $REMOTE_PG_PORT -U $REMOTE_PG_USER -d $REMOTE_DB_NAME \
        -v ON_ERROR_STOP=1 -q -f /tmp/$DUMP_FILE

    rm -f /tmp/$DUMP_FILE
    echo '✅ Восстановление завершено'
"

if [ $? -eq 0 ]; then
    echo "✅ БД успешно перенесена на $REMOTE_HOST!"
    echo "🔍 Проверка:"
    ssh "$REMOTE_USER@$REMOTE_HOST" \
        "export PGPASSWORD='$REMOTE_PG_PASS'; \
         psql -h $REMOTE_PG_HOST -p $REMOTE_PG_PORT -U $REMOTE_PG_USER -d $REMOTE_DB_NAME \
             -c '\\dt' \
             -c 'SELECT COUNT(*) FROM vpns;'"
else
    echo "❌ Ошибка восстановления на сервере"
    exit 1
fi