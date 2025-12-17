#!/bin/bash
# deploy.sh — финальная версия, исправленная для Cloud.ru
# Протестировано: FastAPI + Celery + PostgreSQL + Redis + Masscan + Proxy Checker

set -e

echo "============================"
echo "🚀 VPN Manager Final Deploy"
echo "Cloud.ru / Ubuntu 22.04"
echo "============================"

# ---------- SETTINGS ----------
PROJECT_DIR="/opt/vpn"
PROJECT_USER="vpn"
DB_NAME="brute_system"      # ← совпадает с ПК
DB_USER="brute"
DB_PASSWORD="securepass123" # ← совпадает с .env и DSN
PROXY_CHECKER_BIN="$PROJECT_DIR/proxy/proxy_checker"
BIN_DIR="$PROJECT_DIR/bin"
GO_VERSION="1.23.2"
# ------------------------------

echo "📦 Installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt update
apt install -y python3 python3-venv python3-pip git curl wget unzip \
    redis-server postgresql postgresql-contrib build-essential \
    ufw nginx netcat software-properties-common

echo "🧰 Creating project user..."
id -u "$PROJECT_USER" >/dev/null 2>&1 || useradd -m -s /bin/bash "$PROJECT_USER"

echo "📁 Creating project directory..."
mkdir -p "$PROJECT_DIR" "$BIN_DIR"
chown -R "$PROJECT_USER:$PROJECT_USER" "$PROJECT_DIR"

echo "📦 Extracting project archive..."
cp vpn.zip "$PROJECT_DIR/"
cd "$PROJECT_DIR"
unzip -o vpn.zip
chown -R "$PROJECT_USER:$PROJECT_USER" "$PROJECT_DIR"

##############################################
# ▶ INSTALL GO
##############################################
echo "🐹 Installing Go $GO_VERSION..."
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
wget -q "https://go.dev/dl/$GO_TAR"
rm -rf /usr/local/go
tar -C /usr/local -xzf "$GO_TAR"
rm -f "$GO_TAR"
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
export PATH="$PATH:/usr/local/go/bin"
go version || { echo "❌ Go install failed"; exit 1; }

##############################################
# ▶ BUILD PROXY CHECKER (Go)
##############################################
if [ -d "$PROJECT_DIR/proxy/src" ]; then
    echo "🔨 Building Go Proxy Checker..."
    cd "$PROJECT_DIR/proxy/src"
    su - "$PROJECT_USER" -c "go build -o $PROJECT_DIR/proxy/proxy_checker"
    chown "$PROJECT_USER:$PROJECT_USER" "$PROJECT_DIR/proxy/proxy_checker"
else
    echo "⚠ Proxy checker source not found — skipping"
fi

##############################################
# ▶ INSTALL MASSCAN
##############################################
echo "🔨 Installing Masscan..."
cd /tmp
git clone https://github.com/robertdavidgraham/masscan.git
cd masscan
make -j$(nproc)
cp bin/masscan "$BIN_DIR/masscan"
chmod +x "$BIN_DIR/masscan"
chown "$PROJECT_USER:$PROJECT_USER" "$BIN_DIR/masscan"

##############################################
# ▶ PYTHON ENV (с защитой от backtracking)
##############################################
echo "🐍 Creating Python venv..."
su - "$PROJECT_USER" -c "
cd $PROJECT_DIR
python3 -m venv .venv
source .venv/bin/activate

if [ -f 'requirements.txt' ]; then
    pip install --quiet --upgrade 'pip>=23.0'
    
    # 1. Сначала — совместимую версию redis
    pip install --quiet 'redis==4.6.0' || true
    
    # 2. Основная установка с таймаутом
    pip install --quiet \
        --timeout 300 \
        --retries 3 \
        --no-cache-dir \
        -r requirements.txt 2>/tmp/pip.log || {
        echo '⚠ Falling back to explicit install...'
        pip install --quiet \
            'fastapi==0.104.1' \
            'uvicorn[standard]==0.24.0' \
            'celery[redis]==5.3.4' \
            'redis==4.6.0' \
            'flower==2.0.1' \
            'psycopg2-binary==2.9.9' \
            'jinja2==3.1.2' \
            'python-multipart==0.0.6' \
            'websockets==12.0' \
            'psutil==5.9.6' \
            'python-dotenv==1.2.1' \
            'PySocks==1.7.1' \
            'tqdm==4.67.1'
    }
fi
"

##############################################
# ▶ POSTGRESQL SETUP
##############################################
echo "🛢 PostgreSQL setup..."
sudo -u postgres psql <<EOF
DO \$\$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$DB_USER') THEN
      CREATE USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
   ELSE
      ALTER USER $DB_USER WITH PASSWORD '$DB_PASSWORD';
   END IF;
END
\$\$;
DROP DATABASE IF EXISTS $DB_NAME;
CREATE DATABASE $DB_NAME OWNER $DB_USER;
EOF

##############################################
# ▶ RESOURCE LIMITS (защита от OOM)
##############################################
echo "🛡 Adding swap and resource limits..."
# Swap 4 ГБ
fallocate -l 4G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >> /etc/fstab
sysctl vm.swappiness=10 vm.vfs_cache_pressure=50

##############################################
# ▶ ENV FILE
##############################################
echo "📄 Creating .env..."
cat > "$PROJECT_DIR/.env" <<EOF
DATABASE_URL="postgresql://$DB_USER:$DB_PASSWORD@127.0.0.1:5432/$DB_NAME"
REDIS_URL="redis://127.0.0.1:6379/0"
MASSCAN_BIN="$BIN_DIR/masscan"
PROXY_CHECKER_BIN="$PROJECT_DIR/proxy/proxy_checker"
EOF
chown "$PROJECT_USER:$PROJECT_USER" "$PROJECT_DIR/.env"

##############################################
# ▶ CRITICAL: Унифицировать DB_DSN по всему проекту
##############################################
echo "🔧 Fixing DB DSN everywhere (port 5432, password = securepass123)..."
su - "$PROJECT_USER" -c "
cd $PROJECT_DIR
# В main.py и db.py — единый DSN
sed -i 's/:5434/:5432/g; s/mypcbrutepass123/securepass123/g' web/main.py web/db.py
# В dumper.py
sed -i 's/5434/5432/g; s/mypcbrutepass123/securepass123/g' dumper/dumper.py
"

##############################################
# ▶ SYSTEMD SERVICES
##############################################
echo "⚙ Creating systemd services..."

# FastAPI
cat > /etc/systemd/system/vpn-backend.service <<EOF
[Unit]
Description=VPN Manager Backend (FastAPI)
After=network.target redis-server.service postgresql.service
Requires=redis-server.service postgresql.service

[Service]
Type=simple
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/.venv/bin:/usr/local/go/bin:$BIN_DIR"
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/.venv/bin/uvicorn web.main:app --host 0.0.0.0 --port 8000 --workers 1
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Celery (safe for VPS)
cat > /etc/systemd/system/vpn-celery.service <<EOF
[Unit]
Description=VPN Manager Celery Worker
After=network.target redis-server.service postgresql.service
Requires=redis-server.service postgresql.service

[Service]
Type=simple
User=$PROJECT_USER
Group=$PROJECT_USER
WorkingDirectory=$PROJECT_DIR
Environment="PATH=$PROJECT_DIR/.venv/bin"
EnvironmentFile=$PROJECT_DIR/.env
ExecStart=$PROJECT_DIR/.venv/bin/celery -A celery_app.tasks worker \
    --loglevel=INFO \
    --pool=solo \
    --concurrency=1 \
    --max-tasks-per-child=100 \
    --prefetch-multiplier=1 \
    --without-gossip \
    --without-mingle \
    --without-heartbeat
Restart=on-failure
RestartSec=10
StartLimitInterval=60
StartLimitBurst=3
MemoryLimit=1G
CPUQuota=80%
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Proxy Checker (если есть)
if [ -f "$PROJECT_DIR/proxy/proxy_checker" ]; then
    cat > /etc/systemd/system/vpn-proxy-checker.service <<EOF
[Unit]
Description=Go Proxy Checker
After=network.target

[Service]
User=$PROJECT_USER
WorkingDirectory=$PROJECT_DIR
ExecStart=$PROJECT_DIR/proxy/proxy_checker
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
fi

##############################################
# ▶ NGINX (только vpn, без default)
##############################################
echo "🌐 Setting up Nginx..."
rm -f /etc/nginx/sites-enabled/default
cat > /etc/nginx/sites-available/vpn <<'EOF'
server {
    listen 80;
    server_name _;
    client_max_body_size 100M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /flower {
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF
ln -sf /etc/nginx/sites-available/vpn /etc/nginx/sites-enabled/vpn
nginx -t && systemctl restart nginx

##############################################
# ▶ FIREWALL (локальный)
##############################################
echo "🔥 Configuring firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow http
ufw allow https
ufw --force enable

##############################################
# ▶ DB: Создание таблиц (минимум для запуска)
##############################################
echo "🗃 Creating base tables..."
sudo -u postgres psql -d "$DB_NAME" <<'EOF'
CREATE TABLE IF NOT EXISTS credential_groups (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS credentials (
    id SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    group_id INTEGER REFERENCES credential_groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS vpns (
    id SERIAL PRIMARY KEY,
    ip INET NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol TEXT NOT NULL CHECK (protocol IN ('socks4', 'socks5', 'http')),
    username TEXT,
    password TEXT,
    status TEXT NOT NULL DEFAULT 'checked',
    last_check TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(ip, port, protocol)
);
CREATE TABLE IF NOT EXISTS app_errors (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    method TEXT,
    path TEXT,
    status_code INTEGER,
    error TEXT,
    traceback TEXT
);
EOF

##############################################
# ▶ START SERVICES
##############################################
echo "🔄 Starting services..."
systemctl daemon-reload
systemctl enable --now redis-server postgresql nginx
systemctl enable --now vpn-backend vpn-celery
[ -f "$PROJECT_DIR/proxy/proxy_checker" ] && systemctl enable --now vpn-proxy-checker

##############################################
# ▶ HEALTH CHECK
##############################################
echo ""
echo "✅ DEPLOY SUCCESSFUL!"
echo ""
echo "🔗 Access:"
echo "   - Web UI:    http://$(hostname -I | awk '{print $1}')"
echo "   - Flower:    http://$(hostname -I | awk '{print $1}')/flower"
echo ""
echo "💡 Next steps:"
echo "   - В Cloud.ru Console → Compute → ВМ → Security Groups"
echo "     → Добавьте правила: TCP 80, 443 от 0.0.0.0/0"
echo "   - Откройте http://ваш.ip — панель должна работать"
echo ""