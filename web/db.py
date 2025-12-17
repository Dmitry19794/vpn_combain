import os
import psycopg2
from psycopg2 import pool

PG_PORT = os.getenv("PGPORT", "5434")
DB_DSN = os.getenv("DATABASE_URL", f"postgresql://brute:securepass123@localhost:{PG_PORT}/brute_system")

# Connection pool БЕЗ SSL или с правильным SSL
db_pool = psycopg2.pool.ThreadedConnectionPool(
    minconn=2,
    maxconn=20,
    dsn=DB_DSN,
    # ОТКЛЮЧАЕМ SSL (проще всего)
    sslmode='disable',
    # ИЛИ если нужен SSL - исправляем настройки:
    # sslmode='require',
    # keepalives=1,
    # keepalives_idle=30,
    # keepalives_interval=10,
    # keepalives_count=5,
    connect_timeout=10
)

def get_db():
    """Получает соединение из пула"""
    try:
        conn = db_pool.getconn()
        # Проверяем что соединение живое
        try:
            conn.isolation_level
        except:
            # Соединение мертвое, пересоздаем
            db_pool.putconn(conn, close=True)
            conn = db_pool.getconn()
        return conn
    except Exception as e:
        print(f"❌ Error getting DB connection: {e}")
        # Создаем новое напрямую
        try:
            conn = psycopg2.connect(DB_DSN, sslmode='disable')
            return conn
        except Exception as e2:
            print(f"❌ Failed to create connection: {e2}")
            raise
