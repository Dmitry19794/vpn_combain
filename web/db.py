import psycopg2
from psycopg2.pool import SimpleConnectionPool

DB_DSN = os.getenv("DATABASE_URL", "postgresql://brute:your_password_here@localhost:5434/brute_system")

db_pool = SimpleConnectionPool(
    minconn=2,      # было 1
    maxconn=100,    # было 40 - УВЕЛИЧИЛИ!
    dsn=DB_DSN
)

def get_db():
    return db_pool.getconn()