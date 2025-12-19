#!/usr/bin/env python3
# vpn/web/proxy_checker_manager.py
import subprocess
import threading
import time
import os
import signal
import re
import traceback
from typing import Optional
from web.db import get_db, db_pool

# Путь к бинарнику
PROXY_CHECKER_BIN = "/opt/vpn/proxy/proxy_checker"

# Глобальный статус
STATUS = {
    "running": False,
    "paused": False,
    "pid": None,
    "last_log": "stopped"
}

PROCESS: Optional[subprocess.Popen] = None
PARSER_THREAD: Optional[threading.Thread] = None
_PARSER_CONN = None

# КЭШ для батчинга записей (чтобы не долбить БД на каждую строку)
_PROXY_CACHE = []
_CACHE_LOCK = threading.Lock()
_LAST_FLUSH = time.time()

# ===============================
# ИСПРАВЛЕННЫЕ РЕГУЛЯРКИ
# ===============================

# 1. Для строк с прокси (с ✅/✗ в начале)
# Примеры:
# ✅ 123.30.154.171:7777 | US | anonymous | avg: 312ms
# ✗ 45.66.77.88:8080 | EU | transparent | avg: 5.2s
PROXY_REGEX = re.compile(
    r"^[✅✗]\s+([\d\.]+):(\d+)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*avg:\s*([0-9\.]+(?:ms|s))",
    re.IGNORECASE
)

# 2. Для статистических строк (которые НЕ надо парсить)
# Примеры: 
# 14:11:09    📊 1600 | ✅ 0 | ❌ 0
# ⏱ 12:30:45   Checked: 5000 | Alive: 123
STATS_REGEX = re.compile(
    r"(^\d{2}:\d{2}:\d{2}|📊|⏱|Checked:|Total:|Progress:)",
    re.IGNORECASE
)


def _parse_speed_to_ms(speed_raw: str) -> int:
    """Преобразует "1.338s" или "312ms" в целые миллисекунды."""
    try:
        speed_raw = speed_raw.strip().lower()
        if speed_raw.endswith("ms"):
            return int(float(speed_raw[:-2]))
        if speed_raw.endswith("s"):
            return int(float(speed_raw[:-1]) * 1000)
        return int(float(speed_raw))
    except Exception:
        return 0


def _parse_line_to_db(line: str, conn):
    """
    Парсит строку и ДОБАВЛЯЕТ В КЭШ (не сразу в БД).
    """
    global _PROXY_CACHE, _LAST_FLUSH
    
    # Пропускаем статистические строки
    if STATS_REGEX.search(line):
        return
    
    # Парсим только строки с прокси
    m = PROXY_REGEX.search(line)
    if not m:
        # DEBUG: показываем что не распарсилось (только если это похоже на прокси)
        if ":" in line and "|" in line and any(c.isdigit() for c in line):
            print(f"⚠️ Failed to parse proxy line: {line[:100]}")
        return

    host = m.group(1)
    port = int(m.group(2))
    geo = m.group(3).strip()
    anonymity = m.group(4).strip()
    speed_raw = m.group(5).strip()
    speed_ms = _parse_speed_to_ms(speed_raw)
    
    # Определяем жив ли прокси (✅ = alive, ✗ = dead)
    is_alive = line.startswith("✅")
    
    print(f"{'✅' if is_alive else '❌'} Parsed: {host}:{port} | {geo} | {anonymity} | {speed_ms}ms")

    # Добавляем в кэш
    with _CACHE_LOCK:
        _PROXY_CACHE.append((host, port, geo, anonymity, speed_ms, is_alive))
        
        # Сбрасываем в БД раз в 5 секунд ИЛИ при 100 записях
        if len(_PROXY_CACHE) >= 100 or (time.time() - _LAST_FLUSH) > 5:
            print(f"🔄 Flushing cache: {len(_PROXY_CACHE)} proxies...")
            _flush_cache_to_db(conn)
            _LAST_FLUSH = time.time()


def _flush_cache_to_db(conn):
    """Записывает весь кэш в БД одним запросом."""
    global _PROXY_CACHE
    
    if not _PROXY_CACHE:
        return
    
    try:
        cur = conn.cursor()
        
        # Используем batch insert для скорости
        from psycopg2.extras import execute_values
        
        # ИСПРАВЛЕНО: передаем is_alive напрямую
        execute_values(cur, """
            INSERT INTO proxies (host, port, geo, is_alive, anonymity, speed_ms, last_check)
            VALUES %s
            ON CONFLICT (host, port)
            DO UPDATE SET
                geo = EXCLUDED.geo,
                is_alive = EXCLUDED.is_alive,
                anonymity = EXCLUDED.anonymity,
                speed_ms = EXCLUDED.speed_ms,
                last_check = NOW()
        """, [(h, p, g, alive, a, s) for h, p, g, a, s, alive in _PROXY_CACHE])
        
        conn.commit()
        count = len(_PROXY_CACHE)
        _PROXY_CACHE.clear()
        print(f"✅ Flushed {count} proxies to DB")
        
    except Exception as e:
        print(f"❌ Batch insert error: {e}")
        import traceback
        traceback.print_exc()
        try:
            conn.rollback()
        except:
            pass
        _PROXY_CACHE.clear()  # Очищаем чтобы не накапливать мусор


def _log_reader(proc):
    """
    Поток чтения stdout чекера (НЕБЛОКИРУЮЩИЙ с батчингом).
    """
    global STATUS, _PARSER_CONN

    try:
        _PARSER_CONN = get_db()
    except Exception as e:
        STATUS["last_log"] = f"db connect error: {e}"
        print("Parser DB connect error:", e)
        return

    try:
        while True:
            if proc.poll() is not None:
                # Процесс завершился - финальный flush
                print("Process terminated, final flush...")
                with _CACHE_LOCK:
                    _flush_cache_to_db(_PARSER_CONN)
                STATUS["last_log"] = "completed"
                break
            
            try:
                raw = proc.stdout.readline()
                
                if not raw:
                    time.sleep(0.1)
                    continue
                    
                line = raw.decode(errors="ignore").strip() if isinstance(raw, bytes) else str(raw).strip()
                
                if not line:
                    continue

                # Обновляем краткий лог (только для важных строк с прокси)
                if re.match(r'^[✅❌✗✓]\s+\d+\.\d+\.\d+\.\d+:\d+', line):
                    STATUS["last_log"] = line[:300]
                    print(f"[PROXY] {line}")
                elif "completed" in line.lower() or "finished" in line.lower():
                    STATUS["last_log"] = line[:300]
                    print(f"[INFO] {line}")
                    
                # Парсим (добавляем в кэш)
                try:
                    _parse_line_to_db(line, _PARSER_CONN)
                except Exception as e:
                    print(f"Parse error: {e}")
                        
            except Exception as e:
                if proc.poll() is not None:
                    break
                print(f"Read error: {e}")
                time.sleep(0.5)

    except Exception as e:
        STATUS["last_log"] = f"reader error: {e}"
        print(f"Reader exception: {e}")
    finally:
        # Финальный flush перед закрытием
        try:
            with _CACHE_LOCK:
                _flush_cache_to_db(_PARSER_CONN)
        except:
            pass
        
        try:
            if _PARSER_CONN:
                db_pool.putconn(_PARSER_CONN)
        except Exception as e:
            print(f"Failed to putconn: {e}")
        _PARSER_CONN = None


# ===============================
# ▶ START
# ===============================
def start_proxy_checker():
    global PROCESS, STATUS, PARSER_THREAD

    if STATUS.get("running"):
        return {"status": "already_running", "pid": STATUS.get("pid")}

    if not os.path.exists(PROXY_CHECKER_BIN):
        STATUS["last_log"] = "binary not found"
        return {"error": "binary not found"}

    # Запускаем бинарник
    PROCESS = subprocess.Popen(
        [PROXY_CHECKER_BIN, "--recheck-db"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
        universal_newlines=False,  # ← КРИТИЧНО
        close_fds=True
    )

    STATUS["running"] = True
    STATUS["paused"] = False
    STATUS["pid"] = PROCESS.pid
    STATUS["last_log"] = "started"

    # Стартуем поток парсера
    PARSER_THREAD = threading.Thread(target=_log_reader, args=(PROCESS,), daemon=True)
    PARSER_THREAD.start()

    print(f"✅ Proxy checker started with PID {PROCESS.pid}")
    return {"status": "started", "pid": PROCESS.pid}


# ===============================
# ⏹ STOP
# ===============================
def stop_proxy_checker():
    global PROCESS, STATUS

    if not PROCESS:
        STATUS["running"] = False
        STATUS["pid"] = None
        STATUS["last_log"] = "already_stopped"
        return {"status": "already_stopped"}

    try:
        os.kill(PROCESS.pid, signal.SIGTERM)
        for _ in range(10):
            if PROCESS.poll() is not None:
                break
            time.sleep(0.1)
        if PROCESS.poll() is None:
            try:
                os.kill(PROCESS.pid, signal.SIGKILL)
            except:
                pass
    except Exception as e:
        print(f"Error killing process: {e}")

    PROCESS = None
    STATUS["running"] = False
    STATUS["paused"] = False
    STATUS["pid"] = None
    STATUS["last_log"] = "stopped"

    print("⏹ Proxy checker stopped")
    return {"status": "stopped"}


# ===============================
# ⏸ PAUSE
# ===============================
def pause_proxy_checker():
    global STATUS

    if PROCESS and STATUS.get("running"):
        try:
            os.kill(PROCESS.pid, signal.SIGSTOP)
            STATUS["paused"] = True
            STATUS["last_log"] = "paused"
            print("⏸ Proxy checker paused")
            return {"status": "paused"}
        except Exception as e:
            return {"error": str(e)}

    return {"status": "not_running"}


# ===============================
# ▶ RESUME
# ===============================
def resume_proxy_checker():
    global STATUS

    if PROCESS and STATUS.get("paused"):
        try:
            os.kill(PROCESS.pid, signal.SIGCONT)
            STATUS["paused"] = False
            STATUS["last_log"] = "resumed"
            print("▶ Proxy checker resumed")
            return {"status": "resumed"}
        except Exception as e:
            return {"error": str(e)}

    return {"status": "not_paused"}


# ===============================
# 📌 STATUS
# ===============================
def get_proxy_checker_status():
    global STATUS
    
    # Проверка что процесс еще жив
    try:
        if STATUS.get("pid"):
            try:
                os.kill(STATUS["pid"], 0)
            except OSError:
                # Процесс мёртв
                STATUS["running"] = False
                STATUS["pid"] = None
                if STATUS["last_log"] != "completed":
                    STATUS["last_log"] = "process died"
    except Exception:
        pass

    return {
        "running": bool(STATUS.get("running")),
        "paused": bool(STATUS.get("paused")),
        "pid": STATUS.get("pid"),
        "last_log": STATUS.get("last_log", "")
    }
