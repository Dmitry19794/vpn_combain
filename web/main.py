#!/usr/bin/env python3
# vpn/web/main.py
import sys
import os

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import re
import ipaddress
import asyncio
import json
import subprocess
import psycopg2
import threading
import time
import signal
import psutil
import hashlib
import traceback as tb_lib
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from psycopg2.extras import RealDictCursor
from datetime import datetime
from typing import List
from web.db import get_db, db_pool
from functools import lru_cache

from web.proxy_checker_manager import (
    start_proxy_checker,
    stop_proxy_checker,
    pause_proxy_checker,
    resume_proxy_checker,
    get_proxy_checker_status
)

# КЭШ для /proxy-table
_PROXY_TABLE_CACHE = {"data": "", "timestamp": 0}
_PROXY_TABLE_LOCK = threading.Lock()

proxy_line_re = re.compile(
    r"(?P<alive>[✓✗])\s+"
    r"(?P<host>\d+\.\d+\.\d+\.\d+):(?P<port>\d+)\s+\|\s+"
    r"(?P<geo>[^|]+?)\s+\|\s+"
    r"(?P<anonymity>[^|]+?)\s+\|\s+avg:\s*(?P<avg>\d+)ms"
)

# Добавляем путь к Celery tasks (если есть)
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'celery_app'))

checker_process = None
checker_status = {"running": False, "pid": None, "file": None}

proxy_process = None
proxy_status = "stopped"  # running | paused | stopped

try:
    from tasks import run_masscan, process_pending_scans, control_job
    CELERY_AVAILABLE = True
except Exception as e:
    print(f"⚠️ Celery tasks not available: {e}")
    CELERY_AVAILABLE = False

app = FastAPI()

from pathlib import Path
BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")
PG_PORT = os.getenv("PGPORT", "5432")
DB_DSN = os.getenv("DATABASE_URL", f"postgresql://brute:your_password_here@localhost:{PG_PORT}/brute_system")

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    error_text = str(exc)
    trace_text = tb_lib.format_exc()

    try:
        db = get_db()
        cur = get_cursor(db)
        cur.execute("""
            INSERT INTO app_errors (method, path, status_code, error, traceback)
            VALUES (%s, %s, %s, %s, %s)
        """, (
            request.method,
            request.url.path,
            500,
            error_text,
            trace_text
        ))
        db.commit()
        db_pool.putconn(db)
    except Exception as db_err:
        print("❌ FAILED TO SAVE ERROR:", db_err)

    return PlainTextResponse(
        "Internal Server Error (saved to Errors tab)",
        status_code=500
    )

# WebSocket connections manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except:
                try:
                    self.active_connections.remove(connection)
                except:
                    pass

manager = ConnectionManager()

def get_cursor(db):
    return db.cursor(cursor_factory=RealDictCursor)

def is_valid_cidr(cidr):
    try:
        ipaddress.IPv4Interface(cidr)
        return True
    except ValueError:
        try:
            ipaddress.IPv4Address(cidr)
            return True
        except ValueError:
            return False

def is_valid_port(port_str):
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except Exception:
        return False

def is_valid_geo(geo):
    return geo in ['US', 'EU', 'ASIA']

def is_valid_ip_or_url(target):
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        # простая проверка, разрешаем домены (без сложной валидации)
        if '.' in target:
            return True
        return False

def get_celery_status():
    for p in psutil.process_iter(['name','cmdline']):
        try:
            cmd = p.info.get('cmdline') or []
            if any('celery' in (s or '') for s in cmd):
                return {"online": True, "pids": [p.pid]}
        except Exception:
            continue
    return {"online": False, "pids": []}

def get_celery_worker_status():
    """
    Ищет процессы celery worker в системе и возвращает dict:
    {"online": bool, "pids": [pid, ...]}
    """
    try:
        pids = []
        for p in psutil.process_iter(['pid', 'cmdline']):
            try:
                cmd = p.info.get('cmdline') or []
                # ищем 'celery' и 'worker' в командной строке
                if any('celery' in str(x) for x in cmd) and any('worker' in str(x) for x in cmd):
                    pids.append(p.info['pid'])
            except Exception:
                continue
        return {"online": bool(pids), "pids": pids}
    except Exception as e:
        print("get_celery_worker_status error:", e)
        return {"online": False, "pids": []}

# =============        ===================
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    initial_panel_content = await panel_content(request)
    return templates.TemplateResponse("index.html", {
        "request": request,
        "initial_content": initial_panel_content.body.decode('utf-8')
    })

@app.get("/panel-content", response_class=HTMLResponse)
async def panel_content(request: Request):
    """Главная панель со статусами всех систем"""
    db = get_db()
    cur = get_cursor(db)
    try:
        # Статусы сканирования
        cur.execute("""
            SELECT COUNT(*) as running_count
            FROM scan_jobs
            WHERE status IN ('running', 'paused')
        """)
        running_count = cur.fetchone()['running_count']
        
        # Статус VPN
        cur.execute("SELECT COUNT(*) as total FROM vpns")
        vpn_total = cur.fetchone()["total"]
        
        cur.execute("SELECT status, COUNT(*) FROM vpns GROUP BY status")
        vpn_status_counts = {r["status"]: r["count"] for r in cur.fetchall()}
        
    except Exception as e:
        print(f"❌ panel_content error: {e}")
        running_count = 0
        vpn_total = 0
        vpn_status_counts = {}
    finally:
        db_pool.putconn(db)
    
    return templates.TemplateResponse("partials/panel_content.html", {
        "request": request,
        "running_count": running_count,
        "vpn_total": vpn_total,
        "vpn_status_counts": vpn_status_counts
    })

@app.get("/metrics-partial", response_class=HTMLResponse)
async def metrics_partial(request: Request):
    db = get_db()
    cur = get_cursor(db)

    try:
        # Количество групп
        cur.execute("SELECT COUNT(*) AS cnt FROM cred_groups;")
        cred_groups = cur.fetchone()["cnt"]

        # Логины
        cur.execute("SELECT COUNT(*) AS cnt FROM logins;")
        logins = cur.fetchone()["cnt"]

        # Пароли
        cur.execute("SELECT COUNT(*) AS cnt FROM passwords;")
        passwords = cur.fetchone()["cnt"]

        # ИСПРАВЛЕНО: считаем только ЖИВЫЕ прокси
        cur.execute("SELECT COUNT(*) AS cnt FROM proxies WHERE is_alive = TRUE;")
        proxies = cur.fetchone()["cnt"]

        # VPN
        cur.execute("SELECT COUNT(*) AS cnt FROM vpns;")
        vpns = cur.fetchone()["cnt"]

    except Exception as e:
        print("METRICS ERROR:", e)
        cred_groups = logins = passwords = proxies = vpns = 0

    finally:
        db_pool.putconn(db)

    return templates.TemplateResponse("partials/metrics_partial.html", {
        "request": request,
        "cred_groups": cred_groups,
        "logins": logins,
        "passwords": passwords,
        "proxies": proxies,
        "vpns": vpns
    })

@app.post("/clear-masscan")
async def clear_masscan():
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("TRUNCATE TABLE scan_jobs, scanned_addresses RESTART IDENTITY CASCADE;")
        db.commit()
        return RedirectResponse(url="/masscan-content", status_code=303)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка очистки: {e}")
    finally:
        db_pool.putconn(db)

# ========== WEBSOCKET ==========
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await asyncio.sleep(3)
            db = get_db()
            cur = get_cursor(db)
            try:
                cur.execute("""
                    SELECT j.id, j.status, j.progress_percent, j.result_count, j.control_action
                    FROM scan_jobs j
                    WHERE j.status IN ('running', 'paused', 'pending')
                    ORDER BY j.created_at DESC
                    LIMIT 50
                """)
                jobs = cur.fetchall()
            finally:
                db_pool.putconn(db)

            await websocket.send_json({
                'type': 'jobs_update',
                'jobs': [dict(job) for job in jobs]
            })
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# ========== API ENDPOINTS ==========
@app.get("/api/jobs-status")
async def get_jobs_status():
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            SELECT j.id, j.status, j.progress_percent, j.result_count, 
                   j.control_action, j.started_at
            FROM scan_jobs j
            WHERE j.status IN ('running', 'paused', 'pending')
            ORDER BY j.created_at DESC
        """)
        jobs = cur.fetchall()
    finally:
        db_pool.putconn(db)
    return {'jobs': [dict(job) for job in jobs]}

@app.post("/api/control-job")
async def api_control_job(
    job_id: str = Form(...),
    action: str = Form(...)
):
    if not CELERY_AVAILABLE:
        raise HTTPException(status_code=503, detail="Celery not available")
    if action not in ['pause', 'resume', 'stop']:
        raise HTTPException(status_code=400, detail=f"Invalid action: {action}")
    result = control_job.delay(job_id, action)
    await manager.broadcast({
        'type': 'job_control',
        'job_id': job_id,
        'action': action
    })
    return {
        'status': 'success',
        'job_id': job_id,
        'action': action,
        'task_id': result.id
    }

# ========== checker proxy ==============
def run_proxy_checker():
    subprocess.Popen(
        ["./proxy/proxy_checker"],
        cwd="/home/argentum/GolandProjects/vpn/",
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def import_proxies_from_file():
    conn = get_db()
    cur = conn.cursor()

    with open("working_proxies.txt") as f:
        for line in f:
            if ":" not in line:
                continue
            
            host, port = line.strip().split(":")

            cur.execute("""
                INSERT INTO proxies (host, port, is_alive, last_check)
                VALUES (%s, %s, true, now())
                ON CONFLICT (host, port) DO UPDATE
                SET is_alive = true,
                    last_check = now();
            """, (host, int(port)))

    conn.commit()
    cur.close()

def read_proxy_output():
    global proxy_process

    for line in proxy_process.stdout:
        try:
            text = line.decode('utf-8', errors='ignore').strip()
        except:
            continue

        if not text:
            continue

        print("[PROXY]", text)

        # --- парсим строку ---
        m = proxy_line_re.search(text)
        if not m:
            continue

        parsed = {
            "alive": m.group("alive") == "✓",
            "host": m.group("host"),
            "port": int(m.group("port")),
            "geo": m.group("geo").strip(),
            "anonymity": m.group("anonymity").strip(),
            "speed_ms": int(m.group("avg"))
        }

        save_proxy_parsed(parsed)

# ========== НОВЫЕ ЭНДПОИНТЫ ДЛЯ PROXY CHECKER ==========

@app.get("/proxy-checker-status", response_class=HTMLResponse)
async def proxy_checker_status_html():
    """Возвращает HTML статус чекера"""
    status = get_proxy_checker_status()
    
    running = status.get("running", False)
    paused = status.get("paused", False)
    pid = status.get("pid")
    
    if running and paused:
        icon = "⏸"
        color = "#f57c00"
        text = "Paused"
    elif running:
        icon = "🟢"
        color = "#2e7d32"
        text = "Running"
    else:
        icon = "🔴"
        color = "#d32f2f"
        text = "Stopped"
    
    pid_text = f" (PID: {pid})" if pid else ""
    
    return f'<span style="color:{color};">{icon} {text}{pid_text}</span>'

@app.get("/proxy-checker-logs", response_class=HTMLResponse)
async def proxy_checker_logs():
    """Возвращает последние логи чекера"""
    status = get_proxy_checker_status()
    log = status.get("last_log", "No logs yet")
    
    # Форматируем лог для отображения
    if "✓" in log or "[OK]" in log or "found" in log.lower():
        return f'<span style="color:#a5d6a7;">✅ {log}</span>'
    elif "✗" in log or "error" in log.lower() or "failed" in log.lower():
        return f'<span style="color:#ff8a80;">❌ {log}</span>'
    elif "stopped" in log or "paused" in log:
        return f'<span style="color:#ffb74d;">⚠️ {log}</span>'
    else:
        return f'<span style="color:#e0e0e0;">{log}</span>'

# --- роуты для чекера ---
@app.post("/proxy-checker-start")
async def api_checker_start():
    try:
        res = start_proxy_checker()
        return JSONResponse(content=res)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/proxy-checker-stop")
async def api_checker_stop():
    try:
        res = stop_proxy_checker()
        return JSONResponse(content=res)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/proxy-checker-pause")
async def api_checker_pause():
    try:
        res = pause_proxy_checker()
        return JSONResponse(content=res)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

@app.post("/proxy-checker-resume")
async def api_checker_resume():
    try:
        res = resume_proxy_checker()
        return JSONResponse(content=res)
    except Exception as e:
        return JSONResponse(status_code=500, content={"error": str(e)})

def save_proxy_parsed(parsed):
    """
    parsed = {
        "alive": True/False,
        "host": "...",
        "port": int,
        "geo": "...",
        "anonymity": "...",
        "speed_ms": int
    }
    """
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            INSERT INTO proxies (host, port, geo, anonymity, speed_ms, is_alive, last_check)
            VALUES (%s, %s, %s, %s, %s, %s, NOW())
            ON CONFLICT (host, port) DO UPDATE SET
                geo = EXCLUDED.geo,
                anonymity = EXCLUDED.anonymity,
                speed_ms = EXCLUDED.speed_ms,
                is_alive = EXCLUDED.is_alive,
                last_check = NOW();
        """, (
            parsed["host"],
            parsed["port"],
            parsed["geo"],
            parsed["anonymity"],
            parsed["speed_ms"],
            parsed["alive"]
        ))
        db.commit()
    except Exception as e:
        print("DB write failed:", e)
        db.rollback()
    finally:
        db_pool.putconn(db)

@app.delete("/proxies/clear")
def clear_proxies():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM proxies")
    conn.commit()
    cur.close()
    return {"status": "ok"}

@app.get("/proxy/list")
def proxy_list():
    db = get_db()
    cur = get_cursor(db)

    cur.execute("""
        SELECT host, port, country, anonymity, speed, last_check
        FROM proxies
        ORDER BY last_check DESC
        LIMIT 250
    """)

    rows = cur.fetchall()

    html = ""
    for r in rows:
        html += f"""
        <tr>
            <td>{r[0]}</td>
            <td>{r[1]}</td>
            <td>{r[2]}</td>
            <td>{r[3]}</td>
            <td>{r[4]}</td>
            <td>{r[5]}</td>
        </tr>
        """

    if not html:
        html = "<tr><td colspan='6'>No proxies yet</td></tr>"

    return html

@app.get("/api/proxy-list-all")
async def api_proxy_list_all(limit: int = 10000):
    """Возвращает ВСЕ прокси (is_alive = TRUE/FALSE), максимум limit штук."""
    conn = None
    try:
        conn = get_db()
        cur = get_cursor(conn)
        cur.execute("""
            SELECT id, host, port, geo, anonymity, speed_ms, is_alive, last_check
            FROM proxies
            ORDER BY last_check DESC NULLS FIRST  -- сначала не проверенные
            LIMIT %s;
        """, (limit,))
        rows = cur.fetchall()
        proxies = []
        for r in rows:
            proxies.append({
                "id": str(r["id"]),
                "host": r["host"],
                "port": r["port"],
                "geo": r["geo"] or "unknown",
                "anonymity": r["anonymity"] or "anonymous",
                "speed_ms": r["speed_ms"] or 0,
                "is_alive": r["is_alive"],
                "last_check": r["last_check"].isoformat() if r["last_check"] else None
            })
        return JSONResponse({"proxies": proxies, "count": len(proxies)})
    except Exception as e:
        print(f"❌ /api/proxy-list-all error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if conn:
            db_pool.putconn(conn)

@app.get("/api/proxy-list")
async def api_proxy_list(limit: int = 200, geo: str = None):
    """API для получения списка прокси в JSON формате"""
    conn = None
    try:
        conn = get_db()
        cur = get_cursor(conn)  # ← Используем RealDictCursor из db.py
        
        if geo:
            cur.execute("""
                SELECT id, host, port, geo, anonymity, speed_ms, is_alive, last_check
                FROM proxies
                WHERE geo = %s AND is_alive = TRUE
                ORDER BY last_check DESC NULLS LAST
                LIMIT %s
            """, (geo, limit))
        else:
            cur.execute("""
                SELECT id, host, port, geo, anonymity, speed_ms, is_alive, last_check
                FROM proxies
                WHERE is_alive = TRUE
                ORDER BY last_check DESC NULLS LAST
                LIMIT %s
            """, (limit,))
        
        rows = cur.fetchall()
        
        # RealDictCursor уже возвращает dict, но конвертируем UUID в строку
        proxies = []
        for r in rows:
            proxies.append({
                "id": str(r["id"]),
                "host": r["host"],
                "port": r["port"],
                "geo": r["geo"] or "unknown",
                "anonymity": r["anonymity"] or "anonymous",
                "speed_ms": r["speed_ms"] or 0,
                "is_alive": r["is_alive"],
                "last_check": r["last_check"].isoformat() if r["last_check"] else None
            })
        
        return JSONResponse(content={"proxies": proxies, "count": len(proxies)})
        
    except Exception as e:
        print(f"❌ /api/proxy-list error: {e}")
        import traceback
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})
        
    finally:
        if conn:
            try:
                db_pool.putconn(conn)
            except:
                pass

@app.post("/api/proxy-batch-update")
async def api_proxy_batch_update(proxies: List[dict]):
    """
    Обновляет СУЩЕСТВУЮЩИЕ прокси: is_alive, speed_ms, last_check, geo, anonymity
    Новые прокси НЕ добавляет.
    Формат: [{"host", "port", "geo", "anonymity", "speed_ms", "is_alive"}]
    """
    conn = None
    try:
        conn = get_db()
        cur = get_cursor(conn)
        updated = 0
        for p in proxies:
            cur.execute("""
                UPDATE proxies
                SET
                    geo = %s,
                    anonymity = %s,
                    speed_ms = %s,
                    is_alive = %s,
                    last_check = NOW()
                WHERE host = %s AND port = %s;
            """, (
                p.get("geo", "??"),
                p.get("anonymity", "anonymous"),
                int(p.get("speed_ms", 0)),
                bool(p.get("is_alive", False)),
                p["host"],
                int(p["port"])
            ))
            updated += cur.rowcount
        conn.commit()
        return {"updated": updated, "total": len(proxies)}
    except Exception as e:
        if conn:
            conn.rollback()
        print(f"❌ /api/proxy-batch-update error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if conn:
            db_pool.putconn(conn)

@app.get("/proxy-table", response_class=HTMLResponse)
def proxy_table(limit: int = 50):
    """Возвращает HTML таблицу прокси"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()

        cur.execute("""
            SELECT host, port, geo, anonymity, speed_ms, is_alive, last_check
            FROM proxies
            WHERE is_alive = TRUE
            ORDER BY last_check DESC NULLS LAST
            LIMIT %s;
        """, (limit,))

        rows = cur.fetchall()
        print(f"📊 /proxy-table: found {len(rows)} proxies")
        
        if not rows:
            return "<tr><td colspan='6' style='text-align:center;'>No proxies yet</td></tr>"

        html = ""
        for r in rows:
            host = r[0]
            port = r[1]
            geo = r[2] or "unknown"
            anonymity = r[3] or "-"
            speed_ms = r[4] or 0
            is_alive = r[5]
            last_check = r[6]
            
            alive_icon = "🟢" if is_alive else "🔴"
            speed = f"{speed_ms}ms" if speed_ms else "-"
            last_check_str = last_check.strftime('%H:%M:%S') if last_check else '-'
            
            html += f"""
            <tr>
                <td style="font-family:monospace;">{host}</td>
                <td>{port}</td>
                <td><strong>{geo}</strong></td>
                <td>{anonymity}</td>
                <td style="color:#a5d6a7;">{speed}</td>
                <td>{alive_icon} {last_check_str}</td>
            </tr>
            """
        
        cur.close()
        return html
        
    except Exception as e:
        print(f"❌ /proxy-table error: {e}")
        return "<tr><td colspan='6' style='color:#ff8a80;'>Error</td></tr>"
    finally:
        if conn:
            db_pool.putconn(conn)

# ========== checker vpn ENDPOINTS ==========
@app.post("/start-checker")
async def start_checker(file: UploadFile = File(...)):
    global checker_process, checker_status

    if checker_status["running"]:
        return {"status": "already_running"}

    upload_path = f"/tmp/{file.filename}"
    with open(upload_path, "wb") as f:
        f.write(await file.read())

    checker_process = subprocess.Popen(
        ["./checker"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    checker_status = {
        "running": True,
        "pid": checker_process.pid,
        "file": upload_path
    }

    return {"status": "started", "pid": checker_process.pid}

@app.get("/checker-status")
def checker_status_endpoint():
    """Статус VPN checker (не proxy checker!)"""
    try:
        # Пока VPN checker не реализован - возвращаем заглушку
        return JSONResponse({
            "running": False,
            "pid": None,
            "last_log": "VPN Checker not implemented yet"
        })
    except Exception as e:
        print("checker-status error:", e)
        return JSONResponse({"running": False, "pid": None, "last_log": ""})

@app.get("/checker-content", response_class=HTMLResponse)
async def checker_content(request: Request):
    return templates.TemplateResponse("checker_content.html", {"request": request})

# ========== ОСТАЛЬНЫЕ ENDPOINTS ==========

@app.get("/scan-jobs-status", response_class=HTMLResponse)
async def scan_jobs_status():
    try:
        conn = psycopg2.connect(DB_DSN)
        cur = conn.cursor()

        cur.execute("""
            SELECT id, status, geo, created_at
            FROM scan_jobs
            ORDER BY created_at DESC
            LIMIT 20
        """)
        jobs = cur.fetchall()

        cur.close()
        conn.close()

        if not jobs:
            return "<div class='pending'>No scan jobs</div>"

        html = """
        <table>
            <tr>
                <th>ID</th>
                <th>Status</th>
                <th>GEO</th>
                <th>Created</th>
            </tr>
        """

        for job_id, status, geo, created in jobs:
            css = "pending"
            if status == "running":
                css = "running"
            elif status == "completed":
                css = "completed"

            html += f"""
            <tr class="{css}">
                <td>{job_id}</td>
                <td>{status}</td>
                <td>{geo}</td>
                <td>{created}</td>
            </tr>
            """

        html += "</table>"
        return html

    except Exception as e:
        return f"<div class='running'>DB Error: {e}</div>"

@app.post("/start-global-scan")
async def start_global_scan():
    return "<b>Scan started (manual trigger)</b>"

@app.post("/stop-all-scans")
async def stop_all_scans():
    return "<b>Stop signal sent</b>"

# /celery-status — возвращает HTML (htmx ожидает HTML)
@app.get("/celery-status", response_class=HTMLResponse)
def celery_status_endpoint():
    try:
        st = get_celery_worker_status()
        if st.get("online"):
            pids = ", ".join(str(x) for x in st.get("pids", []))
            return HTMLResponse(f"🟢 Online (pids: {pids})")
        else:
            return HTMLResponse("🔴 Offline")
    except Exception as e:
        # не ломаем UI, просто сообщим Offline
        print("celery-status error:", e)
        return HTMLResponse("🔴 Offline")

@app.get("/vpns-content", response_class=HTMLResponse)
async def vpns_content(request: Request):
    vpns_part = await vpns_partial(request)

    html_content = f"""
    <div class="card">
        <h3>📡 Последние 10 VPN</h3>
        {vpns_part.body.decode('utf-8')}
    </div>
    """

    return HTMLResponse(content=html_content)

@app.get("/masscan-content", response_class=HTMLResponse)
async def masscan_content(request: Request):
    process_status = await scan_process_status(request)
    jobs_status = await scan_jobs_status(request)
    return templates.TemplateResponse("partials/masscan_content.html", {
        "request": request,
        "process_status": process_status.body.decode('utf-8'),
        "jobs_status": jobs_status.body.decode('utf-8')
    })

@app.get("/proxy-content", response_class=HTMLResponse)
async def proxy_content(request: Request):
    return templates.TemplateResponse("partials/proxy_content.html", {
        "request": request
    })

@app.post("/upload-proxies")
async def upload_proxies(file: UploadFile = File(...), geo: str = Form(...)):
    if not is_valid_geo(geo):
        return HTMLResponse('<div style="color:#d32f2f;">❌ Неверная GEO</div>')
    contents = (await file.read()).decode('utf-8').strip().splitlines()
    entries = []
    for ln in contents:
        ln = ln.strip()
        if not ln:
            continue
        # Ожидаем host:port
        if ':' not in ln:
            continue
        host, port = ln.split(':', 1)
        host = host.strip()
        port = port.strip()
        if not host or not port:
            continue
        try:
            port_int = int(port)
        except:
            continue
        entries.append((host, port_int, geo))
    if not entries:
        return HTMLResponse('<div style="color:#d32f2f;">❌ Нет валидных записей host:port</div>')
    db = get_db()
    cur = get_cursor(db)
    inserted = 0
    try:
        # Убедимся, что таблица существует (безопасно)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS proxies (
                id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                geo TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        for host, port_int, geo in entries:
            cur.execute("""
                INSERT INTO proxies (host, port, geo)
                VALUES (%s, %s, %s)
                ON CONFLICT (host, port) DO NOTHING;
            """, (host, port_int, geo))
            if cur.rowcount > 0:
                inserted += 1
        db.commit()
    except Exception as e:
        db.rollback()
        return HTMLResponse(f'<div style="color:#d32f2f;">❌ Ошибка записи: {str(e)[:200]}</div>')
    finally:
        db_pool.putconn(db)
    return HTMLResponse(f'<div style="color:#a5d6a7;">✅ Загружено {inserted} прокси</div>')

@app.get("/errors-content", response_class=HTMLResponse)
async def errors_content(request: Request):
    db = get_db()
    cur = get_cursor(db)

    try:
        cur.execute("""
            SELECT id, created_at, method, path, status_code, error, traceback
            FROM app_errors
            ORDER BY created_at DESC
            LIMIT 100;
        """)
        errors = cur.fetchall()
    except Exception as e:
        print("ERRORS TAB LOAD FAILED:", e)
        errors = []
    finally:
        db_pool.putconn(db)

    return templates.TemplateResponse("partials/errors_content.html", {
        "request": request,
        "errors": errors
    })

@app.post("/clear-errors")
async def clear_errors():
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("TRUNCATE TABLE app_errors;")
        db.commit()
    finally:
        db_pool.putconn(db)

    return RedirectResponse(url="/errors-content", status_code=303)

@app.get("/vpns-partial", response_class=HTMLResponse)
async def vpns_partial(request: Request):
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            SELECT id, target_url, protocol, status, geo
            FROM vpns
            ORDER BY created_at DESC
            LIMIT 10
        """)
        vpns = cur.fetchall()
    finally:
        db_pool.putconn(db)
    return templates.TemplateResponse("partials/vpns.html", {
        "request": request,
        "vpns": vpns
    })

@app.post("/rebrut")
async def rebrut(vpn_id: str = Form(...)):
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            INSERT INTO tasks (id, type, status, payload, geo)
            SELECT gen_random_uuid(), 'rebrut', 'pending',
                   jsonb_build_object('vpn_id', %s, 'usernames', ARRAY['administrator','it','helpdesk']),
                   geo
            FROM vpns WHERE id = %s
        """, (vpn_id, vpn_id))
        db.commit()
    finally:
        db_pool.putconn(db)
    return {"status": "rebrut queued"}

@app.post("/add-scan-job")
async def add_scan_job(
    cidr: str = Form(...),
    geo: str = Form(...),
    port: str = Form(...)
):
    if not cidr or not geo or not port:
        raise HTTPException(status_code=400, detail="Все поля обязательны")
    if not is_valid_cidr(cidr):
        raise HTTPException(status_code=400, detail=f"Неверный формат CIDR/IP: {cidr}")
    if not is_valid_port(port):
        raise HTTPException(status_code=400, detail=f"Неверный порт: {port}")
    if not is_valid_geo(geo):
        raise HTTPException(status_code=400, detail=f"Неверная гео: {geo}")
    port_int = int(port)
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            INSERT INTO scan_subnets (cidr, geo)
            VALUES (%s, %s)
            ON CONFLICT (cidr, geo) DO UPDATE SET cidr = EXCLUDED.cidr
            RETURNING id;
        """, (cidr, geo))
        subnet_id = cur.fetchone()['id']
        cur.execute("""
            INSERT INTO scan_ports (port, protocol)
            VALUES (%s, 'tcp')
            ON CONFLICT (port, protocol) DO UPDATE SET port = EXCLUDED.port
            RETURNING id;
        """, (port_int,))
        port_id = cur.fetchone()['id']
        cur.execute("""
            INSERT INTO scan_jobs (subnet_id, port_id, status)
            VALUES (%s, %s, 'pending')
            RETURNING id;
        """, (subnet_id, port_id))
        job_id = cur.fetchone()['id']
        db.commit()
        return {
            "status": "success",
            "message": f"Задача создана для {cidr}:{port} (GEO: {geo})",
            "job_id": str(job_id)
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка БД: {str(e)}")
    finally:
        db_pool.putconn(db)

@app.post("/upload-subnets")
async def upload_subnets(
    file: UploadFile = File(...),
    geo: str = Form(...),
    port: str = Form(...)
):
    if not is_valid_geo(geo):
        raise HTTPException(status_code=400, detail=f"Неверная гео: {geo}")
    if not is_valid_port(port):
        raise HTTPException(status_code=400, detail=f"Неверный порт: {port}")
    port_int = int(port)
    contents = await file.read()
    await file.close()
    cidr_list = contents.decode('utf-8').strip().split('\n')
    valid_cidrs = []
    for line in cidr_list:
        cidr = line.strip()
        if cidr and is_valid_cidr(cidr):
            valid_cidrs.append(cidr)
    if not valid_cidrs:
        raise HTTPException(status_code=400, detail="Файл не содержит валидных CIDR")
    db = get_db()
    cur = get_cursor(db)
    try:
        created_jobs = 0
        for cidr in valid_cidrs:
            cur.execute("""
                INSERT INTO scan_subnets (cidr, geo)
                VALUES (%s, %s)
                ON CONFLICT (cidr, geo) DO UPDATE SET cidr = EXCLUDED.cidr
                RETURNING id;
            """, (cidr, geo))
            subnet_id = cur.fetchone()['id']
            cur.execute("""
                INSERT INTO scan_ports (port, protocol)
                VALUES (%s, 'tcp')
                ON CONFLICT (port, protocol) DO UPDATE SET port = EXCLUDED.port
                RETURNING id;
            """, (port_int,))
            port_id = cur.fetchone()['id']
            cur.execute("""
                INSERT INTO scan_jobs (subnet_id, port_id, status)
                VALUES (%s, %s, 'pending');
            """, (subnet_id, port_id))
            created_jobs += 1
        db.commit()
        return {
            "status": "success",
            "message": f"Создано {created_jobs} задач для GEO: {geo}, Port: {port_int}"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка БД: {str(e)}")
    finally:
        db_pool.putconn(db)

@app.post("/upload-addresses")
async def upload_addresses(
    file: UploadFile = File(...),
    geo: str = Form(...),
    port: str = Form(...)
):
    if not is_valid_geo(geo):
        raise HTTPException(status_code=400, detail=f"Неверная гео: {geo}")
    if not is_valid_port(port):
        raise HTTPException(status_code=400, detail=f"Неверный порт: {port}")
    port_int = int(port)
    contents = await file.read()
    await file.close()
    target_list = contents.decode('utf-8').strip().split('\n')
    valid_targets = []
    for line in target_list:
        target = line.strip()
        if target and is_valid_ip_or_url(target):
            valid_targets.append(target)
    if not valid_targets:
        raise HTTPException(status_code=400, detail="Файл не содержит валидных IP")
    db = get_db()
    cur = get_cursor(db)
    try:
        for target in valid_targets:
            cur.execute("""
                INSERT INTO scanned_addresses (id, ip, port, geo, is_checked, created_at, updated_at)
                VALUES (gen_random_uuid(), %s, %s, %s, FALSE, NOW(), NOW())
                ON CONFLICT DO NOTHING;
            """, (target, port_int, geo))
        db.commit()
        return {
            "status": "success",
            "message": f"Загружено {len(valid_targets)} IP для GEO: {geo}, Port: {port_int}"
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Ошибка БД: {str(e)}")
    finally:
        db_pool.putconn(db)

@app.post("/start-masscan")
async def start_masscan(geo: str = Form(default="US")):
    if not CELERY_AVAILABLE:
        raise HTTPException(status_code=503, detail="Celery not available")
    if not is_valid_geo(geo):
        raise HTTPException(status_code=400, detail=f"Неверная гео: {geo}")
    task = process_pending_scans.delay(geo=geo, limit=10)
    return {
        "status": "success",
        "message": f"Запущена обработка pending задач для GEO: {geo}",
        "celery_task_id": task.id
    }

@app.get("/scan-process-status", response_class=HTMLResponse)
async def scan_process_status(request: Request):
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            SELECT COUNT(*) as running_count
            FROM scan_jobs
            WHERE status IN ('running', 'paused')
        """)
        running_count = cur.fetchone()['running_count']
    finally:
        db_pool.putconn(db)
    status_text = f"Celery: {running_count} активных задач" if CELERY_AVAILABLE else "Celery: недоступен"
    button_text = "Запустить обработку"
    button_disabled = "" if CELERY_AVAILABLE else "disabled"
    return templates.TemplateResponse("partials/scan_process_status.html", {
        "request": request,
        "status_text": status_text,
        "button_text": button_text,
        "button_disabled": button_disabled
    })

@app.get("/scan-jobs-status", response_class=HTMLResponse)
async def scan_jobs_status(request: Request):
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            SELECT s.geo, j.status, COUNT(*) as cnt
            FROM scan_jobs j
            JOIN scan_subnets s ON j.subnet_id = s.id
            GROUP BY s.geo, j.status
        """)
        masscan_status_counts = {}
        for r in cur.fetchall():
            geo = r["geo"]
            status = r["status"]
            cnt = r["cnt"]
            if geo not in masscan_status_counts:
                masscan_status_counts[geo] = {}
            masscan_status_counts[geo][status] = cnt
    finally:
        db_pool.putconn(db)
    return templates.TemplateResponse("partials/scan_jobs_status.html", {
        "request": request,
        "masscan_status_counts": masscan_status_counts,
    })

@app.get("/task-status/{task_id}")
async def get_task_status(task_id: str):
    if not CELERY_AVAILABLE:
        return {"error": "Celery not available"}
    from celery.result import AsyncResult
    task = AsyncResult(task_id)
    response = {
        'task_id': task_id,
        'state': task.state,
        'info': task.info if task.info else {}
    }
    return response

# ================== Credentials area (FIXED) ==================
@app.get("/credentials-content", response_class=HTMLResponse)
async def credentials_content(request: Request):
    """
    Возвращаем шаблон credentials_content.html с переменной cred_groups,
    где каждая группа содержит .logins и .passwords — списки значений.
    """
    db = get_db()
    cur = get_cursor(db)
    cred_groups = []
    try:
        cur.execute("SELECT id, name, geo, priority, created_at FROM cred_groups ORDER BY created_at DESC;")
        groups = cur.fetchall()
        for g in groups:
            gid = g['id']
            # Получаем логины для группы
            cur.execute("""
                SELECT l.id, l.value
                FROM cred_group_logins cgl
                JOIN logins l ON l.id = cgl.login_id
                WHERE cgl.group_id = %s
                ORDER BY l.created_at NULLS LAST;
            """, (gid,))
            logins = [r['value'] for r in cur.fetchall()] if cur.rowcount else []

            # Получаем пароли для группы
            cur.execute("""
                SELECT p.id, p.value
                FROM cred_group_passwords cgp
                JOIN passwords p ON p.id = cgp.password_id
                WHERE cgp.group_id = %s
                ORDER BY p.created_at NULLS LAST;
            """, (gid,))
            passwords = [r['value'] for r in cur.fetchall()] if cur.rowcount else []

            # Формируем структуру для шаблона
            cred_groups.append({
                "id": gid,
                "name": g["name"],
                "geo": g["geo"],
                "priority": g.get("priority", 0),
                "created_at": g.get("created_at"),
                "logins": logins,
                "passwords": passwords
            })
    except Exception as e:
        # В случае ошибки возвращаем пустой список, чтобы UI не ломался
        print("Credentials query error:", e)
        cred_groups = []
    finally:
        db_pool.putconn(db)

    # Также можно посчитать общую статистику (кол-во логинов/паролей/групп)
    total_logins = 0
    total_passwords = 0
    try:
        total_logins = sum(len(g['logins']) for g in cred_groups)
        total_passwords = sum(len(g['passwords']) for g in cred_groups)
    except:
        pass

    return templates.TemplateResponse("partials/credentials_content.html", {
        "request": request,
        "cred_groups": cred_groups,
        "logins_count": total_logins,
        "passwords_count": total_passwords,
        "groups_count": len(cred_groups)
    })

@app.post("/create-cred-group")
async def create_cred_group(
    name: str = Form(...),
    geo: str = Form(...),
    priority: int = Form(...)
):
    if not is_valid_geo(geo):
        return HTMLResponse("❌ Неверная GEO", status_code=400)

    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            INSERT INTO cred_groups (name, geo, priority)
            VALUES (%s, %s, %s)
            RETURNING id, name, geo, priority, created_at;
        """, (name, geo, priority))

        row = cur.fetchone()
        db.commit()

        return HTMLResponse(f"""
        <tr hx-swap-oob="beforeend:#cred-groups-list">
            <td style="font-family: monospace; font-size:0.75em;">{str(row['id'])[:8]}...</td>
            <td><strong>{row['name']}</strong></td>
            <td>{row['geo']}</td>
            <td>{row['priority']}</td>
            <td>
                <form hx-delete="/delete-cred-group/{row['id']}"
                      hx-confirm="Удалить группу?"
                      hx-target="#main-content"
                      hx-swap="outerHTML">
                    <button class="btn" style="background:#d32f2f;">🗑️</button>
                </form>
            </td>
        </tr>
        """)

    except Exception as e:
        db.rollback()
        print("CREATE GROUP ERROR:", e)
        return HTMLResponse(f"❌ Ошибка БД: {e}", status_code=500)
    finally:
        db_pool.putconn(db)

@app.post("/upload-creds-simple")
async def upload_creds_simple(
    file: UploadFile = File(...),
    cred_type: str = Form(...),
    group_id: str = Form(...)  # ← ОБЯЗАТЕЛЬНО
):
    if cred_type not in ('login', 'password'):
        return HTMLResponse('<div style="color:#d32f2f;">❌ cred_type must be login or password</div>')
    contents = await file.read()
    lines = [x.strip() for x in contents.decode('utf-8', errors='ignore').split('\n') if x.strip()]
    if not lines:
        return HTMLResponse('<div style="color:#d32f2f;">❌ Файл пуст</div>')
    db = get_db()
    cur = get_cursor(db)
    try:
        # Проверяем, что группа существует
        cur.execute("SELECT id FROM cred_groups WHERE id = %s", (group_id,))
        if cur.rowcount == 0:
            return HTMLResponse('<div style="color:#d32f2f;">❌ Группа не найдена</div>')
        table = "logins" if cred_type == "login" else "passwords"
        link_table = "cred_group_logins" if cred_type == "login" else "cred_group_passwords"
        col_name = "login_id" if cred_type == "login" else "password_id"
        inserted = 0
        for val in lines:
            cur.execute(f"""
                INSERT INTO {table} (id, value, created_at)
                VALUES (gen_random_uuid(), %s, NOW())
                ON CONFLICT (value) DO NOTHING
                RETURNING id;
            """, (val,))
            row = cur.fetchone()
            if not row:
                cur.execute(f"SELECT id FROM {table} WHERE value = %s", (val,))
                row = cur.fetchone()
            if row:
                cur.execute(f"""
                    INSERT INTO {link_table} (group_id, {col_name})
                    VALUES (%s, %s)
                    ON CONFLICT DO NOTHING;
                """, (group_id, row['id']))
                inserted += 1
        db.commit()
        return HTMLResponse(f'<div style="color:#a5d6a7;">✅ Загружено {inserted} {cred_type}ов в группу</div>')
    except Exception as e:
        db.rollback()
        print("DB ERROR:", e)
        return HTMLResponse(f'<div style="color:#d32f2f;">❌ Ошибка: {str(e)[:200]}</div>')
    finally:
        db_pool.putconn(db)

@app.post("/upload-creds-pairs")
async def upload_creds_pairs(file: UploadFile = File(...)):
    contents = await file.read()
    lines = contents.decode('utf-8', errors='ignore').split('\n')
    pairs = []
    for line in lines:
        line = line.strip()
        if not line or ':' not in line:
            continue
        login, password = line.split(':', 1)
        login = login.strip()
        password = password.strip()
        if login and password:
            pairs.append((login, password))
    if not pairs:
        return HTMLResponse('<div style="color:#d32f2f;">❌ Нет валидных пар login:password</div>')
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS cred_pairs (
                id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
                login_value TEXT NOT NULL,
                password_value TEXT NOT NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        """)
        inserted = 0
        for login, password in pairs:
            cur.execute("""
                INSERT INTO cred_pairs (login_value, password_value)
                VALUES (%s, %s)
                ON CONFLICT (login_value, password_value) DO NOTHING
            """, (login, password))
            if cur.rowcount > 0:
                inserted += 1
        db.commit()
        return HTMLResponse(f"""
        <div style="color:#a5d6a7;">✅ Загружено {inserted} уникальных пар</div>
        """)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"DB error: {e}")
    finally:
        db_pool.putconn(db)

@app.delete("/delete-cred-group/{group_id}")
async def delete_cred_group(group_id: str):
    import re
    if not re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', group_id):
        raise HTTPException(status_code=400, detail="Invalid group ID format")
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("DELETE FROM cred_group_logins WHERE group_id = %s", (group_id,))
        cur.execute("DELETE FROM cred_group_passwords WHERE group_id = %s", (group_id,))
        cur.execute("DELETE FROM cred_group_pairs WHERE group_id = %s", (group_id,))
        cur.execute("DELETE FROM cred_groups WHERE id = %s", (group_id,))
        db.commit()
        return RedirectResponse(url="/credentials-content", status_code=303)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db_pool.putconn(db)

@app.post("/delete-all-creds")
async def delete_all_creds():
    db = get_db()
    cur = get_cursor(db)
    try:
        cur.execute("DELETE FROM cred_group_pairs;")
        cur.execute("DELETE FROM cred_group_logins;")
        cur.execute("DELETE FROM cred_group_passwords;")
        cur.execute("DELETE FROM cred_groups;")
        cur.execute("DELETE FROM logins;")
        cur.execute("DELETE FROM passwords;")
        cur.execute("DELETE FROM cred_pairs;")
        db.commit()
        return RedirectResponse(url="/credentials-content", status_code=303)
    finally:
        db_pool.putconn(db)
