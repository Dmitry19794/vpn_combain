#!/usr/bin/env python3
# vpn/celery_app/tasks.py - ПОЛНОСТЬЮ ИСПРАВЛЕННАЯ ВЕРСИЯ

import os
import sys
from celery.schedules import crontab

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import threading
import signal
import atexit
import subprocess
import psycopg2
import time
import traceback as tb
import tempfile
import ipaddress
from psycopg2.extras import RealDictCursor, execute_values
from celery import Celery, Task
from datetime import datetime
from typing import Dict, List, Optional

# ИСПРАВЛЕНИЕ: НЕ используем connection pool в Celery workers
# Каждый worker создает свое соединение
PG_PORT = os.getenv("PGPORT", "5434")
DB_DSN = f"postgresql://brute:securepass123@localhost:{PG_PORT}/brute_system"

VPN_CHECKER_PROCESSES = {}
VPN_CHECKER_LOCK = threading.Lock()

def get_db_connection():
    """Создает НОВОЕ соединение к БД (без пула)"""
    try:
        conn = psycopg2.connect(
            DB_DSN,
            connect_timeout=10,
            options='-c statement_timeout=30000'
        )
        conn.autocommit = False
        return conn
    except Exception as e:
        print(f"❌ DB connection error: {e}")
        raise

# ============================================
# Конфигурация Celery
# ============================================
app = Celery(
    'tasks',
    broker='redis://localhost:6379/0',
    backend='redis://localhost:6379/1'
)

app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
    worker_prefetch_multiplier=1,  # ВАЖНО: не берем задачи заранее
    task_acks_late=True,
)

CHUNK_SIZE = 1000
CIDR_SPLIT_SIZE = 24

# ============================================
# ЛОГ ОШИБОК
# ============================================
def save_worker_error(path: str, error: str, tb_text: Optional[str] = None):
    """Сохраняет ошибку в таблицу app_errors"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO app_errors (method, path, status_code, error, traceback)
            VALUES (%s, %s, %s, %s, %s)
        """, ("CELERY", path, 500, (error or '')[:8000], (tb_text or tb.format_exc())[:16000]))
        conn.commit()
    except Exception as e:
        print(f"❌ FAILED TO SAVE CELERY ERROR: {e}")
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

# ============================================
# Базовый класс для задач (on_failure)
# ============================================
class MasscanTask(Task):
    def on_failure(self, exc, task_id, args, kwargs, einfo):
        job_id = kwargs.get('job_id') or (args[0] if args else None)
        print(f"❌ Task {task_id} failed: {exc}")
        
        if not job_id:
            save_worker_error(path=f"task.on_failure:{task_id}", error=str(exc), tb_text=tb.format_exc())
            return

        conn = None
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE scan_jobs
                SET status = 'failed',
                    finished_at = NOW(),
                    process_pid = NULL,
                    control_action = NULL
                WHERE id = %s
            """, (job_id,))
            conn.commit()
        except Exception as e:
            print(f"Failed to update job status in on_failure: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass

        save_worker_error(path=f"task.on_failure:{task_id}", error=str(exc), tb_text=tb.format_exc())

# ============================================
# РАБОТА С ПРОКСИ
# ============================================
def get_random_proxy(geo: str = None):
    """Получает случайный живой прокси из БД"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        if geo:
            cur.execute("""
                SELECT host, port, anonymity, geo
                FROM proxies
                WHERE is_alive = TRUE AND geo = %s
                ORDER BY RANDOM()
                LIMIT 1
            """, (geo,))
        else:
            cur.execute("""
                SELECT host, port, anonymity, geo
                FROM proxies
                WHERE is_alive = TRUE
                ORDER BY RANDOM()
                LIMIT 1
            """)
        
        row = cur.fetchone()
        if row:
            return {
                "host": row[0],
                "port": row[1],
                "anonymity": row[2] if len(row) > 2 else "unknown",
                "geo": row[3] if len(row) > 3 else "unknown"
            }
        return None
        
    except Exception as e:
        print(f"❌ get_random_proxy error: {e}")
        return None
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

def create_proxychains_config(proxy_host: str, proxy_port: int, proxy_type: str = "http") -> str:
    """Создает временный конфиг для proxychains4"""
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            config_path = f.name
            f.write(f"""# Proxychains config for nmap
strict_chain
proxy_dns
tcp_read_time_out 30000
tcp_connect_time_out 15000

[ProxyList]
{proxy_type} {proxy_host} {proxy_port}
""")
        
        print(f"📝 Created proxychains config: {proxy_type}://{proxy_host}:{proxy_port}")
        return config_path
        
    except Exception as e:
        print(f"❌ Failed to create proxychains config: {e}")
        return None

def run_nmap_via_proxy(target: str, port: int, proxy_info: dict, 
                       output_file: str, timeout: int = 180) -> bool:
    """Запускает nmap через proxychains"""
    config_path = None
    
    try:
        proxy_host = proxy_info["host"]
        proxy_port = proxy_info["port"]
        proxy_type = "http"
        
        config_path = create_proxychains_config(proxy_host, proxy_port, proxy_type)
        if not config_path:
            return False
        
        cmd = [
            'proxychains4', '-f', config_path, '-q',
            'nmap',
            '-p', str(port),
            '-sT', '-Pn', '--open',
            '-T3',
            '--max-retries', '2',
            '--host-timeout', '60s',
            '--max-rtt-timeout', '2000ms',
            '--initial-rtt-timeout', '500ms',
            '-oG', output_file,
            target
        ]
        
        print(f"🔍 Running nmap via proxy {proxy_host}:{proxy_port} for {target}:{port}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            returncode = process.returncode
            
            if returncode == 0:
                print(f"✅ Nmap completed for {target}")
                return True
            else:
                print(f"⚠️ Nmap returned code {returncode} for {target}")
                return False
                
        except subprocess.TimeoutExpired:
            print(f"⏰ Nmap timeout for {target}")
            try:
                process.kill()
                process.wait(timeout=5)
            except:
                pass
            return False
            
    except Exception as e:
        print(f"❌ run_nmap_via_proxy error: {e}")
        return False
        
    finally:
        if config_path and os.path.exists(config_path):
            try:
                os.remove(config_path)
            except:
                pass

def split_cidr_into_blocks(cidr: str, block_size: int = 24) -> List[str]:
    """Разбивает CIDR на блоки"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        if network.prefixlen >= block_size:
            return [str(network)]
        
        subnets = list(network.subnets(new_prefix=block_size))
        
        if len(subnets) > 1000:
            print(f"⚠️ Too many subnets ({len(subnets)}), taking first 1000")
            subnets = subnets[:1000]
        
        return [str(subnet) for subnet in subnets]
        
    except Exception as e:
        print(f"❌ split_cidr error: {e}")
        return [cidr]

def parse_nmap_results(output_file: str, job_id: str, port: int, geo: str, conn) -> int:
    """Парсит greppable output nmap"""
    total = 0
    if not os.path.exists(output_file):
        return 0

    try:
        with open(output_file, 'r') as f:
            ips = []
            for line in f:
                if 'Host:' in line and 'Ports:' in line:
                    try:
                        parts = line.split()
                        host_idx = parts.index('Host:')
                        ip = parts[host_idx + 1]
                        
                        if '/open/' in line:
                            ips.append(ip)
                            
                    except Exception:
                        continue
                    
                    if len(ips) >= CHUNK_SIZE:
                        try:
                            count = insert_addresses_batch(conn, ips, port, geo, job_id)
                            conn.commit()
                            total += count
                        except Exception as e:
                            try:
                                conn.rollback()
                            except:
                                pass
                            print(f"❌ Batch insert error: {e}")
                        ips = []
            
            if ips:
                try:
                    count = insert_addresses_batch(conn, ips, port, geo, job_id)
                    conn.commit()
                    total += count
                except Exception as e:
                    try:
                        conn.rollback()
                    except:
                        pass
                    print(f"❌ Final insert error: {e}")
                    
    except Exception as e:
        print(f"❌ parse_nmap_results error: {e}")
    
    return total

def insert_addresses_batch(conn, ips: List[str], port: int, geo: str, job_id: str) -> int:
    """Вставка адресов - БЕЗ FOREIGN KEY"""
    if not ips:
        return 0

    cur = conn.cursor()
    rows = [(ip, port, geo) for ip in ips]  # УБРАЛИ job_id!

    # УБИРАЕМ job_id из INSERT!
    sql = """
        INSERT INTO scanned_addresses (id, ip, port, geo, is_checked, created_at, updated_at)
        SELECT gen_random_uuid(), data.ip::inet, data.port, data.geo, FALSE, NOW(), NOW()
        FROM (VALUES %s) AS data(ip, port, geo)
        ON CONFLICT (ip, port) DO NOTHING
    """

    try:
        execute_values(cur, sql, rows)
        return len(rows)
    except Exception as e:
        print(f"❌ insert_addresses_batch error: {e}")
        return 0

# ============================================
# ОСНОВНАЯ ЗАДАЧА СКАНИРОВАНИЯ
# ============================================
def test_proxy_for_nmap(proxy_host: str, proxy_port: int) -> bool:
    """Тестирует прокси для nmap"""
    try:
        # Создаем тестовый конфиг
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            config_path = f.name
            f.write(f"""strict_chain
                    tcp_connect_time_out 5000
                    [ProxyList]
                    http {proxy_host} {proxy_port}
                    """)
        
        # Тестируем nmap через прокси
        result = subprocess.run(
            ['proxychains4', '-f', config_path, '-q', 
             'nmap', '-p', '443', '-sT', '-Pn', '8.8.8.8'],
            timeout=10,
            capture_output=True,
            text=True
        )
        
        os.remove(config_path)
        
        # Если нашел хоть что-то - прокси работает
        success = 'open' in result.stdout.lower() or result.returncode == 0
        
        if success:
            print(f"✅ Proxy {proxy_host}:{proxy_port} works for nmap")
        else:
            print(f"❌ Proxy {proxy_host}:{proxy_port} FAILED for nmap")
        
        return success
        
    except Exception as e:
        print(f"❌ Proxy test error: {e}")
        return False

def start_vpn_checker_for_geo(geo: str) -> bool:
    """
    Запускает VPN checker для указанной GEO если еще не запущен
    Возвращает True если запущен успешно
    """
    global VPN_CHECKER_PROCESSES
    
    with VPN_CHECKER_LOCK:
        # Проверяем что процесс уже не запущен
        if geo in VPN_CHECKER_PROCESSES:
            proc = VPN_CHECKER_PROCESSES[geo]
            if proc.poll() is None:  # Процесс еще жив
                print(f"✅ VPN Checker for {geo} already running (PID: {proc.pid})")
                return True
            else:
                # Процесс умер - удаляем из словаря
                del VPN_CHECKER_PROCESSES[geo]
        
        # Запускаем новый процесс
        try:
            checker_bin = "/opt/vpn/checker/checker"
            
            if not os.path.exists(checker_bin):
                print(f"❌ Checker binary not found: {checker_bin}")
                return False
            
            # Запускаем checker с параметрами
            proc = subprocess.Popen(
                [checker_bin, f"--geo={geo}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )
            
            VPN_CHECKER_PROCESSES[geo] = proc
            
            # Запускаем поток для чтения логов
            threading.Thread(
                target=_read_checker_logs,
                args=(proc, geo),
                daemon=True
            ).start()
            
            print(f"🚀 Started VPN Checker for {geo} (PID: {proc.pid})")
            return True
            
        except Exception as e:
            print(f"❌ Failed to start VPN Checker for {geo}: {e}")
            return False

def _read_checker_logs(proc, geo):
    """Читает логи VPN checker и выводит в консоль"""
    try:
        for line in iter(proc.stdout.readline, ''):
            if line:
                print(f"[CHECKER-{geo}] {line.rstrip()}")
    except Exception as e:
        print(f"❌ Error reading checker logs for {geo}: {e}")
    finally:
        proc.stdout.close()

def stop_vpn_checker_for_geo(geo: str) -> bool:
    """Останавливает VPN checker для указанной GEO"""
    global VPN_CHECKER_PROCESSES
    
    with VPN_CHECKER_LOCK:
        if geo not in VPN_CHECKER_PROCESSES:
            print(f"⚠️ VPN Checker for {geo} is not running")
            return False
        
        proc = VPN_CHECKER_PROCESSES[geo]
        
        try:
            # Отправляем SIGTERM
            proc.terminate()
            
            # Ждем 5 секунд
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                # Если не завершился - убиваем
                proc.kill()
                proc.wait()
            
            del VPN_CHECKER_PROCESSES[geo]
            print(f"🛑 Stopped VPN Checker for {geo}")
            return True
            
        except Exception as e:
            print(f"❌ Error stopping VPN Checker for {geo}: {e}")
            return False

def get_vpn_checker_status() -> dict:
    """Возвращает статус всех VPN checker процессов"""
    global VPN_CHECKER_PROCESSES
    
    status = {}
    
    with VPN_CHECKER_LOCK:
        for geo, proc in list(VPN_CHECKER_PROCESSES.items()):
            if proc.poll() is None:
                # Процесс жив
                status[geo] = {
                    "running": True,
                    "pid": proc.pid
                }
            else:
                # Процесс умер
                status[geo] = {
                    "running": False,
                    "pid": None
                }
                del VPN_CHECKER_PROCESSES[geo]
    
    return status

# ============================================
# МОДИФИКАЦИЯ parse_nmap_results
# ============================================
def parse_nmap_results(output_file: str, job_id: str, port: int, geo: str, conn) -> int:
    """
    Парсит greppable output nmap
    НОВОЕ: автоматически запускает VPN checker если найдены хосты
    """
    total = 0
    if not os.path.exists(output_file):
        return 0

    try:
        with open(output_file, 'r') as f:
            ips = []
            for line in f:
                if 'Host:' in line and 'Ports:' in line:
                    try:
                        parts = line.split()
                        host_idx = parts.index('Host:')
                        ip = parts[host_idx + 1]
                        
                        if '/open/' in line:
                            ips.append(ip)
                            
                    except Exception:
                        continue
                    
                    if len(ips) >= CHUNK_SIZE:
                        try:
                            count = insert_addresses_batch(conn, ips, port, geo, job_id)
                            conn.commit()
                            total += count
                        except Exception as e:
                            try:
                                conn.rollback()
                            except:
                                pass
                            print(f"❌ Batch insert error: {e}")
                        ips = []
            
            if ips:
                try:
                    count = insert_addresses_batch(conn, ips, port, geo, job_id)
                    conn.commit()
                    total += count
                except Exception as e:
                    try:
                        conn.rollback()
                    except:
                        pass
                    print(f"❌ Final insert error: {e}")
        
        # ✅ НОВОЕ: Если найдены хосты - запускаем VPN checker
        if total > 0:
            print(f"🎯 Found {total} open ports for {geo}, starting VPN checker...")
            start_vpn_checker_for_geo(geo)
                    
    except Exception as e:
        print(f"❌ parse_nmap_results error: {e}")
    
    return total

# ============================================
# API ENDPOINTS для управления VPN checker
# ============================================
@app.task(name='tasks.manage_vpn_checker')
def manage_vpn_checker(geo: str, action: str):
    """
    Управляет VPN checker процессами
    action: 'start', 'stop', 'status'
    """
    if action == 'start':
        return {'status': 'success' if start_vpn_checker_for_geo(geo) else 'failed'}
    
    elif action == 'stop':
        return {'status': 'success' if stop_vpn_checker_for_geo(geo) else 'failed'}
    
    elif action == 'status':
        return get_vpn_checker_status()
    
    else:
        return {'error': f'Invalid action: {action}'}

# ============================================
# Beat schedule для автоматической проверки
# ============================================
app.conf.beat_schedule.update({
    "check-vpn-checkers": {
        "task": "tasks.check_vpn_checker_health",
        "schedule": 60.0,  # Каждую минуту
    },
})

@app.task(name='tasks.check_vpn_checker_health')
def check_vpn_checker_health():
    """
    Проверяет что VPN checker процессы живы
    Перезапускает если есть непроверенные адреса но checker не работает
    """
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Получаем список GEO с непроверенными адресами
        cur.execute("""
            SELECT geo, COUNT(*) as cnt
            FROM scanned_addresses
            WHERE is_checked = FALSE
            GROUP BY geo
            HAVING COUNT(*) > 0
        """)
        
        rows = cur.fetchall()
        
        for row in rows:
            geo = row[0]
            count = row[1]
            
            # Проверяем что checker запущен
            status = get_vpn_checker_status()
            
            if geo not in status or not status[geo].get('running'):
                print(f"⚠️ {geo} has {count} unchecked addresses but checker is not running")
                print(f"🚀 Auto-starting VPN checker for {geo}")
                start_vpn_checker_for_geo(geo)
        
        conn.close()
        
    except Exception as e:
        print(f"❌ check_vpn_checker_health error: {e}")
        if conn:
            try:
                conn.close()
            except:
                pass

# ============================================
# Graceful shutdown при остановке Celery
# ============================================
def shutdown_all_checkers():
    """Останавливает все VPN checker процессы"""
    global VPN_CHECKER_PROCESSES
    
    print("🛑 Shutting down all VPN checkers...")
    
    with VPN_CHECKER_LOCK:
        for geo in list(VPN_CHECKER_PROCESSES.keys()):
            stop_vpn_checker_for_geo(geo)
    
    print("✅ All VPN checkers stopped")

# Регистрируем обработчик сигналов
import atexit
atexit.register(shutdown_all_checkers)

@app.task(bind=True, name='tasks.run_masscan', base=MasscanTask)
def run_masscan(self, job_id: str, cidr: str, port: int, geo: str):
    """Распределенное сканирование через прокси (с fallback на прямой nmap)"""
    print(f"🔍 Starting distributed scan: {cidr}:{port} (Job={job_id}, GEO={geo})")
    
    start_time = time.time()
    total_results = 0
    conn = None
    
    try:
        # Инициализация: помечаем задачу как running
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE scan_jobs
            SET status = 'running',
                started_at = NOW(),
                assigned_to = %s,
                progress_percent = 0,
                control_action = NULL
            WHERE id = %s
        """, (self.request.id, job_id))
        conn.commit()
        conn.close()
        conn = None

        # Разбиваем CIDR на блоки
        blocks = split_cidr_into_blocks(cidr, CIDR_SPLIT_SIZE)
        total_blocks = len(blocks)
        print(f"📊 Split {cidr} into {total_blocks} blocks (/{CIDR_SPLIT_SIZE})")
        
        if total_blocks > 100:
            print(f"⚠️ Too many blocks ({total_blocks}), limiting to 100")
            blocks = blocks[:100]
            total_blocks = 100

        # Сканируем каждый блок
        for i, block in enumerate(blocks):
            # Проверяем control actions
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("SELECT control_action FROM scan_jobs WHERE id = %s", (job_id,))
                row = cur.fetchone()
                ctrl = row[0] if row else None
                conn.close()
                conn = None
            except Exception as e:
                print(f"⚠️ Error checking control: {e}")
                ctrl = None
                if conn:
                    try:
                        conn.close()
                    except:
                        pass
                    conn = None
            
            if ctrl == 'stop':
                print(f"🛑 Stopping job {job_id}")
                break

            # === ПОЛУЧЕНИЕ И ТЕСТИРОВАНИЕ ПРОКСИ ===
            proxy_info = None
            for attempt in range(5):  # Пробуем до 5 прокси
                candidate = get_random_proxy(geo)
                if not candidate:
                    print(f"⚠️ No more proxies for GEO={geo} (attempt {attempt+1}/5)")
                    break

                host, port_candidate = candidate["host"], candidate["port"]
                print(f"🧪 Testing proxy {host}:{port_candidate} (attempt {attempt+1}/5)...")
                
                if test_proxy_for_nmap(host, port_candidate):
                    proxy_info = candidate
                    print(f"✅ Selected working proxy: {host}:{port_candidate}")
                    break
                else:
                    # Помечаем как мёртвый
                    try:
                        db_conn = get_db_connection()
                        db_cur = db_conn.cursor()
                        db_cur.execute("""
                            UPDATE proxies 
                            SET is_alive = FALSE, updated_at = NOW()
                            WHERE host = %s AND port = %s
                        """, (host, port_candidate))
                        db_conn.commit()
                        db_conn.close()
                        print(f"💀 Marked proxy {host}:{port_candidate} as dead")
                    except Exception as e:
                        print(f"⚠️ Failed to mark proxy dead: {e}")

            # === СКАНИРОВАНИЕ: прокси или прямое ===
            output_file = f"/tmp/nmap_{job_id}_{i}.txt"
            success = False

            if proxy_info:
                # ✅ Используем прокси
                print(f"🔍 Scanning {block}:{port} via proxy {proxy_info['host']}:{proxy_info['port']}")
                try:
                    success = run_nmap_via_proxy(
                        target=block,
                        port=port,
                        proxy_info=proxy_info,
                        output_file=output_file,
                        timeout=180
                    )
                except Exception as e:
                    print(f"❌ Nmap via proxy error for {block}: {e}")
                    success = False
            else:
                # 🚫 Нет рабочих прокси — сканируем напрямую
                print(f"🌐 No working proxy — falling back to DIRECT nmap scan for {block}:{port}")
                try:
                    cmd = [
                        'nmap',
                        '-p', str(port),
                        '-sT', '-Pn', '--open',
                        '-T3',
                        '--max-retries', '2',
                        '--host-timeout', '60s',
                        '--max-rtt-timeout', '2000ms',
                        '--initial-rtt-timeout', '500ms',
                        '-oG', output_file,
                        block
                    ]
                    print(f"▶️ Running: {' '.join(cmd)}")
                    
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True
                    )
                    stdout, stderr = process.communicate(timeout=180)
                    returncode = process.returncode
                    success = (returncode == 0)
                    
                    if success:
                        print(f"✅ Direct nmap completed for {block}")
                    else:
                        print(f"⚠️ Direct nmap failed (code {returncode}) for {block}")
                        if stderr.strip():
                            print(f"   STDERR: {stderr[:200]}...")
                
                except subprocess.TimeoutExpired:
                    print(f"⏰ Direct nmap timeout for {block}")
                    try:
                        process.kill()
                        process.wait(timeout=5)
                    except:
                        pass
                    success = False
                except Exception as e:
                    print(f"❌ Direct nmap error: {e}")
                    success = False

            # === ОБРАБОТКА РЕЗУЛЬТАТОВ ===
            if success and os.path.exists(output_file):
                try:
                    conn = get_db_connection()
                    count = parse_nmap_results(output_file, job_id, port, geo, conn)
                    conn.commit()
                    total_results += count
                    print(f"✅ Block {i+1}/{total_blocks}: found {count} hosts")
                except Exception as e:
                    print(f"❌ Parse error for block {i}: {e}")
                    if conn:
                        try:
                            conn.rollback()
                        except:
                            pass
                finally:
                    if conn:
                        try:
                            conn.close()
                        except:
                            pass
                    conn = None
            else:
                print(f"⚠️ Block {i+1}/{total_blocks}: scan failed or no output")

            # Удаляем временный файл
            try:
                if os.path.exists(output_file):
                    os.remove(output_file)
            except Exception as e:
                print(f"⚠️ Failed to remove {output_file}: {e}")

            # Обновляем прогресс
            progress = ((i + 1) / total_blocks) * 100
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("""
                    UPDATE scan_jobs
                    SET progress_percent = %s,
                        result_count = %s
                    WHERE id = %s
                """, (progress, total_results, job_id))
                conn.commit()
                conn.close()
                conn = None
            except Exception as e:
                print(f"⚠️ Progress update error: {e}")
                if conn:
                    try:
                        conn.close()
                    except:
                        pass
                    conn = None

            # Обновляем Celery state
            try:
                elapsed = time.time() - start_time
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'job_id': job_id,
                        'cidr': cidr,
                        'progress': progress,
                        'blocks_done': i + 1,
                        'blocks_total': total_blocks,
                        'results': total_results,
                        'elapsed': int(elapsed)
                    }
                )
            except:
                pass

        # === ФИНАЛЬНОЕ ОБНОВЛЕНИЕ ===
        elapsed = time.time() - start_time
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE scan_jobs
                SET status = 'completed',
                    finished_at = NOW(),
                    result_count = %s,
                    progress_percent = 100,
                    process_pid = NULL,
                    control_action = NULL
                WHERE id = %s
            """, (total_results, job_id))
            conn.commit()
        except Exception as e:
            print(f"❌ Final update error: {e}")
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass

        print(f"✅ Job {job_id} completed: {total_results} hosts in {int(elapsed)}s")
        return {
            'status': 'completed',
            'job_id': job_id,
            'cidr': cidr,
            'port': port,
            'geo': geo,
            'result_count': total_results,
            'elapsed_seconds': int(elapsed),
            'blocks_scanned': total_blocks
        }

    except Exception as e:
        print(f"❌ Fatal error in run_masscan: {e}")
        import traceback
        traceback.print_exc()

        # Помечаем как failed
        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE scan_jobs
                SET status = 'failed',
                    finished_at = NOW(),
                    result_count = %s,
                    process_pid = NULL,
                    control_action = NULL
                WHERE id = %s
            """, (total_results, job_id))
            conn.commit()
        except:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass

        raise

# ============================================
# Управление задачами
# ============================================
@app.task(name='tasks.control_job')
def control_job(job_id: str, action: str):
    if action not in ['pause', 'resume', 'stop']:
        return {'error': f'Invalid action: {action}'}

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            UPDATE scan_jobs
            SET control_action = %s,
                control_updated_at = NOW()
            WHERE id = %s
            RETURNING status
        """, (action, job_id))
        row = cur.fetchone()
        if not row:
            try:
                conn.rollback()
            except:
                pass
            return {'error': 'Job not found'}
        conn.commit()
        print(f"🎛️ Job {job_id}: action={action}")
        result = {
            'status': 'success',
            'job_id': job_id,
            'action': action,
            'current_status': row.get('status') if isinstance(row, dict) else row[0]
        }
        return result
    except Exception as e:
        print(f"❌ Error controlling job: {e}")
        try:
            if conn:
                conn.rollback()
        except:
            pass
        save_worker_error(path=f"control_job:{job_id}", error=str(e), tb_text=tb.format_exc())
        return {'error': str(e)}
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

# ============================================
# АВТОЗАПУСК PENDING - ИСПРАВЛЕНО
# ============================================
@app.task(name='tasks.process_pending_scans')
def process_pending_scans(geo: str = 'US', limit: int = 10):
    """Берём pending задачи и запускаем"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT j.id, s.cidr, p.port, s.geo
            FROM scan_jobs j
            JOIN scan_subnets s ON j.subnet_id = s.id
            JOIN scan_ports p ON j.port_id = p.id
            WHERE j.status = 'pending' AND s.geo = %s
            ORDER BY j.created_at ASC
            LIMIT %s
            FOR UPDATE SKIP LOCKED
        """, (geo, limit))
        
        # ИСПРАВЛЕНИЕ: проверяем rowcount ДО fetchall
        if cur.rowcount == 0:
            conn.commit()
            return None
            
        jobs = cur.fetchall()
        
        if not jobs:
            conn.commit()
            return None

        launched = []
        for job in jobs:
            jid = str(job[0])
            cidr = job[1]
            p = job[2]
            g = job[3]
            cur.execute("UPDATE scan_jobs SET status='queued' WHERE id=%s", (jid,))
            launched.append(jid)
            run_masscan.delay(jid, cidr, p, g)

        conn.commit()
        return {'status': 'launched', 'count': len(launched)}
        
    except Exception as e:
        print(f"❌ process_pending_scans error: {e}")
        try:
            if conn:
                conn.rollback()
        except:
            pass
        return None
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

# ============================================
# Очистка старых данных
# ============================================
@app.task(name='tasks.cleanup_old_data')
def cleanup_old_data(days: int = 7):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            DELETE FROM scan_jobs
            WHERE status IN ('completed', 'stopped', 'failed')
            AND finished_at < NOW() - INTERVAL '%s days'
        """, (days,))
        deleted_jobs = cur.rowcount

        cur.execute("""
            DELETE FROM scanned_addresses
            WHERE is_checked = TRUE 
            AND updated_at < NOW() - INTERVAL '%s days'
        """, (days,))
        deleted_addrs = cur.rowcount

        conn.commit()
        print(f"🧹 Cleaned: {deleted_jobs} jobs, {deleted_addrs} addresses")
        return {'status': 'success', 'deleted_jobs': deleted_jobs, 'deleted_addresses': deleted_addrs}
    except Exception as e:
        print(f"❌ Cleanup error: {e}")
        try:
            if conn:
                conn.rollback()
        except:
            pass
        save_worker_error(path=f"cleanup_old_data:{days}", error=str(e), tb_text=tb.format_exc())
        raise
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass

# ============================================
# Beat schedule
# ============================================
app.conf.beat_schedule = {
    "auto-start-pending-us": {
        "task": "tasks.process_pending_scans",
        "schedule": 15.0,
        "args": ("US", 10),
    },
}
