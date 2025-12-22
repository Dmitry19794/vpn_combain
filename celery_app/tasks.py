#!/usr/bin/env python3
# /opt/vpn/celery_app/tasks.py - ПОЛНЫЙ РАБОЧИЙ КОД

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

# ============================================
# DATABASE
# ============================================

PG_PORT = os.getenv("PGPORT", "5434")
DB_DSN = f"postgresql://brute:securepass123@localhost:{PG_PORT}/brute_system"

def get_db_connection():
    """Создает НОВОЕ соединение к БД"""
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
# CELERY APP
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
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

CHUNK_SIZE = 1000
CIDR_SPLIT_SIZE = 24

VPN_CHECKER_PROCESSES = {}
VPN_CHECKER_LOCK = threading.Lock()

# ============================================
# UTILITIES
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


def parse_masscan_output(output_file: str, job_id: str, port: int, geo: str, conn) -> int:
    """Парсит greppable output masscan"""
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
                            count = insert_addresses_batch(conn, ips, port, geo)
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
                    count = insert_addresses_batch(conn, ips, port, geo)
                    conn.commit()
                    total += count
                except Exception as e:
                    try:
                        conn.rollback()
                    except:
                        pass
                    print(f"❌ Final insert error: {e}")
                    
    except Exception as e:
        print(f"❌ parse_masscan_output error: {e}")
    
    return total


def insert_addresses_batch(conn, ips: List[str], port: int, geo: str) -> int:
    """Вставка адресов в БД"""
    if not ips:
        return 0

    cur = conn.cursor()
    rows = [(ip, port, geo) for ip in ips]

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
# VPN CHECKER MANAGEMENT
# ============================================

def start_vpn_checker_for_geo(geo: str) -> bool:
    """Запускает VPN checker для указанной GEO"""
    global VPN_CHECKER_PROCESSES
    
    with VPN_CHECKER_LOCK:
        if geo in VPN_CHECKER_PROCESSES:
            proc = VPN_CHECKER_PROCESSES[geo]
            if proc.poll() is None:
                print(f"✅ VPN Checker for {geo} already running (PID: {proc.pid})")
                return True
            else:
                del VPN_CHECKER_PROCESSES[geo]
        
        try:
            checker_bin = "/opt/vpn/checker/checker"
            
            if not os.path.exists(checker_bin):
                print(f"❌ Checker binary not found: {checker_bin}")
                return False
            
            proc = subprocess.Popen(
                [checker_bin, f"--geo={geo}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )
            
            VPN_CHECKER_PROCESSES[geo] = proc
            
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
    """Читает логи VPN checker"""
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
            proc.terminate()
            
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
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
                status[geo] = {
                    "running": True,
                    "pid": proc.pid
                }
            else:
                status[geo] = {
                    "running": False,
                    "pid": None
                }
                del VPN_CHECKER_PROCESSES[geo]
    
    return status

# ============================================
# BASE TASK CLASS
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
# MAIN SCAN TASK
# ============================================

@app.task(bind=True, name='tasks.run_masscan', base=MasscanTask)
def run_masscan(self, job_id: str, cidr: str, port: int, geo: str):
    """Сканирование через masscan"""
    print(f"🔍 Starting scan: {cidr}:{port} (Job={job_id}, GEO={geo})")
    
    start_time = time.time()
    total_results = 0
    conn = None
    
    try:
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

        blocks = split_cidr_into_blocks(cidr, CIDR_SPLIT_SIZE)
        total_blocks = len(blocks)
        print(f"📊 Split {cidr} into {total_blocks} blocks")
        
        if total_blocks > 100:
            print(f"⚠️ Too many blocks ({total_blocks}), limiting to 100")
            blocks = blocks[:100]
            total_blocks = 100

        for i, block in enumerate(blocks):
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

            output_file = f"/tmp/masscan_{job_id}_{i}.txt"
            
            cmd = [
                'masscan',
                block,
                '-p', str(port),
                '--rate', '10000',
                '--wait', '0',
                '--open',
                '-oG', output_file
            ]
            
            print(f"▶️ Scanning block {i+1}/{total_blocks}: {block}")
            
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=180
                )
                
                if result.returncode == 0:
                    conn = get_db_connection()
                    count = parse_masscan_output(output_file, job_id, port, geo, conn)
                    conn.commit()
                    total_results += count
                    print(f"✅ Block {i+1}/{total_blocks}: found {count} hosts")
                    conn.close()
                    conn = None
                else:
                    print(f"⚠️ Masscan failed for block {i+1}: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                print(f"⏰ Masscan timeout for block {i+1}")
            except Exception as e:
                print(f"❌ Error scanning block {i+1}: {e}")
            finally:
                if os.path.exists(output_file):
                    try:
                        os.remove(output_file)
                    except:
                        pass

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

        elapsed = time.time() - start_time
        
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
        conn.close()

        if total_results > 0:
            print(f"🎯 Found {total_results} open ports, starting VPN checker...")
            start_vpn_checker_for_geo(geo)

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
            conn.close()
        except:
            pass

        raise

# ============================================
# CONTROL TASKS
# ============================================

@app.task(name='tasks.control_job')
def control_job(job_id: str, action: str):
    """Управление задачами"""
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
# AUTO-START PENDING
# ============================================

@app.task(name='tasks.start_all_pending')
def start_all_pending():
    """Запускает ВСЕ pending задачи"""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT j.id, s.cidr, p.port, s.geo
            FROM scan_jobs j
            JOIN scan_subnets s ON j.subnet_id = s.id
            JOIN scan_ports p ON j.port_id = p.id
            WHERE j.status = 'pending'
            ORDER BY j.created_at ASC
            LIMIT 50
        """)
        
        jobs = cur.fetchall()
        
        if not jobs:
            print("⚠️ No pending jobs")
            conn.close()
            return {'status': 'no_pending'}
        
        print(f"\n{'='*60}")
        print(f"🚀 STARTING {len(jobs)} PENDING JOBS")
        print(f"{'='*60}")
        
        launched = 0
        for job in jobs:
            jid = str(job[0])
            cidr = job[1]
            port = job[2]
            geo = job[3]
            
            cur.execute("UPDATE scan_jobs SET status='queued' WHERE id=%s", (jid,))
            
            print(f"✅ Launching: {cidr}:{port} (GEO={geo})")
            
            run_masscan.delay(jid, cidr, port, geo)
            launched += 1
        
        conn.commit()
        conn.close()
        
        print(f"✅ LAUNCHED {launched} JOBS")
        print(f"{'='*60}\n")
        
        return {'status': 'success', 'launched': launched}
        
    except Exception as e:
        print(f"❌ Error: {e}")
        if conn:
            try:
                conn.close()
            except:
                pass
        return {'status': 'error', 'error': str(e)}

# ============================================
# VPN CHECKER CONTROL
# ============================================

@app.task(name='tasks.manage_vpn_checker')
def manage_vpn_checker(geo: str, action: str):
    """Управляет VPN checker процессами"""
    if action == 'start':
        return {'status': 'success' if start_vpn_checker_for_geo(geo) else 'failed'}
    
    elif action == 'stop':
        return {'status': 'success' if stop_vpn_checker_for_geo(geo) else 'failed'}
    
    elif action == 'status':
        return get_vpn_checker_status()
    
    else:
        return {'error': f'Invalid action: {action}'}

# ============================================
# CLEANUP
# ============================================

@app.task(name='tasks.cleanup_old_data')
def cleanup_old_data(days: int = 7):
    """Очистка старых данных"""
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
# GRACEFUL SHUTDOWN
# ============================================

def shutdown_all_checkers():
    """Останавливает все VPN checker процессы"""
    global VPN_CHECKER_PROCESSES
    
    print("🛑 Shutting down all VPN checkers...")
    
    with VPN_CHECKER_LOCK:
        for geo in list(VPN_CHECKER_PROCESSES.keys()):
            stop_vpn_checker_for_geo(geo)
    
    print("✅ All VPN checkers stopped")

atexit.register(shutdown_all_checkers)

# ============================================
# BEAT SCHEDULE
# ============================================

app.conf.beat_schedule = {
    "start-all-pending": {
        "task": "tasks.start_all_pending",
        "schedule": 30.0,
    },
}

print("✅ Celery tasks loaded")
print("✅ Beat schedule: start_all_pending every 30s")
