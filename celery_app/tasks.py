#!/usr/bin/env python3
# vpn/celery_app/tasks.py
import os
import sys
from celery.schedules import crontab

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import signal
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

from web.db import get_db, db_pool

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
)

CHUNK_SIZE = 1000
CIDR_SPLIT_SIZE = 24  # /24 = 256 IP в блоке

# ============================================
# ЛОГ ОШИБОК
# ============================================
def save_worker_error(path: str, error: str, tb_text: Optional[str] = None):
    """Сохраняет ошибку в таблицу app_errors"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        try:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS app_errors (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    created_at TIMESTAMPTZ DEFAULT NOW(),
                    method TEXT,
                    path TEXT,
                    status_code INTEGER,
                    error TEXT,
                    traceback TEXT
                );
            """)
            cur.execute("""
                INSERT INTO app_errors (method, path, status_code, error, traceback)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                "CELERY",
                path,
                500,
                (error or '')[:8000],
                (tb_text or tb.format_exc())[:16000]
            ))
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except:
                pass
            print("❌ FAILED TO INSERT app_errors row:", e)
    except Exception as e:
        print("❌ FAILED TO SAVE CELERY ERROR:", e)
    finally:
        if conn:
            try:
                db_pool.putconn(conn)
            except Exception:
                try:
                    conn.close()
                except:
                    pass

# ============================================
# КОНТРОЛЬ ЗАДАЧ
# ============================================
def get_job_control_status(job_id):
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT control_action
            FROM scan_jobs
            WHERE id = %s
        """, (job_id,))
        row = cur.fetchone()
        return row[0] if row else None
    except Exception as e:
        print("❌ get_job_control_status error:", e)
        return None
    finally:
        if conn:
            db_pool.putconn(conn)

def update_job_progress(job_id: str, progress: float, conn):
    """Обновляет progress_percent"""
    try:
        cur = conn.cursor()
        cur.execute("""
            UPDATE scan_jobs
            SET progress_percent = %s
            WHERE id = %s
        """, (progress, job_id))
    except Exception as e:
        save_worker_error("update_job_progress", str(e), tb.format_exc())
        raise

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
            conn = get_db()
            cur = conn.cursor()
            try:
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
                try:
                    conn.rollback()
                except:
                    pass
                print("Failed to update job status in on_failure:", e)
        except Exception as e:
            print("Failed to get connection in on_failure:", e)
        finally:
            if conn:
                try:
                    db_pool.putconn(conn)
                except:
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
        conn = get_db()
        cur = conn.cursor()
        
        if geo:
            cur.execute("""
                SELECT host, port
                FROM proxies
                WHERE is_alive = TRUE AND geo = %s
                ORDER BY RANDOM()
                LIMIT 1
            """, (geo,))
        else:
            cur.execute("""
                SELECT host, port
                FROM proxies
                WHERE is_alive = TRUE
                ORDER BY RANDOM()
                LIMIT 1
            """)
        
        row = cur.fetchone()
        if row:
            return (row[0], row[1])
        return None
        
    except Exception as e:
        print(f"❌ get_random_proxy error: {e}")
        return None
    finally:
        if conn:
            try:
                db_pool.putconn(conn)
            except:
                pass

def run_nmap_via_proxy(target: str, port: int, proxy_host: str, proxy_port: int, 
                       output_file: str, timeout: int = 120) -> bool:
    """Запускает nmap через proxychains"""
    config_path = None
    try:
        # Создаем временный конфиг proxychains
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as f:
            config_path = f.name
            f.write(f"""# Proxychains config
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 {proxy_host} {proxy_port}
""")
        
        print(f"📝 Created proxychains config: {proxy_host}:{proxy_port}")
        
        # Команда nmap
        cmd = [
            'proxychains4', '-f', config_path, '-q',
            'nmap',
            '-p', str(port),
            '-sT',
            '-Pn',
            '--open',
            '-T4',
            '--max-retries', '1',
            '--host-timeout', '30s',
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
            process.kill()
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
        
        # Ограничение
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

# ============================================
# ОСНОВНАЯ ЗАДАЧА СКАНИРОВАНИЯ
# ============================================
@app.task(bind=True, name='tasks.run_masscan', base=MasscanTask)
def run_masscan(self, job_id: str, cidr: str, port: int, geo: str):
    """Распределенное сканирование через прокси"""
    print(f"🔍 Starting distributed scan: {cidr}:{port} (Job={job_id}, GEO={geo})")
    
    start_time = time.time()
    total_results = 0
    conn = None
    
    try:
        # Помечаем задачу как running
        try:
            conn = get_db()
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
        except Exception as e:
            print(f"❌ Error setting running status: {e}")
        finally:
            if conn:
                try:
                    db_pool.putconn(conn)
                except:
                    pass
            conn = None
        
        # Разбиваем на блоки
        blocks = split_cidr_into_blocks(cidr, CIDR_SPLIT_SIZE)
        total_blocks = len(blocks)
        print(f"📊 Split {cidr} into {total_blocks} blocks (/{CIDR_SPLIT_SIZE})")
        
        # Ограничиваем
        if total_blocks > 100:
            print(f"⚠️ Too many blocks ({total_blocks}), limiting to 100")
            blocks = blocks[:100]
            total_blocks = 100
        
        # Сканируем каждый блок
        for i, block in enumerate(blocks):
            # Проверяем control actions
            try:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("SELECT control_action FROM scan_jobs WHERE id = %s", (job_id,))
                row = cur.fetchone()
                ctrl = row[0] if row else None
            except Exception as e:
                print(f"⚠️ Error checking control: {e}")
                ctrl = None
            finally:
                if conn:
                    try:
                        db_pool.putconn(conn)
                    except:
                        pass
                conn = None
            
            if ctrl == 'stop':
                print(f"🛑 Stopping job {job_id}")
                break
            
            # Получаем прокси
            proxy = get_random_proxy(geo)
            if not proxy:
                print(f"⚠️ No proxy for GEO={geo}, skipping {block}")
                continue
            
            proxy_host, proxy_port = proxy
            output_file = f"/tmp/nmap_{job_id}_{i}.txt"
            
            # Запускаем nmap
            try:
                success = run_nmap_via_proxy(
                    target=block,
                    port=port,
                    proxy_host=proxy_host,
                    proxy_port=proxy_port,
                    output_file=output_file,
                    timeout=120
                )
            except Exception as e:
                print(f"❌ Nmap error for {block}: {e}")
                success = False
            
            if success:
                # Парсим результаты
                try:
                    conn = get_db()
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
                            db_pool.putconn(conn)
                        except:
                            pass
                    conn = None
            else:
                print(f"⚠️ Block {i+1}/{total_blocks}: scan failed")
            
            # Удаляем временный файл
            try:
                if os.path.exists(output_file):
                    os.remove(output_file)
            except:
                pass
            
            # Обновляем прогресс
            progress = ((i + 1) / total_blocks) * 100
            try:
                conn = get_db()
                cur = conn.cursor()
                cur.execute("""
                    UPDATE scan_jobs
                    SET progress_percent = %s,
                        result_count = %s
                    WHERE id = %s
                """, (progress, total_results, job_id))
                conn.commit()
            except Exception as e:
                print(f"⚠️ Progress update error: {e}")
            finally:
                if conn:
                    try:
                        db_pool.putconn(conn)
                    except:
                        pass
                conn = None
            
            # Celery meta
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
        
        # Финальный апдейт
        elapsed = time.time() - start_time
        try:
            conn = get_db()
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
                    db_pool.putconn(conn)
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
        
        # Помечаем failed
        try:
            conn = get_db()
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
                    db_pool.putconn(conn)
                except:
                    pass
        
        raise

# ============================================
# ВСТАВКА АДРЕСОВ
# ============================================
def insert_addresses_batch(conn, ips: List[str], port: int, geo: str, job_id: str) -> int:
    if not ips:
        return 0

    cur = conn.cursor()
    rows = [(ip, port, geo, job_id) for ip in ips]

    sql = """
        INSERT INTO scanned_addresses (id, ip, port, geo, job_id, is_checked, created_at, updated_at)
        SELECT gen_random_uuid(), data.ip::inet, data.port, data.geo, data.job_id::uuid, FALSE, NOW(), NOW()
        FROM (VALUES %s) AS data(ip, port, geo, job_id)
        ON CONFLICT DO NOTHING
    """

    try:
        execute_values(cur, sql, rows)
        return len(rows)
    except Exception as e:
        save_worker_error("insert_addresses_batch", str(e), tb.format_exc())
        return 0

# ============================================
# Управление задачами (pause/stop/resume)
# ============================================
@app.task(name='tasks.control_job')
def control_job(job_id: str, action: str):
    if action not in ['pause', 'resume', 'stop']:
        return {'error': f'Invalid action: {action}'}

    conn = None
    try:
        conn = get_db()
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
                db_pool.putconn(conn)
            except:
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
        conn = get_db()
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
                db_pool.putconn(conn)
            except:
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

# ============================================
# АВТОЗАПУСК PENDING
# ============================================
# НАЙДИ В tasks.py функцию process_pending_scans и ЗАМЕНИ на это:

@app.task(name='tasks.process_pending_scans')
def process_pending_scans(geo: str = 'US', limit: int = 10):
    """Берём pending задачи и запускаем"""
    conn = None
    try:
        conn = get_db()
        cur = conn.cursor()
        
        # ИСПРАВЛЕНО: добавлена проверка результата
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
        
        # ПРОВЕРЯЕМ что есть результаты
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
        # НЕ бросаем exception, просто возвращаем None
        return None
    finally:
        if conn:
            try:
                db_pool.putconn(conn)
            except:
                try:
                    conn.close()
                except:
                    pass
