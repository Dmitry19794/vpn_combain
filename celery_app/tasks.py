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

# ============================================
# ЛОГ ОШИБОК
# ============================================
def save_worker_error(path: str, error: str, tb_text: Optional[str] = None):
    """
    Сохраняет ошибку в таблицу app_errors. Берёт соединение из пула и
    гарантированно возвращает его.
    """
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
            # Не поднимаем исключение выше — логирование ошибок не должно ломать задачу.
            print("❌ FAILED TO INSERT app_errors row:", e)
    except Exception as e:
        print("❌ FAILED TO SAVE CELERY ERROR (pool error?):", e)
    finally:
        # Всегда возвращаем соединение в пул, если оно было получено.
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
    """
    Обновляет progress_percent — НЕ делает commit (вызовчик решает).
    conn — открытое соединение.
    """
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
                print("Failed to update job status in on_failure (db):", e)
                save_worker_error(path=f"task.on_failure:update:{task_id}", error=str(e), tb_text=tb.format_exc())
        except Exception as e:
            print("Failed to update job status in on_failure (pool/get):", e)
            save_worker_error(path=f"task.on_failure:getconn:{task_id}", error=str(e), tb_text=tb.format_exc())
        finally:
            if conn:
                try:
                    db_pool.putconn(conn)
                except:
                    try:
                        conn.close()
                    except:
                        pass

        # Сохраняем саму ошибку
        save_worker_error(path=f"task.on_failure:{task_id}", error=str(exc), tb_text=tb.format_exc())


# ============================================
# ПАРСИНГ РЕЗУЛЬТАТОВ MASSCAN
# ============================================
def parse_and_save_results(output_file: str, job_id: str, port: int, geo: str, conn) -> int:
    """
    Парсит output_file и вставляет адреса пачками.
    conn передаётся открытым; функция делает commit/rollback по результатам.
    """
    total = 0
    if not os.path.exists(output_file):
        return 0

    try:
        with open(output_file, 'r') as f:
            ips = []
            for line in f:
                if line.startswith('open'):
                    parts = line.strip().split()
                    if len(parts) >= 4:
                        try:
                            found_port = int(parts[2])
                        except:
                            continue
                        if found_port == port:
                            ips.append(parts[3])

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
                            save_worker_error(f"parse_and_save_results:chunk:{job_id}", str(e), tb.format_exc())
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
                    save_worker_error(f"parse_and_save_results:final:{job_id}", str(e), tb.format_exc())

    except Exception as e:
        save_worker_error(f"parse_and_save_results:open:{job_id}", str(e), tb.format_exc())

    return total


# ============================================
# ОСНОВНАЯ ЗАДАЧА СКАНИРОВАНИЯ
# ============================================
@app.task(bind=True, name='tasks.run_masscan')
def run_masscan(self, job_id: str, cidr: str, port: int, geo: str):
    """
    Masscan runner — каждое обращение к БД делает короткое соединение.
    """
    print(f"🔍 Starting masscan: {cidr}:{port} (Job={job_id})")

    process = None
    output_file = f"/tmp/masscan_{job_id}.txt"
    paused_at = None
    total_ips = 0
    start_time = time.time()

    try:
        # Оценка объёма адресов
        try:
            import ipaddress
            network = ipaddress.ip_network(cidr, strict=False)
            total_ips = network.num_addresses
        except Exception:
            total_ips = 256

        # Помечаем задачу как running (короткое соединение)
        conn = None
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
            try:
                conn.rollback()
            except:
                pass
            save_worker_error(f"run_masscan:set-running:{job_id}", str(e), tb.format_exc())
        finally:
            if conn:
                try:
                    db_pool.putconn(conn)
                except:
                    try:
                        conn.close()
                    except:
                        pass

        # Запускаем masscan
        cmd = [
            'sudo', 'masscan',
            cidr,
            f'-p{port}',
            '--rate=1000',
            '--banners',
            '-oL', output_file
        ]
        print(f"📡 Running: {' '.join(cmd)}")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Сохраняем PID (короткое соединение)
        conn = None
        try:
            conn = get_db()
            cur = conn.cursor()
            cur.execute("UPDATE scan_jobs SET process_pid = %s WHERE id = %s", (process.pid, job_id))
            conn.commit()
        except Exception as e:
            try:
                conn.rollback()
            except:
                pass
            save_worker_error(f"run_masscan:set-pid:{job_id}", str(e), tb.format_exc())
        finally:
            if conn:
                try:
                    db_pool.putconn(conn)
                except:
                    try:
                        conn.close()
                    except:
                        pass

        # Мониторинг процесса — каждую итерацию берём отдельное соединение
        last_check = time.time()
        while process.poll() is None:
            if time.time() - last_check > 2:
                last_check = time.time()
                try:
                    conn_ctrl = None
                    try:
                        conn_ctrl = get_db()
                        ctrl = get_job_control_status(job_id)
                    except Exception as e:
                        save_worker_error(f"run_masscan:ctrl-get:{job_id}", str(e), tb.format_exc())
                        ctrl = {'action': None}
                    finally:
                        if conn_ctrl:
                            try:
                                db_pool.putconn(conn_ctrl)
                            except:
                                try:
                                    conn_ctrl.close()
                                except:
                                    pass

                    action = ctrl if isinstance(ctrl, str) else None

                    if action == 'stop':
                        print(f"🛑 Stopping job {job_id} by user request")
                        try:
                            process.terminate()
                            time.sleep(1)
                            if process.poll() is None:
                                process.kill()
                        except:
                            pass

                        # update status stopped and parse results
                        conn_upd = None
                        try:
                            conn_upd = get_db()
                            cur = conn_upd.cursor()
                            cur.execute("""
                                UPDATE scan_jobs
                                SET status = 'stopped',
                                    finished_at = NOW(),
                                    process_pid = NULL,
                                    control_action = NULL
                                WHERE id = %s
                            """, (job_id,))
                            conn_upd.commit()
                        except Exception as e:
                            try:
                                conn_upd.rollback()
                            except:
                                pass
                            save_worker_error(f"run_masscan:stop-update:{job_id}", str(e), tb.format_exc())
                        finally:
                            if conn_upd:
                                try:
                                    db_pool.putconn(conn_upd)
                                except:
                                    try:
                                        conn_upd.close()
                                    except:
                                        pass

                        # parse results using a fresh connection and pass it to parser
                        conn_parse = None
                        try:
                            conn_parse = get_db()
                            results_count = parse_and_save_results(output_file, job_id, port, geo, conn_parse)
                            conn_parse.commit()
                        except Exception as e:
                            try:
                                if conn_parse:
                                    conn_parse.rollback()
                            except:
                                pass
                            results_count = 0
                            save_worker_error(f"run_masscan:parse-after-stop:{job_id}", str(e), tb.format_exc())
                        finally:
                            if conn_parse:
                                try:
                                    db_pool.putconn(conn_parse)
                                except:
                                    try:
                                        conn_parse.close()
                                    except:
                                        pass

                        return {
                            'status': 'stopped',
                            'job_id': job_id,
                            'result_count': results_count,
                            'message': 'Stopped by user'
                        }

                    elif action == 'pause':
                        if paused_at is None:
                            print(f"⏸️ Pausing job {job_id}")
                            try:
                                os.kill(process.pid, signal.SIGSTOP)
                            except:
                                pass
                            paused_at = time.time()
                            conn_upd = None
                            try:
                                conn_upd = get_db()
                                cur = conn_upd.cursor()
                                cur.execute("UPDATE scan_jobs SET status = 'paused' WHERE id = %s", (job_id,))
                                conn_upd.commit()
                            except Exception as e:
                                try:
                                    if conn_upd:
                                        conn_upd.rollback()
                                except:
                                    pass
                                save_worker_error(f"run_masscan:pause-update:{job_id}", str(e), tb.format_exc())
                            finally:
                                if conn_upd:
                                    try:
                                        db_pool.putconn(conn_upd)
                                    except:
                                        try:
                                            conn_upd.close()
                                        except:
                                            pass

                    elif action == 'resume' and paused_at is not None:
                        print(f"▶️ Resuming job {job_id}")
                        try:
                            os.kill(process.pid, signal.SIGCONT)
                        except:
                            pass
                        paused_at = None
                        conn_upd = None
                        try:
                            conn_upd = get_db()
                            cur = conn_upd.cursor()
                            cur.execute("UPDATE scan_jobs SET status = 'running', control_action = NULL WHERE id = %s", (job_id,))
                            conn_upd.commit()
                        except Exception as e:
                            try:
                                if conn_upd:
                                    conn_upd.rollback()
                            except:
                                pass
                            save_worker_error(f"run_masscan:resume-update:{job_id}", str(e), tb.format_exc())
                        finally:
                            if conn_upd:
                                try:
                                    db_pool.putconn(conn_upd)
                                except:
                                    try:
                                        conn_upd.close()
                                    except:
                                        pass

                    # Обновление прогресса
                    if paused_at is None:
                        elapsed = time.time() - start_time
                        scanned_estimate = min(elapsed * 1000, total_ips)
                        progress = min((scanned_estimate / total_ips) * 100, 99) if total_ips > 0 else 50

                        # обновляем прогресс коротким соединением
                        conn_prog = None
                        try:
                            conn_prog = get_db()
                            update_job_progress(job_id, progress, conn_prog)
                            conn_prog.commit()
                        except Exception as e:
                            try:
                                if conn_prog:
                                    conn_prog.rollback()
                            except:
                                pass
                            save_worker_error(f"run_masscan:update-progress:{job_id}", str(e), tb.format_exc())
                        finally:
                            if conn_prog:
                                try:
                                    db_pool.putconn(conn_prog)
                                except:
                                    try:
                                        conn_prog.close()
                                    except:
                                        pass

                        # celery meta
                        try:
                            self.update_state(
                                state='PROGRESS',
                                meta={'job_id': job_id, 'cidr': cidr, 'progress': progress, 'elapsed': int(elapsed)}
                            )
                        except:
                            pass

                except Exception as e:
                    # логируем, но не бросаем — чтобы цикл masscan продолжал
                    save_worker_error(f"run_masscan:control-loop:{job_id}", str(e), tb.format_exc())

            time.sleep(0.5)

        # После завершения процесса — получаем returncode, парсим и обновляем статус
        returncode = process.returncode
        elapsed = time.time() - start_time
        print(f"📊 Masscan finished: return_code={returncode}, time={elapsed:.1f}s")

        if returncode not in (0, -15):
            try:
                stdout, stderr = process.communicate(timeout=5)
            except:
                stdout, stderr = ("", "")
            save_worker_error(f"run_masscan:masscan-error:{job_id}", stderr)
            raise Exception(f"Masscan failed with code {returncode}: {stderr[:300]}")

        # Парсим результаты (используем отдельное соединение внутри)
        conn_parse = None
        try:
            conn_parse = get_db()
            result_count = parse_and_save_results(output_file, job_id, port, geo, conn_parse)
            conn_parse.commit()
        except Exception as e:
            try:
                if conn_parse:
                    conn_parse.rollback()
            except:
                pass
            result_count = 0
            save_worker_error(f"run_masscan:parse-results:{job_id}", str(e), tb.format_exc())
        finally:
            if conn_parse:
                try:
                    db_pool.putconn(conn_parse)
                except:
                    try:
                        conn_parse.close()
                    except:
                        pass

        # Финальный апдейт статуса completed
        conn_upd = None
        try:
            conn_upd = get_db()
            cur = conn_upd.cursor()
            cur.execute("""
                UPDATE scan_jobs
                SET status = 'completed',
                    finished_at = NOW(),
                    result_count = %s,
                    progress_percent = 100,
                    process_pid = NULL,
                    control_action = NULL
                WHERE id = %s
            """, (result_count, job_id))
            conn_upd.commit()
        except Exception as e:
            try:
                if conn_upd:
                    conn_upd.rollback()
            except:
                pass
            save_worker_error(f"run_masscan:finish-update:{job_id}", str(e), tb.format_exc())
        finally:
            if conn_upd:
                try:
                    db_pool.putconn(conn_upd)
                except:
                    try:
                        conn_upd.close()
                    except:
                        pass

        try:
            os.remove(output_file)
        except:
            pass

        print(f"✅ Job {job_id} completed: found {result_count} addresses")
        return {
            'status': 'completed',
            'job_id': job_id,
            'cidr': cidr,
            'port': port,
            'geo': geo,
            'result_count': result_count,
            'elapsed_seconds': int(elapsed)
        }

    except Exception as e:
        save_worker_error(f"run_masscan:exception:{job_id}", str(e), tb.format_exc())
        # помечаем failed
        conn_fail = None
        try:
            conn_fail = get_db()
            cur = conn_fail.cursor()
            cur.execute("""
                UPDATE scan_jobs
                SET status = 'failed',
                    finished_at = NOW(),
                    process_pid = NULL,
                    control_action = NULL
                WHERE id = %s
            """, (job_id,))
            conn_fail.commit()
        except Exception as e2:
            save_worker_error(f"run_masscan:update-failed:{job_id}", str(e2), tb.format_exc())
        finally:
            if conn_fail:
                try:
                    db_pool.putconn(conn_fail)
                except:
                    try:
                        conn_fail.close()
                    except:
                        pass
        raise

    finally:
        # окончательное завершение процесса, если жив
        try:
            if process and process.poll() is None:
                try:
                    process.terminate()
                    time.sleep(0.5)
                    if process.poll() is None:
                        process.kill()
                except:
                    pass
        except:
            pass


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
#   start masscan job (beat)
# ============================================
app.conf.beat_schedule = {
    "auto-start-pending-us": {
        "task": "tasks.process_pending_scans",
        "schedule": 15.0,  # каждые 15 секунд
        "args": ("US", 10),
    },
}


# ============================================
# АВТОЗАПУСК PENDING
# ============================================
@app.task(name='tasks.process_pending_scans')
def process_pending_scans(geo: str = 'US', limit: int = 10):
    """
    Берём несколько pending задач и запускаем run_masscan.delay для каждой.
    Обязательно корректно возвращаем соединение.
    """
    conn = None
    try:
        conn = get_db()
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
            # помечаем queued
            cur.execute("UPDATE scan_jobs SET status='queued' WHERE id=%s", (jid,))
            launched.append(jid)
            run_masscan.delay(jid, cidr, p, g)

        conn.commit()
        return {'status': 'launched', 'count': len(launched)}
    except Exception as e:
        try:
            if conn:
                conn.rollback()
        except:
            pass
        save_worker_error("process_pending_scans", str(e), tb.format_exc())
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
