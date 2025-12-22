#!/usr/bin/env python3
# /opt/vpn/celery_app/tasks.py - ПОЛНЫЙ РАБОЧИЙ КОД С PIPELINE

import os
import sys
import json

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import threading
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
# CONFIG LOADER
# ============================================

def load_config():
    """Загружает конфиг из файла"""
    config_file = '/opt/vpn/config.json'
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except:
            pass
    return {
        "scanner": {"engine": "masscan", "rate": 10000},
        "httpx": {"enabled": True},
        "detection": {"mode": "checker-only"}
    }

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

VPN_CHECKER_PROCESSES = {}
VPN_CHECKER_LOCK = threading.Lock()

# ============================================
# UTILITIES
# ============================================

def split_cidr_into_blocks(cidr: str, block_size: int = 24) -> List[str]:
    """Разбивает CIDR на блоки"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.prefixlen >= block_size:
            return [str(network)]
        subnets = list(network.subnets(new_prefix=block_size))
        if len(subnets) > 1000:
            subnets = subnets[:1000]
        return [str(subnet) for subnet in subnets]
    except Exception as e:
        print(f"❌ split_cidr error: {e}")
        return [cidr]

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
        print(f"❌ insert error: {e}")
        return 0

# ============================================
# VPN CHECKER MANAGEMENT
# ============================================

def start_vpn_checker_for_geo(geo: str) -> bool:
    """Запускает VPN checker"""
    global VPN_CHECKER_PROCESSES
    with VPN_CHECKER_LOCK:
        if geo in VPN_CHECKER_PROCESSES:
            proc = VPN_CHECKER_PROCESSES[geo]
            if proc.poll() is None:
                print(f"✅ Checker for {geo} already running")
                return True
            else:
                del VPN_CHECKER_PROCESSES[geo]
        try:
            checker_bin = "/opt/vpn/checker/checker"
            if not os.path.exists(checker_bin):
                print(f"❌ Checker not found")
                return False
            proc = subprocess.Popen(
                [checker_bin, f"--geo={geo}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                universal_newlines=True
            )
            VPN_CHECKER_PROCESSES[geo] = proc
            print(f"🚀 Started Checker for {geo}")
            return True
        except Exception as e:
            print(f"❌ Failed to start checker: {e}")
            return False

# ============================================
# MAIN SCAN TASK
# ============================================

@app.task(bind=True, name='tasks.run_masscan')
def run_masscan(self, job_id: str, cidr: str, port: int, geo: str):
    """Основная задача сканирования с pipeline"""
    print(f"\n{'='*60}")
    print(f"🔍 Starting scan: {cidr}:{port} (GEO={geo})")
    print(f"{'='*60}\n")
    
    config = load_config()
    scanner_engine = config.get('scanner', {}).get('engine', 'masscan')
    httpx_enabled = config.get('httpx', {}).get('enabled', True)
    detection_mode = config.get('detection', {}).get('mode', 'checker-only')
    
    print(f"📋 Pipeline: {scanner_engine} → {'httpx → ' if httpx_enabled else ''}{detection_mode}")
    
    start_time = time.time()
    total_results = 0
    conn = None
    
    try:
        # Обновляем статус
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE scan_jobs
            SET status = 'running', started_at = NOW()
            WHERE id = %s
        """, (job_id,))
        conn.commit()
        conn.close()
        conn = None

        # STEP 1: СКАНИРОВАНИЕ
        blocks = split_cidr_into_blocks(cidr, 24)
        total_blocks = len(blocks)
        print(f"📊 Split into {total_blocks} blocks")
        
        if total_blocks > 100:
            blocks = blocks[:100]
            total_blocks = 100

        found_ips = []

        for i, block in enumerate(blocks):
            output_file = f"/tmp/scan_{job_id}_{i}.txt"
            
            # Выбираем сканер
            if scanner_engine == 'naabu':
                cmd = [
                    '/opt/vpn/bin/naabu',
                    '-host', block,
                    '-p', str(port),
                    '-rate', '10000',
                    '-silent',
                    '-json',
                    '-o', output_file
                ]
            else:
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
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
                
                if result.returncode == 0 and os.path.exists(output_file):
                    # Парсим результаты
                    with open(output_file, 'r') as f:
                        for line in f:
                            if scanner_engine == 'naabu':
                                try:
                                    data = json.loads(line)
                                    if 'ip' in data:
                                        found_ips.append(data['ip'])
                                except:
                                    continue
                            else:
                                if 'Host:' in line and '/open/' in line:
                                    parts = line.split()
                                    try:
                                        idx = parts.index('Host:')
                                        found_ips.append(parts[idx + 1])
                                    except:
                                        continue
                    
                    # Сохраняем в БД
                    if found_ips:
                        conn = get_db_connection()
                        count = insert_addresses_batch(conn, found_ips, port, geo)
                        conn.commit()
                        total_results += count
                        conn.close()
                        conn = None
                        print(f"✅ Block {i+1}/{total_blocks}: found {count} hosts")
                        found_ips = []
                
            except Exception as e:
                print(f"❌ Scan error block {i+1}: {e}")
            finally:
                if os.path.exists(output_file):
                    try:
                        os.remove(output_file)
                    except:
                        pass

            # Обновляем прогресс
            progress = ((i + 1) / total_blocks) * 100
            try:
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute("""
                    UPDATE scan_jobs
                    SET progress_percent = %s, result_count = %s
                    WHERE id = %s
                """, (progress, total_results, job_id))
                conn.commit()
                conn.close()
                conn = None
            except:
                pass

        elapsed = time.time() - start_time
        
        # ФИНАЛ: обновляем статус на completed
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            UPDATE scan_jobs
            SET status = 'completed',
                finished_at = NOW(),
                result_count = %s,
                progress_percent = 100
            WHERE id = %s
        """, (total_results, job_id))
        conn.commit()
        conn.close()

        print(f"\n{'='*60}")
        print(f"✅ Scan completed: {total_results} hosts in {int(elapsed)}s")
        print(f"{'='*60}\n")

        # STEP 2: Запускаем VPN Checker если нашли хосты
        if total_results > 0:
            print(f"🎯 Starting VPN checker for {geo}")
            start_vpn_checker_for_geo(geo)

        return {
            'status': 'completed',
            'job_id': job_id,
            'result_count': total_results,
            'elapsed_seconds': int(elapsed)
        }

    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()

        try:
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute("""
                UPDATE scan_jobs
                SET status = 'failed', finished_at = NOW()
                WHERE id = %s
            """, (job_id,))
            conn.commit()
            conn.close()
        except:
            pass

        raise

# ============================================
# AUTO-START PENDING
# ============================================

@app.task(name='tasks.start_all_pending')
def start_all_pending():
    """Запускает pending задачи"""
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
