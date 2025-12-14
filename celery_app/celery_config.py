# vpn/celery_app/celery_config.py
# Конфигурация Celery

from celery.schedules import crontab

# Broker и Backend
broker_url = 'redis://localhost:6379/0'
result_backend = 'redis://localhost:6379/1'

# Сериализация
task_serializer = 'json'
accept_content = ['json']
result_serializer = 'json'

# Временная зона
timezone = 'UTC'
enable_utc = True

# Отслеживание задач
task_track_started = True
task_send_sent_event = True

# Лимиты времени выполнения
task_time_limit = 3600  # 1 час hard limit
task_soft_time_limit = 3300  # 55 минут soft limit

# Настройки воркера
worker_prefetch_multiplier = 1  # Берём по одной задаче за раз
worker_max_tasks_per_child = 50  # Перезапуск воркера после 50 задач
worker_disable_rate_limits = True

# Результаты
result_expires = 86400  # Результаты хранятся 24 часа

# Периодические задачи (Celery Beat)
beat_schedule = {
    'process-pending-scans-us': {
        'task': 'tasks.process_pending_scans',
        'schedule': 30.0,  # Каждые 30 секунд
        'args': ('US', 5)  # GEO, limit
    },
    'process-pending-scans-eu': {
        'task': 'tasks.process_pending_scans',
        'schedule': 30.0,
        'args': ('EU', 5)
    },
    'process-pending-scans-asia': {
        'task': 'tasks.process_pending_scans',
        'schedule': 30.0,
        'args': ('ASIA', 5)
    },
    'cleanup-old-metrics': {
        'task': 'tasks.cleanup_old_metrics',
        'schedule': crontab(hour=3, minute=0),  # Каждый день в 3:00 UTC
        'args': (7,)  # Удаляем метрики старше 7 дней
    }
}

# Логирование
worker_log_format = '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s'
worker_task_log_format = '[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s'