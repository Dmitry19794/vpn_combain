#!/usr/bin/env python3
# web/settings_api.py - API endpoints для управления настройками

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List
import sys

sys.path.insert(0, '/opt/vpn')
from config import config

router = APIRouter(prefix="/api/settings", tags=["settings"])

# ============================================
# Pydantic Models
# ============================================

class ScannerConfig(BaseModel):
    engine: str  # masscan | naabu
    rate: int
    workers: int
    timeout: int
    retries: int

class HttpxConfig(BaseModel):
    enabled: bool
    timeout: int
    threads: int
    extract_title: bool
    tech_detect: bool
    status_code: bool
    headers: bool

class NucleiConfig(BaseModel):
    templates: List[str]
    severity: List[str]
    concurrent: int

class CheckerConfig(BaseModel):
    min_workers: int
    max_workers: int
    verify_ssl: bool

class DetectionConfig(BaseModel):
    mode: str  # nuclei-only | checker-only | nuclei-then-checker | parallel
    timeout: int
    nuclei: NucleiConfig
    checker: CheckerConfig

class BruteConfig(BaseModel):
    enabled: bool
    timeout: int
    max_attempts: int

class FullConfig(BaseModel):
    scanner: ScannerConfig
    httpx: HttpxConfig
    detection: DetectionConfig
    brute: BruteConfig

# ============================================
# API Endpoints
# ============================================

@router.get("/current")
async def get_current_settings():
    """Получить текущие настройки"""
    return {
        "status": "success",
        "config": config._config
    }

@router.post("/save")
async def save_settings(settings: FullConfig):
    """Сохранить полную конфигурацию"""
    try:
        # Обновляем конфиг
        config._config = settings.dict()
        config.save()
        
        return {
            "status": "success",
            "message": "Settings saved successfully"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/scanner")
async def update_scanner(settings: ScannerConfig):
    """Обновить настройки сканера"""
    try:
        config.update({
            'scanner.engine': settings.engine,
            'scanner.rate': settings.rate,
            'scanner.workers': settings.workers,
            'scanner.timeout': settings.timeout,
            'scanner.retries': settings.retries
        })
        
        return {
            "status": "success",
            "scanner": settings.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/httpx")
async def update_httpx(settings: HttpxConfig):
    """Обновить настройки httpx"""
    try:
        config.update({
            'httpx.enabled': settings.enabled,
            'httpx.timeout': settings.timeout,
            'httpx.threads': settings.threads,
            'httpx.extract_title': settings.extract_title,
            'httpx.tech_detect': settings.tech_detect,
            'httpx.status_code': settings.status_code,
            'httpx.headers': settings.headers
        })
        
        return {
            "status": "success",
            "httpx": settings.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/detection")
async def update_detection(settings: DetectionConfig):
    """Обновить настройки детекции"""
    try:
        config.update({
            'detection.mode': settings.mode,
            'detection.timeout': settings.timeout,
            'detection.nuclei.templates': settings.nuclei.templates,
            'detection.nuclei.severity': settings.nuclei.severity,
            'detection.nuclei.concurrent': settings.nuclei.concurrent,
            'detection.checker.min_workers': settings.checker.min_workers,
            'detection.checker.max_workers': settings.checker.max_workers,
            'detection.checker.verify_ssl': settings.checker.verify_ssl
        })
        
        return {
            "status": "success",
            "detection": settings.dict()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/validate")
async def validate_settings():
    """Проверяет наличие всех бинарников"""
    import os
    from pathlib import Path
    
    bin_dir = config.bin_dir
    tools = {
        'masscan': '/usr/bin/masscan',
        'naabu': bin_dir / 'naabu',
        'httpx': bin_dir / 'httpx',
        'nuclei': bin_dir / 'nuclei'
    }
    
    status = {}
    all_ok = True
    
    for tool, path in tools.items():
        exists = Path(path).exists()
        status[tool] = {
            'installed': exists,
            'path': str(path)
        }
        if not exists and tool == config.scanner_engine:
            all_ok = False
    
    return {
        "status": "valid" if all_ok else "invalid",
        "tools": status,
        "current_engine": config.scanner_engine
    }

@router.post("/reset")
async def reset_to_defaults():
    """Сбросить настройки к значениям по умолчанию"""
    try:
        from config import DEFAULT_CONFIG
        config._config = DEFAULT_CONFIG.copy()
        config.save()
        
        return {
            "status": "success",
            "message": "Settings reset to defaults",
            "config": config._config
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/pipeline-preview")
async def get_pipeline_preview():
    """Возвращает текущую конфигурацию pipeline"""
    steps = []
    
    # Step 1: Scanner
    steps.append({
        "name": config.scanner_engine.upper(),
        "description": "Port scanning",
        "active": True,
        "config": {
            "rate": config.get('scanner.rate'),
            "workers": config.get('scanner.workers')
        }
    })
    
    # Step 2: Httpx (опционально)
    if config.httpx_enabled:
        steps.append({
            "name": "HTTPX",
            "description": "HTTP fingerprinting",
            "active": True,
            "config": {
                "timeout": config.get('httpx.timeout'),
                "threads": config.get('httpx.threads')
            }
        })
    
    # Step 3: Detection
    mode = config.detection_mode
    if mode == 'nuclei-only':
        steps.append({
            "name": "NUCLEI",
            "description": "Template-based detection",
            "active": True
        })
    elif mode == 'checker-only':
        steps.append({
            "name": "CHECKER",
            "description": "Deep analysis",
            "active": True
        })
    elif mode == 'nuclei-then-checker':
        steps.append({
            "name": "NUCLEI + CHECKER",
            "description": "Combined detection",
            "active": True
        })
    elif mode == 'parallel':
        steps.append({
            "name": "PARALLEL",
            "description": "Both engines",
            "active": True
        })
    
    # Step 4: Brute
    if config.get('brute.enabled'):
        steps.append({
            "name": "BRUTE",
            "description": "Credential stuffing",
            "active": True
        })
    
    return {
        "status": "success",
        "pipeline": steps
    }
