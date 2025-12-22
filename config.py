#!/usr/bin/env python3
# /opt/vpn/config.py

import os
import json
from pathlib import Path

DEFAULT_CONFIG = {
    "scanner": {
        "engine": "masscan",
        "rate": 10000,
        "workers": 64,
        "timeout": 5,
        "retries": 2
    },
    "httpx": {
        "enabled": True,
        "timeout": 10,
        "threads": 50
    },
    "detection": {
        "mode": "nuclei-then-checker",
        "timeout": 15
    },
    "brute": {
        "enabled": True,
        "timeout": 30,
        "max_attempts": 3
    },
    "paths": {
        "bin_dir": "/opt/vpn/bin"
    }
}

CONFIG_FILE = Path("/opt/vpn/config.json")

class ConfigManager:
    _instance = None
    _config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load()
        return cls._instance

    def _load(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    self._config = json.load(f)
                print(f"✅ Config loaded from {CONFIG_FILE}")
            except Exception as e:
                print(f"⚠️ Failed to load config: {e}")
                self._config = DEFAULT_CONFIG.copy()
        else:
            print(f"📝 Creating default config")
            self._config = DEFAULT_CONFIG.copy()
            self.save()

    def save(self):
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self._config, f, indent=2)
            print(f"💾 Config saved")
        except Exception as e:
            print(f"❌ Failed to save config: {e}")

    def get(self, key, default=None):
        keys = key.split('.')
        value = self._config
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                return default
            if value is None:
                return default
        return value

    def update(self, updates):
        for key, value in updates.items():
            keys = key.split('.')
            cfg = self._config
            for k in keys[:-1]:
                if k not in cfg:
                    cfg[k] = {}
                cfg = cfg[k]
            cfg[keys[-1]] = value
        self.save()

config = ConfigManager()
