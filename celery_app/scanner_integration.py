#!/usr/bin/env python3
# /opt/vpn/celery_app/scanner_integration.py
# РЕАЛЬНАЯ ИНТЕГРАЦИЯ naabu, httpx, nuclei

import subprocess
import json
import os
import tempfile
from typing import List, Dict, Tuple

# ============================================
# NAABU - Port Scanner
# ============================================

def run_naabu(target: str, ports: List[int], output_file: str, rate: int = 10000, timeout: int = 300) -> Tuple[int, List[str]]:
    """
    Запускает naabu для сканирования портов
    
    Returns:
        (returncode, list_of_ips)
    """
    try:
        naabu_bin = "/opt/vpn/bin/naabu"
        
        if not os.path.exists(naabu_bin):
            print(f"❌ Naabu not found at {naabu_bin}")
            return -1, []
        
        # Формируем порты
        ports_str = ','.join(map(str, ports))
        
        cmd = [
            naabu_bin,
            '-host', target,
            '-p', ports_str,
            '-rate', str(rate),
            '-json',
            '-o', output_file,
            '-silent'
        ]
        
        print(f"🔍 Running naabu: {' '.join(cmd)}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode != 0:
            print(f"⚠️ Naabu exited with code {result.returncode}")
            print(f"STDERR: {result.stderr}")
        
        # Парсим результаты
        open_ips = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        if 'ip' in data and 'port' in data:
                            open_ips.append(data['ip'])
                    except json.JSONDecodeError:
                        continue
        
        # Дедупликация
        open_ips = list(set(open_ips))
        
        print(f"✅ Naabu found {len(open_ips)} hosts with open ports")
        
        return result.returncode, open_ips
        
    except subprocess.TimeoutExpired:
        print(f"⏰ Naabu timeout after {timeout}s")
        return -1, []
    except Exception as e:
        print(f"❌ Naabu error: {e}")
        return -1, []


# ============================================
# HTTPX - HTTP Fingerprinting
# ============================================

def run_httpx(targets: List[str], output_file: str, timeout: int = 10, threads: int = 50) -> Tuple[int, List[Dict]]:
    """
    Запускает httpx для HTTP fingerprinting
    
    Returns:
        (returncode, list_of_results)
    """
    try:
        httpx_bin = "/opt/vpn/bin/httpx"
        
        if not os.path.exists(httpx_bin):
            print(f"❌ Httpx not found at {httpx_bin}")
            return -1, []
        
        # Создаём временный файл с целями
        input_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for target in targets:
            input_file.write(f"{target}\n")
        input_file.close()
        
        cmd = [
            httpx_bin,
            '-l', input_file.name,
            '-timeout', str(timeout),
            '-threads', str(threads),
            '-json',
            '-title',
            '-tech-detect',
            '-status-code',
            '-o', output_file,
            '-silent'
        ]
        
        print(f"🌐 Running httpx on {len(targets)} targets")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout * 10  # Общий таймаут
        )
        
        # Удаляем временный файл
        try:
            os.remove(input_file.name)
        except:
            pass
        
        if result.returncode != 0:
            print(f"⚠️ Httpx exited with code {result.returncode}")
        
        # Парсим результаты
        results = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        results.append(data)
                    except json.JSONDecodeError:
                        continue
        
        print(f"✅ Httpx probed {len(results)} HTTP services")
        
        return result.returncode, results
        
    except subprocess.TimeoutExpired:
        print(f"⏰ Httpx timeout")
        return -1, []
    except Exception as e:
        print(f"❌ Httpx error: {e}")
        return -1, []


# ============================================
# NUCLEI - VPN Detection
# ============================================

def run_nuclei(targets: List[str], output_file: str, templates: List[str] = None, timeout: int = 300) -> Tuple[int, List[Dict]]:
    """
    Запускает nuclei для детекции VPN
    
    Returns:
        (returncode, list_of_findings)
    """
    try:
        nuclei_bin = "/opt/vpn/bin/nuclei"
        
        if not os.path.exists(nuclei_bin):
            print(f"❌ Nuclei not found at {nuclei_bin}")
            return -1, []
        
        # Создаём временный файл с целями
        input_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        for target in targets:
            input_file.write(f"{target}\n")
        input_file.close()
        
        cmd = [
            nuclei_bin,
            '-l', input_file.name,
            '-json',
            '-o', output_file,
            '-silent'
        ]
        
        # Добавляем templates
        if templates:
            for tmpl in templates:
                cmd.extend(['-t', tmpl])
        else:
            # По умолчанию ищем VPN
            cmd.extend(['-t', 'vpn/', '-t', 'cves/'])
        
        print(f"🎯 Running nuclei on {len(targets)} targets")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        # Удаляем временный файл
        try:
            os.remove(input_file.name)
        except:
            pass
        
        if result.returncode != 0:
            print(f"⚠️ Nuclei exited with code {result.returncode}")
        
        # Парсим результаты
        findings = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        findings.append(data)
                    except json.JSONDecodeError:
                        continue
        
        print(f"✅ Nuclei found {len(findings)} matches")
        
        return result.returncode, findings
        
    except subprocess.TimeoutExpired:
        print(f"⏰ Nuclei timeout")
        return -1, []
    except Exception as e:
        print(f"❌ Nuclei error: {e}")
        return -1, []


# ============================================
# FILTER VPN CANDIDATES
# ============================================

def filter_vpn_candidates(httpx_results: List[Dict]) -> List[str]:
    """
    Фильтрует потенциальные VPN из результатов httpx
    """
    VPN_KEYWORDS = [
        'vpn', 'fortigate', 'fortinet', 'anyconnect', 'cisco',
        'palo alto', 'globalprotect', 'sonicwall', 'pulse secure',
        'juniper', 'ssl-vpn', 'sslvpn', 'remote access'
    ]
    
    candidates = []
    
    for result in httpx_results:
        url = result.get('url', '')
        title = result.get('title', '').lower()
        tech = ' '.join(result.get('tech', [])).lower()
        
        # Проверяем keywords
        text = f"{title} {tech}"
        if any(keyword in text for keyword in VPN_KEYWORDS):
            candidates.append(url)
            print(f"  🎯 VPN candidate: {url} ({title})")
    
    return candidates


# ============================================
# EXTRACT VPN INFO FROM NUCLEI
# ============================================

def extract_vpn_info(nuclei_findings: List[Dict]) -> List[Dict]:
    """
    Извлекает информацию о VPN из результатов nuclei
    """
    vpns = []
    
    for finding in nuclei_findings:
        try:
            vpn_info = {
                'url': finding.get('host', finding.get('matched-at', '')),
                'template_id': finding.get('template-id', ''),
                'template_name': finding.get('info', {}).get('name', ''),
                'severity': finding.get('info', {}).get('severity', 'unknown'),
                'protocol': extract_protocol_from_template(finding.get('template-id', '')),
                'matched_at': finding.get('matched-at', ''),
            }
            
            if vpn_info['protocol']:
                vpns.append(vpn_info)
                print(f"  ✅ VPN detected: {vpn_info['url']} ({vpn_info['protocol']})")
        
        except Exception as e:
            print(f"  ⚠️ Failed to parse finding: {e}")
            continue
    
    return vpns


def extract_protocol_from_template(template_id: str) -> str:
    """
    Извлекает тип VPN из template ID
    """
    protocols = {
        'fortinet': 'Fortinet',
        'fortigate': 'Fortinet',
        'cisco': 'Cisco AnyConnect',
        'anyconnect': 'Cisco AnyConnect',
        'palo-alto': 'Palo Alto',
        'globalprotect': 'Palo Alto',
        'sonicwall': 'SonicWall',
        'pulse': 'Pulse Secure',
        'juniper': 'Pulse Secure',
        'openvpn': 'OpenVPN'
    }
    
    template_lower = template_id.lower()
    for keyword, protocol in protocols.items():
        if keyword in template_lower:
            return protocol
    
    return None
