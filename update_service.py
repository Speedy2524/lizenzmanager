"""
Update-Prüfungsdienst für den Lizenzmanager.
Fragt die GitHub Releases API asynchron und gecacht ab, um über neue Versionen zu informieren.
"""

import os
import re
import time
import json
import logging
import urllib.request
import urllib.error
import config

logger = logging.getLogger('update_service')

_update_cache = {
    'last_checked': 0,
    'data': None
}

CACHE_TTL_SECONDS = 7200  # 2 Stunden Cache


def parse_version(v_str):
    """Parst Versionsstrings wie 'v1.2.3', '1.2.0' in ein numerisches Tupel (1, 2, 3)."""
    if not v_str:
        return (0, 0, 0)
    clean = re.sub(r'^[vV]', '', str(v_str).strip())
    parts = []
    for p in clean.split('.'):
        match = re.match(r'^\d+', p)
        if match:
            parts.append(int(match.group()))
        else:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def is_newer_version(latest_str, current_str):
    """Gibt True zurück, wenn latest_str echt neuer ist als current_str."""
    return parse_version(latest_str) > parse_version(current_str)


def check_for_updates(force=False, simulate=False):
    """
    Prüft, ob auf GitHub eine neuere Release-Version vorliegt.
    Ergebnisse werden gecacht, um API-Limits und Netzwerkverzögerungen zu vermeiden.
    """
    current_ver = getattr(config, 'APP_VERSION', '1.1.0')
    repo = getattr(config, 'APP_REPO', 'Speedy2524/lizenzmanager')

    if simulate:
        return {
            'current_version': current_ver,
            'latest_version': 'v1.2.0',
            'update_available': True,
            'release_name': 'Lizenzmanager v1.2.0 (Simuliertes Update)',
            'release_url': f'https://github.com/{repo}/releases',
            'release_notes': '• Neue Funktionen und Leistungsverbesserungen\n• Sicherheits- und Stabilitätsupdates\n• Aktualisierte Bibliotheken',
            'published_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'simulated': True,
            'error': None
        }

    now = time.time()
    if not force and _update_cache['data'] and (now - _update_cache['last_checked'] < CACHE_TTL_SECONDS):
        return _update_cache['data']

    result = {
        'current_version': current_ver,
        'latest_version': current_ver,
        'update_available': False,
        'release_name': '',
        'release_url': f'https://github.com/{repo}/releases',
        'release_notes': '',
        'published_at': None,
        'checked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'error': None
    }

    if not getattr(config, 'CHECK_FOR_UPDATES', True):
        result['disabled'] = True
        return result

    try:
        url = f'https://api.github.com/repos/{repo}/releases/latest'
        req = urllib.request.Request(url, headers={
            'User-Agent': f'Lizenzmanager/{current_ver}',
            'Accept': 'application/vnd.github.v3+json'
        })
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            tag = data.get('tag_name', '').strip()
            result['latest_version'] = tag or current_ver
            result['release_name'] = data.get('name') or tag
            result['release_url'] = data.get('html_url') or result['release_url']
            result['release_notes'] = data.get('body') or ''
            result['published_at'] = data.get('published_at')

            if tag and is_newer_version(tag, current_ver):
                result['update_available'] = True

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Noch kein formales Release angelegt -> aktuellste Version
            result['latest_version'] = current_ver
            result['update_available'] = False
        else:
            logger.warning(f"GitHub API HTTP-Fehler bei Update-Prüfung: {e.code}")
            result['error'] = f"GitHub API Status: {e.code}"
    except Exception as e:
        logger.warning(f"Update-Prüfung fehlgeschlagen: {e}")
        result['error'] = str(e)

    _update_cache['last_checked'] = now
    _update_cache['data'] = result
    return result
