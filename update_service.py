"""
Update-Prüfungsdienst für den Lizenzmanager.
Fragt die GitHub Releases API oder GitHub Commits API asynchron und gecacht ab,
um über neue Software-Releases und bereitstehende Docker-Container-Images zu informieren.
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


def get_installed_commit():
    """
    Ermittelt den Git-Commit-Hash der aktuell ausgeführten Version.
    Prüft Umgebungsvariablen, Docker-Build-Dateien und das lokale Git-Repository.
    """
    # 1. Aus Umgebungsvariable (Docker build arg oder .env)
    sha = os.environ.get('APP_COMMIT_SHA', '').strip()
    if sha and sha != 'dev':
        return sha[:7]

    # 2. Aus BUILD_COMMIT Datei (vom Dockerfile erzeugt)
    candidates = [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), 'BUILD_COMMIT'),
        os.path.join(os.getcwd(), 'BUILD_COMMIT'),
        '/app/BUILD_COMMIT'
    ]
    for p in candidates:
        if os.path.isfile(p):
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    c = f.read().strip()
                    if c and c != 'dev':
                        return c[:7]
            except Exception:
                pass

    # 3. Aus lokalem Git-Verzeichnis (Entwicklungsumgebung)
    try:
        import subprocess
        res = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'],
            cwd=os.path.dirname(os.path.abspath(__file__)),
            capture_output=True,
            text=True,
            timeout=2
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass

    return None


def check_for_updates(force=False, simulate=False):
    """
    Prüft, ob auf GitHub eine neuere Release-Version oder ein neues Docker-Image vorliegt.
    1. Prüft GitHub Releases.
    2. Falls keine Releases existieren, prüft Commits auf 'main' für Docker-Image-Aktualisierungen.
    Ergebnisse werden für 2 Stunden gecacht.
    """
    current_ver = getattr(config, 'APP_VERSION', '1.1.0')
    repo = getattr(config, 'APP_REPO', 'Speedy2524/lizenzmanager')
    installed_commit = get_installed_commit()

    if simulate:
        current_display = f"v{current_ver} ({installed_commit})" if installed_commit else f"v{current_ver}"
        return {
            'current_version': current_display,
            'latest_version': 'Build 9f2b8a1',
            'update_available': True,
            'update_type': 'commit',
            'release_name': 'Neuer Docker-Build bereit (9f2b8a1) - Test',
            'release_url': f'https://github.com/{repo}/commits/main',
            'release_notes': '• Simulierter neuer Docker-Build aus GitHub Actions (:latest)\n• Um das Update im Echtbetrieb anzuwenden: docker compose pull && docker compose up -d\n• Enthält neueste Fehlerkorrekturen und Optimierungen',
            'published_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'checked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            'current_commit': installed_commit or 'dev',
            'latest_commit': '9f2b8a1',
            'simulated': True,
            'error': None
        }

    now = time.time()
    if not force and _update_cache['data'] and (now - _update_cache['last_checked'] < CACHE_TTL_SECONDS):
        return _update_cache['data']

    current_display = f"v{current_ver} ({installed_commit})" if installed_commit else f"v{current_ver}"

    result = {
        'current_version': current_display,
        'latest_version': current_display,
        'update_available': False,
        'update_type': 'release',
        'release_name': '',
        'release_url': f'https://github.com/{repo}/releases',
        'release_notes': '',
        'published_at': None,
        'checked_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'current_commit': installed_commit,
        'latest_commit': installed_commit,
        'error': None
    }

    if not getattr(config, 'CHECK_FOR_UPDATES', True):
        result['disabled'] = True
        return result

    headers = {
        'User-Agent': f'Lizenzmanager/{current_ver}',
        'Accept': 'application/vnd.github.v3+json'
    }

    has_release = False

    # --------------------------------------------------------------------------
    # SCHRITT 1: GitHub Releases prüfen (falls formale Releases gepflegt werden)
    # --------------------------------------------------------------------------
    try:
        url_releases = f'https://api.github.com/repos/{repo}/releases/latest'
        req = urllib.request.Request(url_releases, headers=headers)
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            tag = data.get('tag_name', '').strip()
            if tag:
                has_release = True
                result['latest_version'] = tag
                result['release_name'] = data.get('name') or tag
                result['release_url'] = data.get('html_url') or result['release_url']
                result['release_notes'] = data.get('body') or ''
                result['published_at'] = data.get('published_at')

                if is_newer_version(tag, current_ver):
                    result['update_available'] = True
                    result['update_type'] = 'release'

    except urllib.error.HTTPError as e:
        if e.code != 404:
            logger.warning(f"GitHub API HTTP-Fehler bei Release-Prüfung: {e.code}")
    except Exception as e:
        logger.debug(f"Release-Prüfung übersprungen oder fehlgeschlagen: {e}")

    # --------------------------------------------------------------------------
    # SCHRITT 2: Fallback auf Commits auf 'main' (für automatische Docker :latest Builds)
    # --------------------------------------------------------------------------
    if not has_release or not result['update_available']:
        try:
            branch = getattr(config, 'APP_BRANCH', 'main')
            url_commits = f'https://api.github.com/repos/{repo}/commits/{branch}'
            req_c = urllib.request.Request(url_commits, headers=headers)
            with urllib.request.urlopen(req_c, timeout=3.5) as resp_c:
                c_data = json.loads(resp_c.read().decode('utf-8'))
                remote_sha = c_data.get('sha', '').strip()
                short_sha = remote_sha[:7] if remote_sha else ''
                c_info = c_data.get('commit', {})
                commit_msg = c_info.get('message', '').strip()
                commit_date = c_info.get('author', {}).get('date')

                result['latest_commit'] = short_sha

                if short_sha:
                    if installed_commit and short_sha.lower() != installed_commit.lower():
                        # Neuer Commit auf GitHub vorhanden -> Neues Docker-Image bereit!
                        result['update_available'] = True
                        result['update_type'] = 'commit'
                        result['latest_version'] = f"Build {short_sha}"
                        result['release_name'] = f"Neuer Docker-Build ({short_sha})"
                        result['release_notes'] = commit_msg
                        result['release_url'] = c_data.get('html_url') or f"https://github.com/{repo}/commit/{remote_sha}"
                        result['published_at'] = commit_date
                    elif installed_commit and short_sha.lower() == installed_commit.lower():
                        # Absolut aktuell
                        result['update_available'] = False
                        result['latest_version'] = current_display
                        result['release_name'] = 'Aktuellster Build'
                    else:
                        # Installierter Commit unbekannt
                        result['latest_version'] = f"Build {short_sha}"

        except urllib.error.HTTPError as e:
            logger.warning(f"GitHub API HTTP-Fehler bei Commit-Prüfung: {e.code}")
            result['error'] = f"GitHub API Status: {e.code}"
        except Exception as e:
            logger.warning(f"Commit-Prüfung fehlgeschlagen: {e}")
            result['error'] = str(e)

    _update_cache['last_checked'] = now
    _update_cache['data'] = result
    return result
