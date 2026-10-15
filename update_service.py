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
import threading
import urllib.request
import urllib.error
import config

logger = logging.getLogger('update_service')

_cache_lock = threading.Lock()
_update_cache = {
    'last_checked': 0,
    'last_network_call': 0,
    'data': None
}

CACHE_TTL_SECONDS = 7200  # 2 Stunden regulärer Cache
MIN_NETWORK_INTERVAL_SECONDS = 30  # Mindestens 30 Sekunden Abstand zwischen externen GitHub-Anfragen (Schutz vor DoS & Rate-Limit-Erschöpfung)


def _get_safe_repo():
    """Validiert den konfigurierten Repository-Namen (Owner/Repo)."""
    repo = str(getattr(config, 'APP_REPO', 'Speedy2524/lizenzmanager')).strip()
    if not re.match(r'^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$', repo):
        return 'Speedy2524/lizenzmanager'
    return repo


def _get_safe_branch():
    """Validiert den konfigurierten Git-Branch."""
    branch = str(getattr(config, 'APP_BRANCH', 'main')).strip()
    if not re.match(r'^[a-zA-Z0-9_.-]+$', branch):
        return 'main'
    return branch


def _is_safe_github_url(url, repo):
    """Stellt sicher, dass die übermittelte Release-URL eine legitime GitHub-Adresse des Repositories ist."""
    if not url or not isinstance(url, str):
        return False
    clean = url.strip()
    expected_prefix = f'https://github.com/{repo}/'
    return clean.startswith(expected_prefix)


def parse_version(v_str):
    """Parst Versionsstrings wie 'v1.2.3', '1.2.0' in ein numerisches Tupel."""
    if not v_str:
        return (0, 0, 0, 0)
    clean = re.sub(r'^[vV]', '', str(v_str).strip())
    parts = []
    for p in clean.split('.'):
        match = re.match(r'^\d+', p)
        if match:
            parts.append(int(match.group()))
        else:
            parts.append(0)
    while len(parts) < 4:
        parts.append(0)
    return tuple(parts)


def is_newer_version(latest_str, current_str):
    """Gibt True zurück, wenn latest_str echt neuer ist als current_str."""
    return parse_version(latest_str) > parse_version(current_str)


def get_installed_commit():
    """
    Ermittelt den Git-Commit-Hash der aktuell ausgeführten Version.
    Prüft Umgebungsvariablen, Docker-Build-Dateien und das lokale Git-Repository.
    Gibt nur validierte Hexadezimal-Hashes zurück.
    """
    # 1. Aus Umgebungsvariable (Docker build arg oder .env)
    sha = os.environ.get('APP_COMMIT_SHA', '').strip()
    if sha and sha.lower() != 'dev' and re.match(r'^[a-fA-F0-9]{7,40}$', sha):
        return sha[:7].lower()

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
                    c = f.read(100).strip()
                    if c and c.lower() != 'dev' and re.match(r'^[a-fA-F0-9]{7,40}$', c):
                        return c[:7].lower()
            except Exception:
                pass

    # 3. Aus lokalem Git-Verzeichnis (Entwicklungsumgebung)
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        git_dir = os.path.join(base_dir, '.git')
        if os.path.exists(git_dir):
            import subprocess
            res = subprocess.run(
                ['git', 'rev-parse', '--short', 'HEAD'],
                cwd=base_dir,
                capture_output=True,
                text=True,
                timeout=2,
                shell=False
            )
            if res.returncode == 0 and res.stdout.strip():
                out = res.stdout.strip()
                if re.match(r'^[a-fA-F0-9]{7,40}$', out):
                    return out[:7].lower()
    except Exception:
        pass

    return None


def check_for_updates(force=False, simulate=False):
    """
    Prüft, ob auf GitHub eine neuere Release-Version oder ein neues Docker-Image vorliegt.
    1. Prüft GitHub Releases.
    2. Falls keine Releases existieren, prüft Commits auf 'main' für Docker-Image-Aktualisierungen.
    Ergebnisse werden threadsicher gecacht und gegen Rate-Limit-Überlastung abgesichert.
    """
    current_ver = getattr(config, 'APP_VERSION', '1.1.0')
    repo = _get_safe_repo()
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
    current_display = f"v{current_ver} ({installed_commit})" if installed_commit else f"v{current_ver}"

    with _cache_lock:
        # Cache-Prüfung: reguläre TTL (2 Std) oder Cooldown für force=True (30 Sek)
        if _update_cache['data']:
            if not force and (now - _update_cache['last_checked'] < CACHE_TTL_SECONDS):
                return _update_cache['data']
            if force and (now - _update_cache['last_network_call'] < MIN_NETWORK_INTERVAL_SECONDS):
                # Rate-Limit-Schutz: Zu häufige manuelle Klicks werden durch den Cache bedient
                return _update_cache['data']

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
    rate_limit_exceeded = False

    # --------------------------------------------------------------------------
    # SCHRITT 1: GitHub Releases prüfen (falls formale Releases gepflegt werden)
    # --------------------------------------------------------------------------
    try:
        url_releases = f'https://api.github.com/repos/{repo}/releases/latest'
        req = urllib.request.Request(url_releases, headers=headers)
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            tag = str(data.get('tag_name') or '').strip()
            if tag:
                has_release = True
                result['latest_version'] = tag[:50]
                result['release_name'] = str(data.get('name') or tag)[:150]
                raw_url = str(data.get('html_url') or '').strip()
                result['release_url'] = raw_url if _is_safe_github_url(raw_url, repo) else f'https://github.com/{repo}/releases'
                result['release_notes'] = str(data.get('body') or '')[:10000]
                result['published_at'] = str(data.get('published_at') or '')[:50] or None

                if is_newer_version(tag, current_ver):
                    result['update_available'] = True
                    result['update_type'] = 'release'

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Kein Release vorhanden
            pass
        elif e.code == 403:
            rate_limit_exceeded = True
            logger.warning(f"GitHub API Rate-Limit erreicht (HTTP 403): {e}")
            result['error'] = "GitHub API Rate-Limit erreicht (60 Anfragen/Std). Bitte später erneut versuchen."
        else:
            logger.warning(f"GitHub API HTTP-Fehler bei Release-Prüfung: {e.code}")
            result['error'] = f"GitHub API Status: {e.code}"
    except Exception as e:
        logger.debug(f"Release-Prüfung übersprungen oder fehlgeschlagen: {e}")

    # --------------------------------------------------------------------------
    # SCHRITT 2: Fallback auf Commits auf 'main' (für automatische Docker :latest Builds)
    # --------------------------------------------------------------------------
    if not rate_limit_exceeded and (not has_release or not result['update_available']):
        try:
            branch = _get_safe_branch()
            url_commits = f'https://api.github.com/repos/{repo}/commits/{branch}'
            req_c = urllib.request.Request(url_commits, headers=headers)
            with urllib.request.urlopen(req_c, timeout=3.5) as resp_c:
                c_data = json.loads(resp_c.read().decode('utf-8'))
                remote_sha = str(c_data.get('sha') or '').strip()
                short_sha = remote_sha[:7].lower() if remote_sha else ''
                c_info = c_data.get('commit') or {}
                commit_msg = str(c_info.get('message') or '').strip()[:1000]
                author_info = c_info.get('author') or {}
                commit_date = str(author_info.get('date') or '')[:50] or None

                if short_sha and re.match(r'^[a-fA-F0-9]{7,40}$', remote_sha):
                    result['latest_commit'] = short_sha
                    raw_c_url = str(c_data.get('html_url') or '').strip()
                    safe_c_url = raw_c_url if _is_safe_github_url(raw_c_url, repo) else f'https://github.com/{repo}/commit/{remote_sha}'

                    if installed_commit and short_sha != installed_commit.lower():
                        result['update_available'] = True
                        result['update_type'] = 'commit'
                        result['latest_version'] = f"Build {short_sha}"
                        result['release_name'] = f"Neuer Docker-Build ({short_sha})"
                        result['release_notes'] = commit_msg
                        result['release_url'] = safe_c_url
                        result['published_at'] = commit_date
                    elif installed_commit and short_sha == installed_commit.lower():
                        result['update_available'] = False
                        result['latest_version'] = current_display
                        result['release_name'] = 'Aktuellster Build'
                    else:
                        result['latest_version'] = f"Build {short_sha}"

        except urllib.error.HTTPError as e:
            if e.code == 403:
                logger.warning(f"GitHub API Rate-Limit bei Commit-Prüfung erreicht: {e.code}")
                result['error'] = "GitHub API Rate-Limit erreicht (60 Anfragen/Std). Bitte später erneut versuchen."
            else:
                logger.warning(f"GitHub API HTTP-Fehler bei Commit-Prüfung: {e.code}")
                result['error'] = f"GitHub API Status: {e.code}"
        except Exception as e:
            logger.warning(f"Commit-Prüfung fehlgeschlagen: {e}")
            result['error'] = str(e)

    with _cache_lock:
        _update_cache['last_checked'] = now
        _update_cache['last_network_call'] = now
        _update_cache['data'] = result

    return result
