#!/usr/bin/env python3
"""
Automatisierter Repository-Monitor & Security-Review- und Auto-Bugfix-Dienst für Lizenzmanager.
Überwacht https://github.com/Speedy2524/lizenzmanager auf neue Commits,
führt automatische Sicherheitsüberprüfungen (Static Analysis, Secrets, XSS, SQLi, Security Headers)
und Unit-Tests durch, behebt gefundene Schwachstellen automatisch und protokolliert alle Ergebnisse.
"""

import os
import sys
import time
import json
import logging
import argparse
import subprocess
import ast
import re
import atexit
import signal

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

LOG_FILE = os.path.join(DATA_DIR, 'security_audit.log')
REPORT_FILE = os.path.join(DATA_DIR, 'last_audit_report.json')
STATE_FILE = os.path.join(DATA_DIR, 'monitor_state.json')
PID_FILE = os.path.join(DATA_DIR, 'monitor.pid')

if sys.platform == 'win32' and hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('repo_monitor')


def is_pid_running(pid):
    """Prüft plattformübergreifend, ob ein Prozess mit gegebener PID existiert und aktiv ist."""
    if not pid or pid <= 0:
        return False
    if sys.platform == 'win32':
        try:
            import ctypes
            from ctypes import wintypes
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if handle:
                exit_code = wintypes.DWORD()
                success = ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                ctypes.windll.kernel32.CloseHandle(handle)
                # 259 is STILL_ACTIVE
                return bool(success and exit_code.value == 259)
            return False
        except Exception:
            return False
    else:
        try:
            os.kill(pid, 0)
            return True
        except (OSError, ProcessLookupError):
            return False


def acquire_daemon_lock(force=False):
    """Stellt sicher, dass nur eine Instanz des Monitor-Daemons aktiv ist."""
    if os.path.exists(PID_FILE):
        old_pid = None
        try:
            with open(PID_FILE, 'r', encoding='utf-8') as fp:
                old_pid = int(fp.read().strip())
        except (ValueError, OSError):
            old_pid = None

        if old_pid and is_pid_running(old_pid) and old_pid != os.getpid():
            if not force:
                logger.warning(f"Monitor-Daemon läuft bereits aktiv mit PID {old_pid}. Neuer Start abgebrochen (Single-Instance Protection).")
                return False
            logger.info(f"Übernehme Daemon-Lock von vorheriger PID {old_pid} (--force aktiviert)...")

    try:
        with open(PID_FILE, 'w', encoding='utf-8') as fp:
            fp.write(str(os.getpid()))
        return True
    except Exception as e:
        logger.error(f"Konnte PID-Datei nicht schreiben: {e}")
        return False


def release_daemon_lock():
    """Entfernt die PID-Datei bei Beendigung des Daemons."""
    try:
        if os.path.exists(PID_FILE):
            with open(PID_FILE, 'r', encoding='utf-8') as fp:
                saved_pid = int(fp.read().strip())
            if saved_pid == os.getpid():
                os.remove(PID_FILE)
    except Exception:
        pass


def stop_running_daemon():
    """Beendet einen laufenden Monitor-Daemon anhand der PID-Datei."""
    if not os.path.exists(PID_FILE):
        logger.info("Keine aktive PID-Datei gefunden. Kein Monitor-Daemon aktiv.")
        return True
    try:
        with open(PID_FILE, 'r', encoding='utf-8') as fp:
            pid = int(fp.read().strip())
    except Exception:
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        return True

    if not is_pid_running(pid):
        logger.info(f"Prozess mit PID {pid} läuft nicht mehr. Entferne verwaiste PID-Datei.")
        try:
            os.remove(PID_FILE)
        except OSError:
            pass
        return True

    logger.info(f"Beende laufenden Monitor-Daemon (PID {pid})...")
    if sys.platform == 'win32':
        subprocess.run(['taskkill', '/F', '/PID', str(pid)], capture_output=True)
    else:
        try:
            os.kill(pid, signal.SIGTERM)
        except Exception:
            pass

    time.sleep(1)
    if is_pid_running(pid):
        logger.warning(f"Prozess {pid} konnte nicht beendet werden.")
        return False
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except OSError:
        pass
    logger.info("Monitor-Daemon erfolgreich beendet.")
    return True


def cleanup_stale_git_locks(max_age_seconds=60):
    """Entfernt verwaiste Git-Lockdateien (.git/*.lock), wenn sie älter als max_age_seconds sind."""
    git_dir = os.path.join(BASE_DIR, '.git')
    if not os.path.isdir(git_dir):
        return
    now = time.time()
    for fname in ('index.lock', 'FETCH_HEAD.lock', 'HEAD.lock', 'config.lock'):
        lock_path = os.path.join(git_dir, fname)
        if os.path.exists(lock_path):
            try:
                mtime = os.path.getmtime(lock_path)
                if now - mtime > max_age_seconds:
                    os.remove(lock_path)
                    logger.warning(f"Verwaiste Git-Lockdatei entfernt: {fname} (Alter: {round(now - mtime)}s)")
            except Exception as e:
                logger.warning(f"Konnte Git-Lockdatei {fname} nicht entfernen: {e}")


def run_cmd(cmd_list, timeout=45):
    """Führt einen Subprozess-Befehl sicher aus."""
    cleanup_stale_git_locks()
    try:
        res = subprocess.run(
            cmd_list,
            cwd=BASE_DIR,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return res.returncode == 0, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        return False, '', str(e)


def get_current_local_commit():
    """Ermittelt den aktuellen lokalen Commit-Hash."""
    ok, out, _ = run_cmd(['git', 'rev-parse', 'HEAD'])
    return out[:7].lower() if ok and out else None


def fetch_remote_latest_commit():
    """Prüft remote auf origin/main den neuesten Commit."""
    ok, _, err = run_cmd(['git', 'fetch', 'origin', 'main'])
    if not ok:
        logger.warning(f"git fetch fehlgeschlagen: {err}")
        return None

    ok, out, _ = run_cmd(['git', 'rev-parse', 'origin/main'])
    return out[:7].lower() if ok and out else None


def load_state():
    """Lädt den zuletzt bekannten Commit-Stand."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {'last_reviewed_commit': None, 'last_checked_at': None}


def save_state(state):
    """Speichert den aktuellen Monitor-Stand."""
    try:
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        logger.error(f"Konnte Status nicht speichern: {e}")


# ==============================================================================
# AUDIT-ROUTINEN (SICHERHEITS- & CODE-QUALITÄTSPRÜFUNG)
# ==============================================================================

def audit_python_syntax():
    """Prüft alle Python-Dateien auf syntaktische Korrektheit mittels AST."""
    issues = []
    py_files = []
    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv')):
            continue
        for f in files:
            if f.endswith('.py'):
                py_files.append(os.path.join(root, f))

    for p in py_files:
        rel = os.path.relpath(p, BASE_DIR)
        try:
            with open(p, 'r', encoding='utf-8') as fp:
                code = fp.read()
            ast.parse(code, filename=rel)
        except SyntaxError as se:
            issues.append({
                'type': 'SyntaxError',
                'file': rel,
                'line': se.lineno,
                'message': str(se.msg)
            })
        except Exception as ex:
            issues.append({
                'type': 'ParseError',
                'file': rel,
                'message': str(ex)
            })
    return issues


def audit_hardcoded_secrets():
    """Sucht nach versehentlich fest im Code hinterlegten Passwörtern oder API-Keys."""
    issues = []
    secret_patterns = [
        (r'(?i)(?:api_key|secret_key|password)\s*=\s*["\'][a-zA-Z0-9_\-\.]{20,}["\']', 'Potentieller hardcoded API-Key/Secret'),
        (r'-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----', 'Privater kryptographischer Schlüssel im Repository'),
        (r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}', 'Exponierter GitHub Personal/OAuth/Server Token'),
        (r'github_pat_[a-zA-Z0-9_]{82}', 'Exponierter GitHub Fine-Grained Personal Access Token'),
        (r'sk-[a-zA-Z0-9]{32,}', 'Exponierter OpenAI API-Schlüssel'),
        (r'AKIA[0-9A-Z]{16}', 'Exponierter AWS Access Key ID'),
        (r'xox[baprs]-[0-9a-zA-Z]{10,48}', 'Exponierter Slack Token'),
        (r'(?:postgres|mysql|mongodb|redis):\/\/[a-zA-Z0-9_-]+:[^@\s]+@[a-zA-Z0-9_\.-]+', 'Exponierte Datenbank-Verbindung mit Passwort')
    ]

    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'data', 'tests')):
            continue
        for f in files:
            if f.endswith(('.py', '.js', '.html', '.env.example')):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8', errors='ignore') as fp:
                        for line_idx, line in enumerate(fp, 1):
                            for pattern, desc in secret_patterns:
                                if re.search(pattern, line):
                                    # Ausnahme: config.py Standard-Platzhalter
                                    if 'lizenzmanager-super-secret-key-change-in-production' in line:
                                        continue
                                    issues.append({
                                        'type': 'SecretExposure',
                                        'file': rel,
                                        'line': line_idx,
                                        'message': desc
                                    })
                except Exception:
                    pass
    return issues


def audit_dom_xss():
    """Prüft JS-Dateien auf ungeschützte innerHTML-Zuweisungen von Datenfeldern."""
    issues = []
    js_files = []
    static_dir = os.path.join(BASE_DIR, 'static')
    if not os.path.exists(static_dir):
        return issues

    for root, _, files in os.walk(static_dir):
        for f in files:
            if f.endswith('.js') and not f.endswith('.min.js'):
                js_files.append(os.path.join(root, f))

    for p in js_files:
        rel = os.path.relpath(p, BASE_DIR)
        with open(p, 'r', encoding='utf-8', errors='ignore') as fp:
            for line_idx, line in enumerate(fp, 1):
                # Prüfe ob `${lic.` ohne escapeHtml verwendet wird
                matches = re.finditer(r'\$\{(lic\.[a-zA-Z0-9_]+)\}', line)
                for m in matches:
                    var_name = m.group(1)
                    if 'escapeHtml' not in line and 'format' not in line and 'sanitize' not in line:
                        # Ausnahmen: IDs und rein numerische Variablen
                        if not any(safe_attr in var_name for safe_attr in ('id', 'seats_used', 'seats_total', 'cost', 'billing_cycle_months')):
                            issues.append({
                                'type': 'UnescapedDOMProperty',
                                'file': rel,
                                'line': line_idx,
                                'target': var_name,
                                'message': f"Mögliche XSS-Schwachstelle: {var_name} wird ohne escapeHtml() gerendert"
                            })
    return issues


def audit_sql_injection():
    """Prüft Python-Dateien auf potentielle SQL-Injection durch dynamische String-Formatierung in Queries."""
    issues = []
    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'tests', 'scripts')):
            continue
        for f in files:
            if f.endswith('.py'):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8') as fp:
                        content = fp.read()
                    lines = content.splitlines()
                    tree = ast.parse(content, filename=rel)
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Call):
                            if isinstance(node.func, ast.Attribute) and node.func.attr in ('execute', 'executemany'):
                                if node.args:
                                    first_arg = node.args[0]
                                    is_vuln = False
                                    desc = ""
                                    if isinstance(first_arg, ast.JoinedStr):
                                        is_vuln = True
                                        desc = "f-string Formatierung in execute"
                                    elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Mod):
                                        is_vuln = True
                                        desc = "%-Formatierung in execute"
                                    elif isinstance(first_arg, ast.BinOp) and isinstance(first_arg.op, ast.Add):
                                        is_vuln = True
                                        desc = "String-Konkatenation (+) in execute"
                                    elif isinstance(first_arg, ast.Call) and isinstance(first_arg.func, ast.Attribute) and first_arg.func.attr == 'format':
                                        is_vuln = True
                                        desc = ".format() Formatierung in execute"

                                    if is_vuln:
                                        line_no = getattr(node, 'lineno', 1)
                                        line_src = lines[line_no - 1] if 1 <= line_no <= len(lines) else ""
                                        # Erlaube sichere statische ALTER TABLE Spalten-Migrationen
                                        if 'ALTER TABLE' in line_src and any(col in line_src for col in ('col_name', 'billing_cycle_months')):
                                            continue
                                        issues.append({
                                            'type': 'PotentialSQLInjection',
                                            'file': rel,
                                            'line': line_no,
                                            'message': f"Potentiell unsichere dynamische SQL-Abfrage ({desc}): {line_src.strip()[:60]}..."
                                        })
                except Exception:
                    pass
    return issues


def audit_security_headers():
    """Prüft, ob essentielle Sicherheits-Header in app.py konfiguriert sind."""
    issues = []
    app_path = os.path.join(BASE_DIR, 'app.py')
    if not os.path.exists(app_path):
        return issues

    with open(app_path, 'r', encoding='utf-8') as f:
        content = f.read()

    required_headers = [
        ('X-Content-Type-Options', 'nosniff'),
        ('X-Frame-Options', 'SAMEORIGIN'),
        ('Referrer-Policy', 'strict-origin-when-cross-origin')
    ]

    for header, val in required_headers:
        if header not in content:
            issues.append({
                'type': 'MissingSecurityHeader',
                'file': 'app.py',
                'header': header,
                'value': val,
                'message': f"Sicherheits-Header '{header}' fehlt in app.py"
            })
    return issues


def audit_session_security():
    """Prüft Cookie-Sicherheitsflags in app.py."""
    issues = []
    app_path = os.path.join(BASE_DIR, 'app.py')
    if not os.path.exists(app_path):
        return issues

    with open(app_path, 'r', encoding='utf-8') as f:
        content = f.read()

    if "SESSION_COOKIE_HTTPONLY" not in content:
        issues.append({
            'type': 'InsecureCookieConfig',
            'file': 'app.py',
            'message': "SESSION_COOKIE_HTTPONLY ist nicht konfiguriert"
        })
    if "SESSION_COOKIE_SAMESITE" not in content:
        issues.append({
            'type': 'InsecureCookieConfig',
            'file': 'app.py',
            'message': "SESSION_COOKIE_SAMESITE ist nicht konfiguriert"
        })
    return issues


def audit_debug_mode():
    """Prüft, ob Flask app.run versehentlich mit debug=True gestartet wird."""
    issues = []
    app_path = os.path.join(BASE_DIR, 'app.py')
    if not os.path.exists(app_path):
        return issues

    try:
        with open(app_path, 'r', encoding='utf-8') as f:
            content = f.read()

        for idx, line in enumerate(content.splitlines(), 1):
            if 'app.run(' in line and re.search(r'debug\s*=\s*True', line):
                issues.append({
                    'type': 'DebugModeEnabled',
                    'file': 'app.py',
                    'line': idx,
                    'message': "app.run() hat debug=True aktiviert. Dies ermöglicht im Fehlerfall interaktive Remote Code Execution."
                })
    except Exception:
        pass
    return issues


def audit_jinja_templates():
    """Prüft Jinja2-Templates auf ungeschützte HTML-Filter wie | safe."""
    issues = []
    tpl_dir = os.path.join(BASE_DIR, 'templates')
    if not os.path.exists(tpl_dir):
        return issues

    for root, _, files in os.walk(tpl_dir):
        for f in files:
            if f.endswith('.html'):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8', errors='ignore') as fp:
                        for line_idx, line in enumerate(fp, 1):
                            if re.search(r'\{\{.*?\|\s*safe\s*\}\}', line):
                                issues.append({
                                    'type': 'PotentiallyUnsafeJinjaFilter',
                                    'file': rel,
                                    'line': line_idx,
                                    'message': f"Verwendung des Jinja-Filters '| safe' kann zu Cross-Site Scripting (XSS) führen: {line.strip()[:60]}"
                                })
                except Exception:
                    pass
    return issues


def audit_dangerous_functions():
    """Prüft auf unsichere Funktionen wie eval(), exec(), unsichere Deserialisierung (pickle) oder shell=True."""
    issues = []
    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'tests', 'scripts')):
            continue
        for f in files:
            if f.endswith('.py'):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8') as fp:
                        for line_idx, line in enumerate(fp, 1):
                            stripped = line.strip()
                            if stripped.startswith('#'):
                                continue
                            if re.search(r'(?<!ast\.)\beval\s*\(', line):
                                issues.append({
                                    'type': 'DangerousFunctionCall',
                                    'file': rel,
                                    'line': line_idx,
                                    'message': f"Gefährliche Verwendung von eval(): {stripped[:60]}"
                                })
                            elif re.search(r'\bexec\s*\(', line):
                                issues.append({
                                    'type': 'DangerousFunctionCall',
                                    'file': rel,
                                    'line': line_idx,
                                    'message': f"Gefährliche Verwendung von exec(): {stripped[:60]}"
                                })
                            elif re.search(r'\bpickle\.(?:loads|load)\s*\(', line):
                                issues.append({
                                    'type': 'DangerousDeserialization',
                                    'file': rel,
                                    'line': line_idx,
                                    'message': f"Unsichere Deserialisierung mit pickle: {stripped[:60]}"
                                })
                            elif re.search(r'subprocess\.[a-zA-Z0-9_]+\(.*shell\s*=\s*True', line) or (re.search(r'shell\s*=\s*True', line) and 'subprocess' in line):
                                issues.append({
                                    'type': 'DangerousSubprocessShell',
                                    'file': rel,
                                    'line': line_idx,
                                    'message': f"subprocess mit shell=True kann zu Command Injection führen: {stripped[:60]}"
                                })
                except Exception:
                    pass
    return issues


def audit_insecure_ssl():
    """Prüft auf unsichere oder deaktivierte SSL/TLS-Zertifikatsvalidierung."""
    issues = []
    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'tests', 'scripts')):
            continue
        for f in files:
            if f.endswith('.py'):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8') as fp:
                        for line_idx, line in enumerate(fp, 1):
                            stripped = line.strip()
                            if stripped.startswith('#'):
                                continue
                            if (re.search(r'_create_unverified_context', line) or
                                re.search(r'\bCERT_NONE\b', line) or
                                re.search(r'check_hostname\s*=\s*False', line) or
                                re.search(r'verify\s*=\s*False', line)):
                                issues.append({
                                    'type': 'InsecureSSLConfiguration',
                                    'file': rel,
                                    'line': line_idx,
                                    'message': f"Deaktivierte oder unsichere SSL/TLS-Validierung: {stripped[:60]}"
                                })
                except Exception:
                    pass
    return issues


def audit_open_redirect():
    """Prüft auf ungeprüfte Weiterleitungen mit request.args/form (Open Redirect)."""
    issues = []
    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'tests', 'scripts')):
            continue
        for f in files:
            if f.endswith('.py'):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8') as fp:
                        for line_idx, line in enumerate(fp, 1):
                            stripped = line.strip()
                            if stripped.startswith('#'):
                                continue
                            if re.search(r'redirect\s*\(\s*request\.(?:args|form|values)\.get\(', line):
                                if 'is_safe_url' not in line:
                                    issues.append({
                                        'type': 'PotentialOpenRedirect',
                                        'file': rel,
                                        'line': line_idx,
                                        'message': f"Mögliche Open-Redirect Schwachstelle ohne is_safe_url-Prüfung: {stripped[:60]}"
                                    })
                except Exception:
                    pass
    return issues


def audit_unsafe_yaml_load():
    """Prüft auf unsichere PyYAML-Verwendung (yaml.load ohne SafeLoader oder Loader=Loader)."""
    issues = []
    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'tests', 'scripts')):
            continue
        for f in files:
            if f.endswith('.py'):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8') as fp:
                        for line_idx, line in enumerate(fp, 1):
                            stripped = line.strip()
                            if stripped.startswith('#'):
                                continue
                            if re.search(r'\byaml\.load\s*\(', line):
                                if 'SafeLoader' not in line and 'CSafeLoader' not in line:
                                    issues.append({
                                        'type': 'UnsafeYamlLoad',
                                        'file': rel,
                                        'line': line_idx,
                                        'message': f"Unsichere Verwendung von yaml.load() ohne SafeLoader: {stripped[:60]}"
                                    })
                except Exception:
                    pass
    return issues


def audit_path_traversal():
    """Prüft auf potentielle Path-Traversal-Schwachstellen bei Dateizugriffen."""
    issues = []
    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'tests', 'scripts')):
            continue
        for f in files:
            if f.endswith('.py'):
                p = os.path.join(root, f)
                rel = os.path.relpath(p, BASE_DIR)
                try:
                    with open(p, 'r', encoding='utf-8') as fp:
                        for line_idx, line in enumerate(fp, 1):
                            stripped = line.strip()
                            if stripped.startswith('#'):
                                continue
                            if re.search(r'send_file\s*\(.*request\.(?:args|form|values)\.get\(', line):
                                if 'secure_filename' not in line and 'commonpath' not in line:
                                    issues.append({
                                        'type': 'PotentialPathTraversal',
                                        'file': rel,
                                        'line': line_idx,
                                        'message': f"Potentielles Path Traversal in send_file() mit ungefiltertem Parameter: {stripped[:60]}"
                                    })
                            elif re.search(r'open\s*\(.*os\.path\.join\(.*request\.(?:args|form|values)\.get\(', line):
                                if 'secure_filename' not in line and 'commonpath' not in line:
                                    issues.append({
                                        'type': 'PotentialPathTraversal',
                                        'file': rel,
                                        'line': line_idx,
                                        'message': f"Potentielles Path Traversal in open(os.path.join(...)): {stripped[:60]}"
                                    })
                except Exception:
                    pass
    return issues


def run_unit_tests():
    """Führt die Test-Suite aus."""
    ok, out, err = run_cmd([sys.executable, '-m', 'unittest', 'discover', 'tests'])
    return {
        'success': ok,
        'output': out or err
    }


# ==============================================================================
# AUTOMATISIERTE REPARATUR / BUGFIX-ROUTINEN (AUTO-REMEDIATION)
# ==============================================================================

def auto_remediate_issues(issues):
    """
    Führt automatische Codekorrekturen für bekannte Sicherheitsbefunde durch.
    Gibt die Anzahl der vorgenommenen Korrekturen und eine Aktionsliste zurück.
    """
    remediations = []

    # 1. Behebe DOM-XSS-Befunde in JS-Dateien
    xss_issues = [i for i in issues if i.get('type') == 'UnescapedDOMProperty']
    files_to_fix = {}
    for iss in xss_issues:
        rel = iss.get('file')
        if rel not in files_to_fix:
            files_to_fix[rel] = []
        files_to_fix[rel].append(iss)

    for rel, file_issues in files_to_fix.items():
        abs_path = os.path.join(BASE_DIR, rel)
        if not os.path.exists(abs_path):
            continue
        try:
            with open(abs_path, 'r', encoding='utf-8') as fp:
                lines = fp.readlines()

            modified = False
            for iss in file_issues:
                line_no = iss.get('line')
                var_name = iss.get('target')
                if line_no and 1 <= line_no <= len(lines) and var_name:
                    original = lines[line_no - 1]
                    # Ersetze ${lic.xyz} durch ${escapeHtml(lic.xyz)} falls noch nicht escaped
                    pattern = r'\$\{' + re.escape(var_name) + r'\}'
                    replacement = r'${escapeHtml(' + var_name + r')}'
                    new_line = re.sub(pattern, replacement, original)
                    if new_line != original:
                        lines[line_no - 1] = new_line
                        modified = True
                        remediations.append(f"XSS Sanitized: {rel}:{line_no} ({var_name} -> escapeHtml)")

            if modified:
                with open(abs_path, 'w', encoding='utf-8') as fp:
                    fp.writelines(lines)
                logger.info(f"Auto-Fix angewendet auf {rel}: DOM XSS Variablen geschützt.")
        except Exception as e:
            logger.error(f"Fehler bei Auto-Fix für {rel}: {e}")

    # 2. Behebe fehlende Security Headers in app.py
    header_issues = [i for i in issues if i.get('type') == 'MissingSecurityHeader']
    if header_issues:
        app_path = os.path.join(BASE_DIR, 'app.py')
        try:
            with open(app_path, 'r', encoding='utf-8') as fp:
                app_content = fp.read()

            if '@app.after_request' not in app_content:
                header_func = (
                    "\n@app.after_request\n"
                    "def set_security_headers(response):\n"
                    "    response.headers['X-Content-Type-Options'] = 'nosniff'\n"
                    "    response.headers['X-Frame-Options'] = 'SAMEORIGIN'\n"
                    "    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'\n"
                    "    return response\n"
                )
                target_str = "database.init_db()\n"
                if target_str in app_content:
                    app_content = app_content.replace(target_str, target_str + header_func, 1)
                else:
                    app_content = app_content + header_func

                with open(app_path, 'w', encoding='utf-8') as fp:
                    fp.write(app_content)
                remediations.append("Security Headers: @app.after_request in app.py hinzugefügt")
                logger.info("Auto-Fix angewendet auf app.py: Fehlende Sicherheits-Header ergänzt.")
        except Exception as e:
            logger.error(f"Fehler bei Header-Auto-Fix in app.py: {e}")

    # 3. Behebe Cookie-Sicherheitsflags
    cookie_issues = [i for i in issues if i.get('type') == 'InsecureCookieConfig']
    if cookie_issues:
        app_path = os.path.join(BASE_DIR, 'app.py')
        try:
            with open(app_path, 'r', encoding='utf-8') as fp:
                app_content = fp.read()

            insert_block = ""
            if "SESSION_COOKIE_HTTPONLY" not in app_content:
                insert_block += "app.config['SESSION_COOKIE_HTTPONLY'] = True\n"
            if "SESSION_COOKIE_SAMESITE" not in app_content:
                insert_block += "app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'\n"

            if insert_block and "app.secret_key" in app_content:
                app_content = app_content.replace("app.secret_key = config.SECRET_KEY\n", "app.secret_key = config.SECRET_KEY\n" + insert_block)
                with open(app_path, 'w', encoding='utf-8') as fp:
                    fp.write(app_content)
                remediations.append("Cookie Security: SESSION_COOKIE HTTPOnly/SameSite Flags gesetzt")
                logger.info("Auto-Fix angewendet auf app.py: Session-Cookie-Flags ergänzt.")
        except Exception as e:
            logger.error(f"Fehler bei Cookie-Auto-Fix: {e}")

    # 4. Behebe versehentliches debug=True in app.py
    debug_issues = [i for i in issues if i.get('type') == 'DebugModeEnabled']
    if debug_issues:
        app_path = os.path.join(BASE_DIR, 'app.py')
        try:
            with open(app_path, 'r', encoding='utf-8') as fp:
                app_content = fp.read()
            new_content = re.sub(r'debug\s*=\s*True', 'debug=False', app_content)
            if new_content != app_content:
                with open(app_path, 'w', encoding='utf-8') as fp:
                    fp.write(new_content)
                remediations.append("Security Fix: debug=True in app.py zu debug=False korrigiert")
                logger.info("Auto-Fix angewendet auf app.py: debug=True zu debug=False geändert.")
        except Exception as e:
            logger.error(f"Fehler bei Debug-Mode-Auto-Fix: {e}")

    # 5. Behebe versehentliche '| safe' Filter in Jinja-Templates
    template_issues = [i for i in issues if i.get('type') == 'PotentiallyUnsafeJinjaFilter']
    tpl_files_to_fix = {}
    for iss in template_issues:
        rel = iss.get('file')
        if rel not in tpl_files_to_fix:
            tpl_files_to_fix[rel] = []
        tpl_files_to_fix[rel].append(iss)

    for rel, f_issues in tpl_files_to_fix.items():
        abs_p = os.path.join(BASE_DIR, rel)
        if not os.path.exists(abs_p):
            continue
        try:
            with open(abs_p, 'r', encoding='utf-8') as fp:
                lines = fp.readlines()
            modified = False
            for iss in f_issues:
                line_no = iss.get('line')
                if line_no and 1 <= line_no <= len(lines):
                    orig = lines[line_no - 1]
                    new_l = re.sub(r'(\|\s*safe\b)', '', orig)
                    if new_l != orig:
                        lines[line_no - 1] = new_l
                        modified = True
                        remediations.append(f"Template XSS Sanitized: {rel}:{line_no} (| safe Filter entfernt)")
            if modified:
                with open(abs_p, 'w', encoding='utf-8') as fp:
                    fp.writelines(lines)
                logger.info(f"Auto-Fix angewendet auf {rel}: '| safe' Filter entfernt.")
        except Exception as e:
            logger.error(f"Fehler bei Template-Auto-Fix für {rel}: {e}")

    # 6. Behebe verify=False oder check_hostname=False
    ssl_issues = [i for i in issues if i.get('type') == 'InsecureSSLConfiguration']
    ssl_files_to_fix = {}
    for iss in ssl_issues:
        rel = iss.get('file')
        if rel not in ssl_files_to_fix:
            ssl_files_to_fix[rel] = []
        ssl_files_to_fix[rel].append(iss)

    for rel, f_issues in ssl_files_to_fix.items():
        abs_p = os.path.join(BASE_DIR, rel)
        if not os.path.exists(abs_p):
            continue
        try:
            with open(abs_p, 'r', encoding='utf-8') as fp:
                lines = fp.readlines()
            modified = False
            for iss in f_issues:
                line_no = iss.get('line')
                if line_no and 1 <= line_no <= len(lines):
                    orig = lines[line_no - 1]
                    new_l = re.sub(r'verify\s*=\s*False', 'verify=True', orig)
                    new_l = re.sub(r'check_hostname\s*=\s*False', 'check_hostname = True', new_l)
                    if new_l != orig:
                        lines[line_no - 1] = new_l
                        modified = True
                        remediations.append(f"SSL Fix: {rel}:{line_no} (SSL-Validierung reaktiviert)")
            if modified:
                with open(abs_p, 'w', encoding='utf-8') as fp:
                    fp.writelines(lines)
                logger.info(f"Auto-Fix angewendet auf {rel}: SSL-Validierung reaktiviert.")
        except Exception as e:
            logger.error(f"Fehler bei SSL-Auto-Fix für {rel}: {e}")

    # 7. Behebe unsichere yaml.load-Aufrufe
    yaml_issues = [i for i in issues if i.get('type') == 'UnsafeYamlLoad']
    yaml_files_to_fix = {}
    for iss in yaml_issues:
        rel = iss.get('file')
        if rel not in yaml_files_to_fix:
            yaml_files_to_fix[rel] = []
        yaml_files_to_fix[rel].append(iss)

    for rel, f_issues in yaml_files_to_fix.items():
        abs_p = os.path.join(BASE_DIR, rel)
        if not os.path.exists(abs_p):
            continue
        try:
            with open(abs_p, 'r', encoding='utf-8') as fp:
                lines = fp.readlines()
            modified = False
            for iss in f_issues:
                line_no = iss.get('line')
                if line_no and 1 <= line_no <= len(lines):
                    orig = lines[line_no - 1]
                    new_l = re.sub(r'\byaml\.load\s*\(', 'yaml.safe_load(', orig)
                    new_l = re.sub(r',\s*Loader\s*=\s*(?:yaml\.)?(?:UnsafeLoader|FullLoader|Loader)', '', new_l)
                    if new_l != orig:
                        lines[line_no - 1] = new_l
                        modified = True
                        remediations.append(f"YAML Deserialization Fix: {rel}:{line_no} (yaml.load -> yaml.safe_load)")
            if modified:
                with open(abs_p, 'w', encoding='utf-8') as fp:
                    fp.writelines(lines)
                logger.info(f"Auto-Fix angewendet auf {rel}: yaml.safe_load verwendet.")
        except Exception as e:
            logger.error(f"Fehler bei YAML-Auto-Fix für {rel}: {e}")

    return remediations


def commit_and_push_fixes(remediations, commit_sha):
    """Übernimmt Reparaturen per Git Commit & Push, sofern alle Tests bestehen."""
    ok, status_out, _ = run_cmd(['git', 'status', '--porcelain'])
    if not ok or not status_out.strip():
        logger.info("Keine geänderten Dateien für Commit vorhanden.")
        return False, None

    logger.info("Führe Unit-Tests zur Verifikation der automatischen Reparatur aus...")
    test_result = run_unit_tests()
    if not test_result['success']:
        logger.error("Tests nach Auto-Fix fehlgeschlagen! Mache Änderungen rückgängig (Rollback)...")
        run_cmd(['git', 'checkout', '--', '.'])
        return False, "Unit-Tests nach Remediation fehlgeschlagen - Rollback durchgeführt."

    # Erstelle Commit
    run_cmd(['git', 'add', '-u'])
    commit_msg = f"fix(security): auto-remediate security issues and bugs\n\nAutomated fixes for {commit_sha}:\n" + "\n".join(f"- {r}" for r in remediations)
    ok_commit, commit_out, commit_err = run_cmd(['git', 'commit', '-m', commit_msg])
    if not ok_commit:
        logger.error(f"git commit fehlgeschlagen: {commit_err}")
        return False, commit_err

    # Push auf origin main
    logger.info("Pushe automatisierte Sicherheits- und Bugfixes auf origin/main...")
    ok_push, push_out, push_err = run_cmd(['git', 'push', 'origin', 'main'])
    if not ok_push:
        logger.warning(f"Direkter git push fehlgeschlagen ({push_err}). Versuche Rebase...")
        ok_reb, _, _ = run_cmd(['git', 'pull', '--rebase', 'origin', 'main'])
        if ok_reb:
            ok_push, push_out, push_err = run_cmd(['git', 'push', 'origin', 'main'])
        if not ok_push:
            logger.error(f"git push fehlgeschlagen: {push_err}")
            return False, f"Commit erstellt, aber Push fehlgeschlagen: {push_err}"

    new_commit = get_current_local_commit()
    logger.info(f"✅ Sicherheits-Fixes erfolgreich gepusht: {new_commit}")
    return True, new_commit


# ==============================================================================
# HAUPT-PRÜFLOGIK & REPOSITORY-ÜBERWACHUNG
# ==============================================================================

def perform_full_security_review(commit_sha, auto_fix=True, auto_push=True):
    """Führt eine vollständige Sicherheitsanalyse, Auto-Remediation und Testsuite aus."""
    logger.info(f"Starte automatisierte Sicherheitsprüfung für Commit: {commit_sha}...")
    start_time = time.time()

    syntax_issues = audit_python_syntax()
    secret_issues = audit_hardcoded_secrets()
    xss_issues = audit_dom_xss()
    sql_issues = audit_sql_injection()
    header_issues = audit_security_headers()
    cookie_issues = audit_session_security()
    debug_issues = audit_debug_mode()
    template_issues = audit_jinja_templates()
    dangerous_issues = audit_dangerous_functions()
    ssl_issues = audit_insecure_ssl()
    redirect_issues = audit_open_redirect()
    yaml_issues = audit_unsafe_yaml_load()
    path_issues = audit_path_traversal()

    all_issues = syntax_issues + secret_issues + xss_issues + sql_issues + header_issues + cookie_issues + debug_issues + template_issues + dangerous_issues + ssl_issues + redirect_issues + yaml_issues + path_issues
    test_result = run_unit_tests()

    remediations = []
    pushed_commit = None

    # Falls Schwachstellen gefunden wurden und Auto-Fix aktiviert ist:
    if all_issues and auto_fix:
        logger.warning(f"Gefundene Schwachstellen ({len(all_issues)}). Starte automatische Fehlerbehebung (Auto-Remediation)...")
        remediations = auto_remediate_issues(all_issues)
        if remediations:
            # Erneute Prüfung nach Fehlerbehebung
            syntax_issues = audit_python_syntax()
            secret_issues = audit_hardcoded_secrets()
            xss_issues = audit_dom_xss()
            sql_issues = audit_sql_injection()
            header_issues = audit_security_headers()
            cookie_issues = audit_session_security()
            debug_issues = audit_debug_mode()
            template_issues = audit_jinja_templates()
            dangerous_issues = audit_dangerous_functions()
            ssl_issues = audit_insecure_ssl()
            redirect_issues = audit_open_redirect()
            yaml_issues = audit_unsafe_yaml_load()
            path_issues = audit_path_traversal()
            all_issues = syntax_issues + secret_issues + xss_issues + sql_issues + header_issues + cookie_issues + debug_issues + template_issues + dangerous_issues + ssl_issues + redirect_issues + yaml_issues + path_issues
            test_result = run_unit_tests()

            if auto_push:
                success_push, push_info = commit_and_push_fixes(remediations, commit_sha)
                if success_push:
                    pushed_commit = push_info

    total_issues = len(all_issues)
    is_clean = (total_issues == 0 and test_result['success'])
    duration = round(time.time() - start_time, 2)

    report = {
        'commit': pushed_commit or commit_sha,
        'base_commit': commit_sha,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration_seconds': duration,
        'status': 'PASSED' if is_clean else 'FAILED',
        'tests_passed': test_result['success'],
        'issues_found': total_issues,
        'remediations_applied': remediations,
        'pushed_commit': pushed_commit,
        'syntax_issues': syntax_issues,
        'secret_issues': secret_issues,
        'xss_issues': xss_issues,
        'sql_issues': sql_issues,
        'header_issues': header_issues,
        'cookie_issues': cookie_issues,
        'debug_issues': debug_issues,
        'template_issues': template_issues,
        'dangerous_issues': dangerous_issues,
        'ssl_issues': ssl_issues,
        'redirect_issues': redirect_issues,
        'yaml_issues': yaml_issues,
        'path_issues': path_issues,
        'test_output': test_result['output']
    }

    try:
        with open(REPORT_FILE, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    except Exception as e:
        logger.error(f"Konnte Audit-Bericht nicht schreiben: {e}")

    if is_clean:
        remed_msg = f" ({len(remediations)} Auto-Fixes angewendet)" if remediations else ""
        logger.info(f"✅ Sicherheitsprüfung ERFOLGREICH für {report['commit']} ({duration}s){remed_msg}. Keine Schwachstellen verbleibend.")
    else:
        logger.error(f"⚠️ Sicherheitsprüfung FEHLGESCHLAGEN für {commit_sha}: {total_issues} Befunde, Tests: {'OK' if test_result['success'] else 'FAIL'}")
        for iss in all_issues:
            logger.error(f"  - [{iss['type']}] {iss.get('file')}:{iss.get('line', '?')} - {iss.get('message')}")

    return report


def check_and_review(force=False, auto_fix=True, auto_push=True, verbose=False):
    """Hauptfunktion für eine Überwachungs- und Prüf-Iteration."""
    state = load_state()
    last_reviewed = state.get('last_reviewed_commit')

    remote_commit = fetch_remote_latest_commit()
    local_commit = get_current_local_commit()
    active_commit = remote_commit or local_commit

    log_fn = logger.info if (verbose or force) else logger.debug
    log_fn(f"Monitor-Prüfung: Remote-Commit={remote_commit}, Lokal={local_commit}, Zuletzt geprüft={last_reviewed}")

    should_run = force or (active_commit and active_commit != last_reviewed)

    if not should_run:
        log_fn(f"Keine neuen Commits vorhanden (Stand: {last_reviewed}).")
        return None

    # Falls remote ein neuer Commit vorliegt, Workspace aktualisieren
    if remote_commit and remote_commit != local_commit:
        logger.info(f"Neuer Commit auf Remote erkannt: {remote_commit}. Führe git pull aus...")
        pull_ok, pull_out, pull_err = run_cmd(['git', 'pull', '--ff-only', 'origin', 'main'])
        if not pull_ok:
            logger.warning(f"git pull --ff-only fehlgeschlagen ({pull_err}), versuche Reset auf origin/main...")
            reset_ok, _, reset_err = run_cmd(['git', 'reset', '--hard', 'origin/main'])
            if not reset_ok:
                logger.error(f"git reset fehlgeschlagen: {reset_err}")
                return None
        logger.info(f"Workspace aktualisiert auf Commit: {remote_commit}")
        active_commit = remote_commit

    report = perform_full_security_review(active_commit, auto_fix=auto_fix, auto_push=auto_push)
    state['last_reviewed_commit'] = report.get('commit') or active_commit
    state['last_checked_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
    save_state(state)
    return report


def main():
    parser = argparse.ArgumentParser(description="Lizenzmanager Repo Monitor & Security Auditor")
    parser.add_argument('--check-once', action='store_true', help="Einmalige Überprüfung und Security-Review ausführen")
    parser.add_argument('--force', action='store_true', help="Security-Review auch ohne neuen Commit erzwingen")
    parser.add_argument('--daemon', action='store_true', help="Als Hintergrunddienst kontinuierlich überwachen")
    parser.add_argument('--stop', action='store_true', help="Beendet einen laufenden Monitor-Daemon")
    parser.add_argument('--interval', type=int, default=60, help="Abfrageintervall in Sekunden für Daemon-Modus (Standard: 60)")
    parser.add_argument('--verbose', '-v', action='store_true', help="Ausführliche Logs auch bei unverändertem Zustand")
    parser.add_argument('--no-fix', action='store_true', help="Automatische Fehlerbehebung deaktivieren")
    parser.add_argument('--no-push', action='store_true', help="Automatisches Pushen von Fixes deaktivieren")

    args = parser.parse_args()
    if args.stop:
        stop_running_daemon()
        return

    auto_fix = not args.no_fix
    auto_push = not args.no_push

    if args.daemon:
        if not acquire_daemon_lock(force=args.force):
            sys.exit(1)
        atexit.register(release_daemon_lock)
        logger.info(f"Starte Repository-Monitor im Daemon-Modus (PID {os.getpid()}, Intervall: {args.interval}s, Auto-Fix={auto_fix}, Auto-Push={auto_push})...")
        first_run = args.force
        try:
            while True:
                try:
                    check_and_review(force=first_run, auto_fix=auto_fix, auto_push=auto_push, verbose=args.verbose)
                    first_run = False
                except (KeyboardInterrupt, SystemExit):
                    logger.info("Monitor-Daemon regulär beendet.")
                    break
                except Exception as e:
                    logger.exception(f"Unerwarteter Fehler im Monitor-Loop: {e}")
                try:
                    time.sleep(args.interval)
                except (KeyboardInterrupt, SystemExit):
                    logger.info("Monitor-Daemon während sleep beendet.")
                    break
        finally:
            release_daemon_lock()
    else:
        report = check_and_review(force=args.force or args.check_once, auto_fix=auto_fix, auto_push=auto_push, verbose=args.verbose)
        if report and report['status'] == 'FAILED':
            sys.exit(1)


if __name__ == '__main__':
    main()
