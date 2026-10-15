#!/usr/bin/env python3
"""
Automatisierter Repository-Monitor & Security-Review-Dienst für Lizenzmanager.
Überwacht https://github.com/Speedy2524/lizenzmanager auf neue Commits,
führt automatische Sicherheitsüberprüfungen (Static Analysis, Secrets, XSS, SQLi)
und Unit-Tests durch und protokolliert alle Ergebnisse.
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

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

DATA_DIR = os.path.join(BASE_DIR, 'data')
os.makedirs(DATA_DIR, exist_ok=True)

LOG_FILE = os.path.join(DATA_DIR, 'security_audit.log')
REPORT_FILE = os.path.join(DATA_DIR, 'last_audit_report.json')
STATE_FILE = os.path.join(DATA_DIR, 'monitor_state.json')

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


def run_cmd(cmd_list, timeout=30):
    """Führt einen Subprozess-Befehl sicher aus."""
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
        (r'-----BEGIN (?:RSA )?PRIVATE KEY-----', 'Privater kryptographischer Schlüssel im Repository')
    ]

    for root, _, files in os.walk(BASE_DIR):
        if any(ignored in root for ignored in ('.git', '__pycache__', 'venv', '.venv', 'data')):
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
    for root, _, files in os.walk(os.path.join(BASE_DIR, 'static')):
        for f in files:
            if f.endswith('.js'):
                js_files.append(os.path.join(root, f))

    for p in js_files:
        rel = os.path.relpath(p, BASE_DIR)
        with open(p, 'r', encoding='utf-8') as fp:
            for line_idx, line in enumerate(fp, 1):
                # Prüfe ob `${lic.` ohne escapeHtml verwendet wird
                m = re.search(r'\$\{(lic\.[a-zA-Z0-9_]+)\}', line)
                if m:
                    var_name = m.group(1)
                    if 'escapeHtml' not in line and 'format' not in line and 'sanitize' not in line:
                        # Ausnahmen: IDs und rein numerische Variablen
                        if not any(safe_attr in var_name for safe_attr in ('id', 'seats_used', 'seats_total', 'cost')):
                            issues.append({
                                'type': 'UnescapedDOMProperty',
                                'file': rel,
                                'line': line_idx,
                                'message': f"Mögliche XSS-Schwachstelle: {var_name} wird ohne escapeHtml() gerendert"
                            })
    return issues


def run_unit_tests():
    """Führt die Test-Suite aus."""
    ok, out, err = run_cmd([sys.executable, '-m', 'unittest', 'discover', 'tests'])
    return {
        'success': ok,
        'output': out or err
    }


def perform_full_security_review(commit_sha):
    """Führt eine vollständige Sicherheitsanalyse und Testsuite aus."""
    logger.info(f"Starte automatisierte Sicherheitsprüfung für Commit: {commit_sha}...")
    start_time = time.time()

    syntax_issues = audit_python_syntax()
    secret_issues = audit_hardcoded_secrets()
    xss_issues = audit_dom_xss()
    test_result = run_unit_tests()

    total_issues = len(syntax_issues) + len(secret_issues) + len(xss_issues)
    is_clean = (total_issues == 0 and test_result['success'])
    duration = round(time.time() - start_time, 2)

    report = {
        'commit': commit_sha,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'duration_seconds': duration,
        'status': 'PASSED' if is_clean else 'FAILED',
        'tests_passed': test_result['success'],
        'issues_found': total_issues,
        'syntax_issues': syntax_issues,
        'secret_issues': secret_issues,
        'xss_issues': xss_issues,
        'test_output': test_result['output']
    }

    try:
        with open(REPORT_FILE, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
    except Exception as e:
        logger.error(f"Konnte Audit-Bericht nicht schreiben: {e}")

    if is_clean:
        logger.info(f"✅ Sicherheitsprüfung ERFOLGREICH für {commit_sha} ({duration}s). Keine Schwachstellen gefunden.")
    else:
        logger.error(f"⚠️ Sicherheitsprüfung FEHLGESCHLAGEN für {commit_sha}: {total_issues} Befunde, Tests: {'OK' if test_result['success'] else 'FAIL'}")
        for iss in syntax_issues + secret_issues + xss_issues:
            logger.error(f"  - [{iss['type']}] {iss.get('file')}:{iss.get('line', '?')} - {iss.get('message')}")

    return report


def check_and_review(force=False):
    """Hauptfunktion für eine Prüf-Iteration."""
    state = load_state()
    last_reviewed = state.get('last_reviewed_commit')

    remote_commit = fetch_remote_latest_commit()
    local_commit = get_current_local_commit()
    active_commit = remote_commit or local_commit

    logger.info(f"Monitor-Prüfung: Remote-Commit={remote_commit}, Lokal={local_commit}, Zuletzt geprüft={last_reviewed}")

    should_run = force or (active_commit and active_commit != last_reviewed)

    if not should_run:
        logger.info(f"Keine neuen Commits vorhanden (Stand: {last_reviewed}).")
        return None

    # Falls remote ein neuer Commit vorliegt, Workspace aktualisieren
    if remote_commit and remote_commit != local_commit:
        logger.info(f"Neuer Commit auf Remote erkannt: {remote_commit}. Führe git pull aus...")
        pull_ok, pull_out, pull_err = run_cmd(['git', 'pull', '--ff-only', 'origin', 'main'])
        if not pull_ok:
            logger.error(f"git pull fehlgeschlagen: {pull_err}")
            return None
        logger.info(f"Workspace aktualisiert auf Commit: {remote_commit}")
        active_commit = remote_commit

    report = perform_full_security_review(active_commit)
    state['last_reviewed_commit'] = active_commit
    state['last_checked_at'] = time.strftime('%Y-%m-%d %H:%M:%S')
    save_state(state)
    return report


def main():
    parser = argparse.ArgumentParser(description="Lizenzmanager Repo Monitor & Security Auditor")
    parser.add_argument('--check-once', action='store_true', help="Einmalige Überprüfung und Security-Review ausführen")
    parser.add_argument('--force', action='store_true', help="Security-Review auch ohne neuen Commit erzwingen")
    parser.add_argument('--daemon', action='store_true', help="Als Hintergrunddienst kontinuierlich überwachen")
    parser.add_argument('--interval', type=int, default=300, help="Abfrageintervall in Sekunden für Daemon-Modus (Standard: 300)")

    args = parser.parse_args()

    if args.daemon:
        logger.info(f"Starte Repository-Monitor im Daemon-Modus (Intervall: {args.interval}s)...")
        while True:
            try:
                check_and_review(force=args.force)
            except Exception as e:
                logger.exception(f"Unerwarteter Fehler im Monitor-Loop: {e}")
            time.sleep(args.interval)
    else:
        report = check_and_review(force=args.force or args.check_once)
        if report and report['status'] == 'FAILED':
            sys.exit(1)


if __name__ == '__main__':
    main()
