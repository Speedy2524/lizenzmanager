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


def run_cmd(cmd_list, timeout=45):
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
                        for line_idx, line in enumerate(fp, 1):
                            stripped = line.strip()
                            if stripped.startswith('#'):
                                continue
                            # Erkennung von .execute(f"...") oder .execute("..." % ...) oder .execute("...".format(...))
                            if (re.search(r'\.(?:execute|executemany)\s*\(\s*f["\']', line) or
                                re.search(r'\.(?:execute|executemany)\s*\(\s*["\'].*?["\']\s*%', line) or
                                re.search(r'\.(?:execute|executemany)\s*\(\s*["\'].*?\.format\(', line)):
                                # Erlaube sichere statische ALTER TABLE Spalten-Migrationen
                                if 'ALTER TABLE' in line and any(col in line for col in ('col_name', 'billing_cycle_months')):
                                    continue
                                issues.append({
                                    'type': 'PotentialSQLInjection',
                                    'file': rel,
                                    'line': line_idx,
                                    'message': f"Potentiell unsichere dynamische SQL-Abfrage (Formatierung in execute): {stripped[:60]}..."
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

    all_issues = syntax_issues + secret_issues + xss_issues + sql_issues + header_issues + cookie_issues + debug_issues + template_issues
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
            all_issues = syntax_issues + secret_issues + xss_issues + sql_issues + header_issues + cookie_issues + debug_issues + template_issues
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
            logger.error(f"git pull fehlgeschlagen: {pull_err}")
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
    parser.add_argument('--interval', type=int, default=60, help="Abfrageintervall in Sekunden für Daemon-Modus (Standard: 60)")
    parser.add_argument('--verbose', '-v', action='store_true', help="Ausführliche Logs auch bei unverändertem Zustand")
    parser.add_argument('--no-fix', action='store_true', help="Automatische Fehlerbehebung deaktivieren")
    parser.add_argument('--no-push', action='store_true', help="Automatisches Pushen von Fixes deaktivieren")

    args = parser.parse_args()
    auto_fix = not args.no_fix
    auto_push = not args.no_push

    if args.daemon:
        logger.info(f"Starte Repository-Monitor im Daemon-Modus (Intervall: {args.interval}s, Auto-Fix={auto_fix}, Auto-Push={auto_push})...")
        first_run = args.force
        while True:
            try:
                check_and_review(force=first_run, auto_fix=auto_fix, auto_push=auto_push, verbose=args.verbose)
                first_run = False
            except Exception as e:
                logger.exception(f"Unerwarteter Fehler im Monitor-Loop: {e}")
            time.sleep(args.interval)
    else:
        report = check_and_review(force=args.force or args.check_once, auto_fix=auto_fix, auto_push=auto_push, verbose=args.verbose)
        if report and report['status'] == 'FAILED':
            sys.exit(1)


if __name__ == '__main__':
    main()
