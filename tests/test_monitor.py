import os
import unittest
import tempfile
import shutil
import scripts.monitor_repo as monitor

class TestMonitorRepo(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.orig_base = monitor.BASE_DIR
        monitor.BASE_DIR = self.test_dir

    def tearDown(self):
        monitor.BASE_DIR = self.orig_base
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_audit_python_syntax_valid_and_invalid(self):
        # Valid python file
        valid_path = os.path.join(self.test_dir, 'valid.py')
        with open(valid_path, 'w', encoding='utf-8') as f:
            f.write("def foo():\n    return 42\n")
        self.assertEqual(len(monitor.audit_python_syntax()), 0)

        # Syntax error
        invalid_path = os.path.join(self.test_dir, 'invalid.py')
        with open(invalid_path, 'w', encoding='utf-8') as f:
            f.write("def foo() pass\n")
        issues = monitor.audit_python_syntax()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'SyntaxError')

    def test_audit_hardcoded_secrets(self):
        secret_file = os.path.join(self.test_dir, 'secret.py')
        with open(secret_file, 'w', encoding='utf-8') as f:
            f.write('api_' + 'key = "1234567890123456789012345"\n')
        issues = monitor.audit_hardcoded_secrets()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'SecretExposure')

    def test_audit_and_auto_remediate_dom_xss(self):
        static_dir = os.path.join(self.test_dir, 'static')
        os.makedirs(static_dir, exist_ok=True)
        js_file = os.path.join(static_dir, 'test.js')
        with open(js_file, 'w', encoding='utf-8') as f:
            f.write("const html = `<div>${lic.vendor}</div>`;\n")

        issues = monitor.audit_dom_xss()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'UnescapedDOMProperty')

        # Run auto remediation
        remediations = monitor.auto_remediate_issues(issues)
        self.assertTrue(len(remediations) > 0)

        # Verify file was sanitized
        with open(js_file, 'r', encoding='utf-8') as f:
            new_content = f.read()
        self.assertIn("${escapeHtml(lic.vendor)}", new_content)

        # Audit should now report 0 issues
        self.assertEqual(len(monitor.audit_dom_xss()), 0)

    def test_audit_and_remediate_security_headers(self):
        app_file = os.path.join(self.test_dir, 'app.py')
        with open(app_file, 'w', encoding='utf-8') as f:
            f.write("import os\nimport flask\napp = flask.Flask(__name__)\ndatabase.init_db()\n")

        issues = monitor.audit_security_headers()
        self.assertEqual(len(issues), 3)

        remediations = monitor.auto_remediate_issues(issues)
        self.assertTrue(len(remediations) > 0)

        with open(app_file, 'r', encoding='utf-8') as f:
            new_content = f.read()
        self.assertIn("X-Content-Type-Options", new_content)
        self.assertIn("X-Frame-Options", new_content)
        self.assertEqual(len(monitor.audit_security_headers()), 0)

    def test_audit_and_remediate_cookie_security(self):
        app_file = os.path.join(self.test_dir, 'app.py')
        with open(app_file, 'w', encoding='utf-8') as f:
            f.write("import flask\nimport config\napp = flask.Flask(__name__)\napp.secret_key = config.SECRET_KEY\n")

        issues = monitor.audit_session_security()
        self.assertEqual(len(issues), 2)

        remediations = monitor.auto_remediate_issues(issues)
        self.assertTrue(len(remediations) > 0)

        with open(app_file, 'r', encoding='utf-8') as f:
            new_content = f.read()
        self.assertIn("SESSION_COOKIE_HTTPONLY", new_content)
        self.assertIn("SESSION_COOKIE_SAMESITE", new_content)
        self.assertEqual(len(monitor.audit_session_security()), 0)

    def test_audit_sql_injection(self):
        py_file = os.path.join(self.test_dir, 'query.py')
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write('def get_user(name):\n    cur.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n')
            f.write('    cur.execute("SELECT * FROM items WHERE id = %s" % (name,))\n')
            f.write('    # Sichere Abfragen mit LIKE oder Parametern dürfen NICHT als Injection markiert werden\n')
            f.write('    cur.execute("SELECT COUNT(*) FROM logs WHERE action LIKE \'%DELETE%\' OR action = \'CLEAR\'")\n')
            f.write('    cur.execute("SELECT * FROM items WHERE name LIKE ?", (\'%test%\',))\n')
        issues = monitor.audit_sql_injection()
        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0]['type'], 'PotentialSQLInjection')

    def test_audit_debug_mode_and_remediation(self):
        app_file = os.path.join(self.test_dir, 'app.py')
        with open(app_file, 'w', encoding='utf-8') as f:
            f.write('app.run(host="0.0.0.0", port=5000, debug=True)\n')

        issues = monitor.audit_debug_mode()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'DebugModeEnabled')

        remediations = monitor.auto_remediate_issues(issues)
        self.assertTrue(len(remediations) > 0)

        with open(app_file, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('debug=False', content)
        self.assertEqual(len(monitor.audit_debug_mode()), 0)

    def test_audit_jinja_templates(self):
        tpl_dir = os.path.join(self.test_dir, 'templates')
        os.makedirs(tpl_dir, exist_ok=True)
        html_file = os.path.join(tpl_dir, 'test.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write('<div>{{ user_input | safe }}</div>\n')

        issues = monitor.audit_jinja_templates()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'PotentiallyUnsafeJinjaFilter')

    def test_audit_hardcoded_secrets_aws_and_pat(self):
        secret_file = os.path.join(self.test_dir, 'aws_key.py')
        with open(secret_file, 'w', encoding='utf-8') as f:
            f.write('AWS_KEY = "AKIA1234567890ABCDEF"\n')
        issues = monitor.audit_hardcoded_secrets()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'SecretExposure')

    def test_audit_dangerous_functions(self):
        py_file = os.path.join(self.test_dir, 'danger.py')
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write('x = eval("2 + 2")\n')
            f.write('exec("print(1)")\n')
            f.write('import pickle\npickle.loads(b"data")\n')
            f.write('import subprocess\nsubprocess.run("ls", shell=True)\n')
        issues = monitor.audit_dangerous_functions()
        self.assertEqual(len(issues), 4)
        issue_types = [i['type'] for i in issues]
        self.assertIn('DangerousFunctionCall', issue_types)
        self.assertIn('DangerousDeserialization', issue_types)
        self.assertIn('DangerousSubprocessShell', issue_types)

    def test_audit_and_remediate_jinja_safe(self):
        tpl_dir = os.path.join(self.test_dir, 'templates')
        os.makedirs(tpl_dir, exist_ok=True)
        html_file = os.path.join(tpl_dir, 'unsafe.html')
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write('<div>{{ comment | safe }}</div>\n')

        issues = monitor.audit_jinja_templates()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'PotentiallyUnsafeJinjaFilter')

        remediations = monitor.auto_remediate_issues(issues)
        self.assertTrue(len(remediations) > 0)

        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertNotIn('| safe', content)
        self.assertEqual(len(monitor.audit_jinja_templates()), 0)

    def test_audit_insecure_ssl_and_remediation(self):
        py_file = os.path.join(self.test_dir, 'client.py')
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write('resp = requests.get("https://example.com", verify=False)\n')
            f.write('ctx = ssl._create_unverified_context()\n')
        issues = monitor.audit_insecure_ssl()
        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0]['type'], 'InsecureSSLConfiguration')

        remediations = monitor.auto_remediate_issues(issues)
        self.assertTrue(len(remediations) > 0)

        with open(py_file, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('verify=True', content)

    def test_audit_open_redirect(self):
        py_file = os.path.join(self.test_dir, 'routes.py')
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write('target = request.args.get("next")\nreturn redirect(request.args.get("next"))\n')
        issues = monitor.audit_open_redirect()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'PotentialOpenRedirect')

    def test_state_load_and_save(self):
        data_dir = os.path.join(self.test_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        orig_state_file = monitor.STATE_FILE
        monitor.STATE_FILE = os.path.join(data_dir, 'test_state.json')
        try:
            test_state = {'last_reviewed_commit': 'abcdef1', 'last_checked_at': '2026-10-15 12:00:00'}
            monitor.save_state(test_state)
            loaded = monitor.load_state()
            self.assertEqual(loaded.get('last_reviewed_commit'), 'abcdef1')
        finally:
            monitor.STATE_FILE = orig_state_file


    def test_daemon_pid_lock(self):
        data_dir = os.path.join(self.test_dir, 'data')
        os.makedirs(data_dir, exist_ok=True)
        orig_pid_file = monitor.PID_FILE
        monitor.PID_FILE = os.path.join(data_dir, 'test_monitor.pid')
        try:
            self.assertTrue(monitor.acquire_daemon_lock())
            self.assertTrue(os.path.exists(monitor.PID_FILE))
            # Re-acquiring by same process succeeds
            self.assertTrue(monitor.acquire_daemon_lock())
            monitor.release_daemon_lock()
            self.assertFalse(os.path.exists(monitor.PID_FILE))
        finally:
            monitor.PID_FILE = orig_pid_file

    def test_cleanup_stale_git_locks(self):
        git_dir = os.path.join(self.test_dir, '.git')
        os.makedirs(git_dir, exist_ok=True)
        lock_file = os.path.join(git_dir, 'index.lock')
        with open(lock_file, 'w') as f:
            f.write('lock')
        # Set mtime back by 120 seconds
        past = monitor.time.time() - 120
        os.utime(lock_file, (past, past))
        monitor.cleanup_stale_git_locks(max_age_seconds=60)
        self.assertFalse(os.path.exists(lock_file))

    def test_audit_unsafe_yaml_load_and_remediation(self):
        py_file = os.path.join(self.test_dir, 'config_loader.py')
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write('import yaml\ndata = yaml.load(raw_data)\n')
        issues = monitor.audit_unsafe_yaml_load()
        self.assertEqual(len(issues), 1)
        self.assertEqual(issues[0]['type'], 'UnsafeYamlLoad')

        remediations = monitor.auto_remediate_issues(issues)
        self.assertTrue(len(remediations) > 0)

        with open(py_file, 'r', encoding='utf-8') as f:
            content = f.read()
        self.assertIn('yaml.safe_load(raw_data)', content)
        self.assertEqual(len(monitor.audit_unsafe_yaml_load()), 0)

    def test_audit_path_traversal(self):
        py_file = os.path.join(self.test_dir, 'files.py')
        with open(py_file, 'w', encoding='utf-8') as f:
            f.write('return send_file(os.path.join("uploads", request.args.get("filename")))\n')
            f.write('f = open(os.path.join("data", request.form.get("path")))\n')
        issues = monitor.audit_path_traversal()
        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0]['type'], 'PotentialPathTraversal')


if __name__ == '__main__':
    unittest.main()



