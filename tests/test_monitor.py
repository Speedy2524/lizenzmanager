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
            f.write('api_key = "1234567890123456789012345"\n')
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

if __name__ == '__main__':
    unittest.main()
