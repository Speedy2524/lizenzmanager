import unittest
import app
import config

class TestSecurity(unittest.TestCase):
    def setUp(self):
        app.app.config['TESTING'] = True
        app.database.init_db()
        if not app.database.has_local_admin():
            app.database.create_local_admin('admin', 'AdminPass123!', 'Administrator')
        self.client = app.app.test_client()

    def test_is_safe_url(self):
        # Valid relative paths
        self.assertTrue(app.is_safe_url('/'))
        self.assertTrue(app.is_safe_url('/licenses'))
        self.assertTrue(app.is_safe_url('/dashboard?tab=costs'))

        # Open-redirect attempts
        self.assertFalse(app.is_safe_url('https://evil.com'))
        self.assertFalse(app.is_safe_url('//evil.com'))
        self.assertFalse(app.is_safe_url('/\\evil.com'))
        self.assertFalse(app.is_safe_url('\\\\evil.com'))
        self.assertFalse(app.is_safe_url('javascript:alert(1)'))
        self.assertFalse(app.is_safe_url('data:text/html,evil'))

        # Header injection / CRLF attempts
        self.assertFalse(app.is_safe_url('/path\r\nSet-Cookie: evil=1'))
        self.assertFalse(app.is_safe_url('/path\nEvil: header'))

    def test_csrf_protection_on_mutating_api(self):
        # A mutating request to /api/ without X-Requested-With or X-CSRF-Token should be blocked with 403
        with self.client.session_transaction() as sess:
            sess['user'] = {'username': 'admin', 'is_admin': True}

        # Request missing CSRF header
        res = self.client.post('/api/licenses', json={'name': 'CSRF Test'})
        self.assertEqual(res.status_code, 403)
        self.assertIn('Fehlender CSRF-Schutz-Header', res.get_json().get('error', ''))

        # Request with proper X-Requested-With header
        res_valid = self.client.post('/api/licenses', json={'name': 'CSRF Pass'}, headers={'X-Requested-With': 'XMLHttpRequest'})
        self.assertIn(res_valid.status_code, (200, 201))

    def test_login_rate_limiting(self):
        test_ip = '198.51.100.42'
        app._login_attempts.clear()

        # Up to 5 attempts in 60s window should be allowed
        for i in range(5):
            self.assertFalse(app.is_login_rate_limited(test_ip, max_attempts=5, window_seconds=60))

        # 6th attempt should be rate-limited
        self.assertTrue(app.is_login_rate_limited(test_ip, max_attempts=5, window_seconds=60))

    def test_session_cookie_security_flags(self):
        self.assertTrue(app.app.config.get('SESSION_COOKIE_HTTPONLY'))
        self.assertEqual(app.app.config.get('SESSION_COOKIE_SAMESITE'), 'Lax')

if __name__ == '__main__':
    unittest.main()
