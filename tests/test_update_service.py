import unittest
import update_service
import config

class TestUpdateService(unittest.TestCase):
    def test_safe_repo_validation(self):
        self.assertEqual(update_service._get_safe_repo(), 'Speedy2524/lizenzmanager')
        
        # Malicious or invalid repo names should fallback safely
        old_repo = getattr(config, 'APP_REPO', None)
        try:
            config.APP_REPO = 'Speedy2524/repo;rm -rf'
            self.assertEqual(update_service._get_safe_repo(), 'Speedy2524/lizenzmanager')

            config.APP_REPO = 'https://malicious.com/repo'
            self.assertEqual(update_service._get_safe_repo(), 'Speedy2524/lizenzmanager')
        finally:
            config.APP_REPO = old_repo

    def test_safe_branch_validation(self):
        self.assertEqual(update_service._get_safe_branch(), 'main')

        old_branch = getattr(config, 'APP_BRANCH', None)
        try:
            config.APP_BRANCH = 'main && evil_cmd'
            self.assertEqual(update_service._get_safe_branch(), 'main')
        finally:
            config.APP_BRANCH = old_branch

    def test_is_safe_github_url(self):
        repo = 'Speedy2524/lizenzmanager'
        self.assertTrue(update_service._is_safe_github_url('https://github.com/Speedy2524/lizenzmanager/releases/tag/v1.2.0', repo))
        self.assertTrue(update_service._is_safe_github_url('https://github.com/Speedy2524/lizenzmanager/commit/54fb644', repo))
        
        # Spoofed or external URLs should be rejected
        self.assertFalse(update_service._is_safe_github_url('https://github.com/attacker/malicious/releases', repo))
        self.assertFalse(update_service._is_safe_github_url('https://evil-github.com/Speedy2524/lizenzmanager', repo))
        self.assertFalse(update_service._is_safe_github_url('javascript:alert(1)', repo))

    def test_version_parsing_and_comparison(self):
        self.assertEqual(update_service.parse_version('v1.2.3'), (1, 2, 3, 0))
        self.assertEqual(update_service.parse_version('2.0.0.1'), (2, 0, 0, 1))
        self.assertTrue(update_service.is_newer_version('v1.2.0', '1.1.0'))
        self.assertTrue(update_service.is_newer_version('v2.0.0', 'v1.9.9'))
        self.assertFalse(update_service.is_newer_version('v1.0.0', 'v1.1.0'))
        self.assertFalse(update_service.is_newer_version('v1.1.0', 'v1.1.0'))

if __name__ == '__main__':
    unittest.main()
