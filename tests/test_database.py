import os
import unittest
import tempfile
from datetime import date, timedelta

# Use isolated temporary database for tests
temp_dir = tempfile.mkdtemp()
os.environ['DB_DIR'] = temp_dir
os.environ['DB_PATH'] = os.path.join(temp_dir, 'test_licenses.db')

import database

class TestDatabase(unittest.TestCase):
    def setUp(self):
        database.init_db()
        database.clear_all_data()

    def test_add_and_get_license(self):
        lic_data = {
            'name': 'Test Software Pro',
            'vendor': 'Vendor Corp',
            'category': 'Entwicklung & Tools',
            'license_type': 'subscription',
            'cost': 120.00,
            'billing_cycle': 'yearly',
            'billing_cycle_months': 12,
            'seats_total': 5,
            'seats_used': 3,
            'purchase_date': '2026-01-01',
            'expiration_date': '2027-01-01',
            'notice_period_days': 30,
            'auto_renewal': 1
        }
        created = database.add_license(lic_data)
        self.assertIsNotNone(created)
        self.assertEqual(created['name'], 'Test Software Pro')
        self.assertEqual(created['cost'], 120.00)
        self.assertEqual(created['yearly_equivalent'], 120.00)
        self.assertEqual(created['monthly_equivalent'], 10.00)

        fetched = database.get_license(created['id'])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched['name'], 'Test Software Pro')

    def test_update_license(self):
        created = database.add_license({'name': 'Old Name', 'cost': 50.0})
        updated = database.update_license(created['id'], {'name': 'New Name', 'cost': 75.0})
        self.assertIsNotNone(updated)
        self.assertEqual(updated['name'], 'New Name')
        self.assertEqual(updated['cost'], 75.0)

    def test_delete_license(self):
        created = database.add_license({'name': 'To Delete'})
        lic_id = created['id']
        self.assertTrue(database.delete_license(lic_id))
        self.assertIsNone(database.get_license(lic_id))

    def test_enrich_license_perpetual(self):
        lic_data = {
            'name': 'Perpetual Tool',
            'license_type': 'perpetual',
            'cost': 500.0,
            'billing_cycle': 'once',
            'expiration_date': None
        }
        created = database.add_license(lic_data)
        self.assertEqual(created['badge_color'], 'blue')
        self.assertEqual(created['yearly_equivalent'], 0.0)
        self.assertEqual(created['monthly_equivalent'], 0.0)

    def test_csv_formula_injection_sanitization(self):
        self.assertEqual(database.sanitize_csv_cell('=cmd|/C calc.exe'), "'=cmd|/C calc.exe")
        self.assertEqual(database.sanitize_csv_cell('+123'), "'+123")
        self.assertEqual(database.sanitize_csv_cell('-456'), "'-456")
        self.assertEqual(database.sanitize_csv_cell('@SUM(A1:A10)'), "'@SUM(A1:A10)")
        self.assertEqual(database.sanitize_csv_cell('Normal String'), 'Normal String')

    def test_user_management_and_admin_protection(self):
        # Create initial admin
        admin = database.create_local_admin('admin', 'adminpassword123', 'Administrator')
        self.assertTrue(admin['is_admin'])

        # Verify authentication
        verified = database.verify_local_user('admin', 'adminpassword123')
        self.assertIsNotNone(verified)
        self.assertEqual(verified['username'], 'admin')

        # Add second user (standard)
        user2 = database.add_local_user('johndoe', 'securepass123', 'John Doe', is_admin=False)
        self.assertFalse(user2['is_admin'])

        # Attempt to delete oneself should fail
        with self.assertRaises(ValueError):
            database.delete_local_user(admin_id := database.get_all_local_users()[0]['id'], current_username='admin')

        # Attempt to delete last remaining admin should fail
        with self.assertRaises(ValueError):
            database.delete_local_user(admin_id, current_username='other')

    def test_audit_logging_and_stats(self):
        # Log various events
        database.log_audit_event('CREATE_LICENSE', 'license', 'Test Software', target_id=1, details={'name': 'Test Software'}, username='admin')
        database.log_audit_event('UPDATE_LICENSE', 'license', 'Test Software', target_id=1, details='Cost updated', username='admin')
        database.log_audit_event('DELETE_LICENSE', 'license', 'Test Software', target_id=1, details='Deleted license', username='admin')
        database.log_audit_event('LOGIN', 'auth', 'admin', details='Login successful', username='admin')
        database.log_audit_event('CREATE_USER', 'user', 'editor1', details='Created editor user', username='admin')

        # Check stats
        stats = database.get_audit_log_stats()
        self.assertEqual(stats['total'], 5)
        self.assertEqual(stats['creations'], 2)
        self.assertEqual(stats['updates'], 1)
        self.assertEqual(stats['deletions'], 1)
        self.assertEqual(stats['logins'], 1)
        self.assertEqual(stats['user_actions'], 1)

        # Retrieve logs with filtering
        logs_res = database.get_audit_logs(limit=10, category='license')
        self.assertEqual(logs_res['total'], 3)
        self.assertEqual(len(logs_res['logs']), 3)

        # Deletions only filter
        del_res = database.get_audit_logs(deletions_only=True)
        self.assertEqual(del_res['total'], 1)
        self.assertEqual(del_res['logs'][0]['action'], 'DELETE_LICENSE')

        # Export CSV
        csv_data = database.export_audit_logs_csv()
        self.assertIn('DELETE_LICENSE', csv_data)
        self.assertIn('CREATE_LICENSE', csv_data)

        # Clear logs
        deleted_count = database.clear_audit_logs()
        self.assertEqual(deleted_count, 5)
        self.assertEqual(database.get_audit_log_stats()['total'], 0)

if __name__ == '__main__':
    unittest.main()

