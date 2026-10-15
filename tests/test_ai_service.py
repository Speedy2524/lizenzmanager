import os
import unittest
import ssl
import ai_service
import config

class TestAiService(unittest.TestCase):
    def test_create_ssl_context_with_cert_path(self):
        # Verify that setting SSL_CERT_PATH does not throw NameError for 'os'
        old_cert = getattr(config, 'SSL_CERT_PATH', None)
        try:
            config.SSL_CERT_PATH = 'non_existent_bundle.pem'
            ctx = ai_service._create_ssl_context()
            self.assertIsInstance(ctx, ssl.SSLContext)
        finally:
            config.SSL_CERT_PATH = old_cert

    def test_robust_json_parsing(self):
        # Clean JSON
        raw = '{"name": "Microsoft 365", "cost": 149.00}'
        parsed = ai_service._robust_parse_json(raw)
        self.assertEqual(parsed['name'], 'Microsoft 365')
        self.assertEqual(parsed['cost'], 149.00)

        # Markdown wrapped
        markdown_json = '```json\n{"name": "JetBrains All Products Pack", "cost": 289.0}\n```'
        parsed_md = ai_service._robust_parse_json(markdown_json)
        self.assertEqual(parsed_md['name'], 'JetBrains All Products Pack')

        # Trailing comma & comments
        dirty_json = '{\n// comment\n"name": "Adobe CC",\n"cost": 59.99,\n}'
        parsed_dirty = ai_service._robust_parse_json(dirty_json)
        self.assertEqual(parsed_dirty['name'], 'Adobe CC')

    def test_sanitize_extracted_data(self):
        dirty_data = {
            'name': ' Slack Pro ',
            'category': 'Invalid Category',
            'license_type': 'dauerlizenz',
            'cost': '129,50',
            'seats_total': '10',
            'seats_used': '8'
        }
        sanitized = ai_service._sanitize_extracted_data(dirty_data)
        self.assertEqual(sanitized['name'], 'Slack Pro')
        self.assertEqual(sanitized['category'], 'Sonstiges')
        self.assertEqual(sanitized['license_type'], 'perpetual')
        self.assertEqual(sanitized['cost'], 129.50)
        self.assertEqual(sanitized['seats_total'], 10)
        self.assertEqual(sanitized['seats_used'], 8)

    def test_heuristic_extract_invoice(self):
        sample_invoice = """
        Rechnung Nr. INV-2026-9912
        Aussteller: JetBrains s.r.o.
        Produkt: JetBrains All Products Pack
        Rechnungsdatum: 15.01.2026
        Abrechnung: jährlich
        Gesamtbetrag: 289,00 EUR
        Lizenzen: 1 Benutzer
        """
        extracted = ai_service._heuristic_extract_invoice(sample_invoice)
        self.assertEqual(extracted['vendor'], 'JetBrains s.r.o.')
        self.assertEqual(extracted['cost'], 289.00)
        self.assertEqual(extracted['currency'], 'EUR')
        self.assertEqual(extracted['invoice_number'], 'INV-2026-9912')
        self.assertEqual(extracted['billing_cycle'], 'yearly')

if __name__ == '__main__':
    unittest.main()
