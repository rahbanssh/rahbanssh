import json
import tempfile
import unittest
from pathlib import Path

import panel


class TelegramFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        data = Path(self.temp_dir.name)
        password_file = data / "admin_password"
        password_file.write_text("test-admin-password-123", encoding="utf-8")
        panel.DATA = data
        panel.DB_PATH = data / "panel.db"
        panel.ADMIN_PASSWORD_FILE = password_file
        panel.initialize_database()
        self.owner = panel.admin_record(panel.ADMIN_USERNAME)
        self.replies = []
        self.original_reply = panel.telegram_reply
        self.original_api = panel.telegram_api
        panel.telegram_reply = self._capture_reply
        panel.telegram_api = lambda *_args, **_kwargs: True

    def tearDown(self):
        panel.telegram_reply = self.original_reply
        panel.telegram_api = self.original_api
        self.temp_dir.cleanup()

    def _capture_reply(self, _token, chat_id, text, **kwargs):
        self.replies.append((chat_id, text, kwargs))

    @staticmethod
    def _message(text):
        return {
            "message": {
                "chat": {"id": 123456789, "type": "private"},
                "from": {"id": 123456789, "first_name": "Test", "username": "tester"},
                "text": text,
            }
        }

    @staticmethod
    def _callback(data):
        return {
            "callback_query": {
                "id": "callback-1",
                "data": data,
                "from": {"id": 123456789, "first_name": "Test", "username": "tester"},
                "message": {"chat": {"id": 123456789, "type": "private"}},
            }
        }

    def test_menu_is_simple_and_contains_no_reseller_actions(self):
        menu = json.loads(panel.telegram_menu())
        labels = [button["text"] for row in menu["inline_keyboard"] for button in row]
        self.assertEqual(labels, [
            "🎁 دریافت تست رایگان",
            "🛒 خرید VPN",
            "📊 حجم باقی‌مانده سرویس",
            "☎️ ارتباط با ما",
            "📖 راهنما و نرم‌افزارهای اتصال",
        ])
        self.assertNotIn("نماینده", " ".join(labels))

    def test_new_customer_must_register_before_seeing_menu(self):
        panel.handle_telegram_update(self.owner, "token", self._message("/start"))
        customer = panel.telegram_customer(panel.ADMIN_USERNAME, "123456789")
        self.assertEqual(customer["registered_at"], "")
        markup = json.loads(self.replies[-1][2]["reply_markup"])
        self.assertEqual(markup["inline_keyboard"][0][0]["callback_data"], "register")

        panel.handle_telegram_update(self.owner, "token", self._callback("register"))
        customer = panel.telegram_customer(panel.ADMIN_USERNAME, "123456789")
        self.assertTrue(customer["registered_at"])
        self.assertTrue(self.replies[-1][2]["menu"])

    def test_help_contains_platform_apps(self):
        help_text = panel.telegram_help_text()
        self.assertIn("Android — NPV Tunnel", help_text)
        self.assertIn("iPhone / iPad — NPV Tunnel", help_text)
        self.assertIn("Windows — NetMod", help_text)
        self.assertIn("Windows — Nekoray", help_text)


if __name__ == "__main__":
    unittest.main()
