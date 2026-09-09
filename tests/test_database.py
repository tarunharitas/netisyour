import os
import tempfile
import unittest

from nids.database import Database
from nids.models import Alert


class TestDatabase(unittest.TestCase):
    def setUp(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(path)
        self.path = path
        self.db = Database(path)
        self.db.init_db()

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_insert_and_retrieve_alert(self):
        alert = Alert(
            alert_type="TEST_ALERT", severity="low", confidence=0.5,
            rule_name="test_rule", description="A test alert",
            evidence={"foo": "bar"}, src_ip="10.0.0.1",
        )
        alert_id = self.db.insert_alert(alert)
        self.assertGreater(alert_id, 0)

        fetched = self.db.get_alert(alert_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["alert_type"], "TEST_ALERT")
        self.assertEqual(fetched["evidence"]["foo"], "bar")

    def test_update_alert_status(self):
        alert = Alert(alert_type="TEST", severity="low", confidence=0.5,
                       rule_name="r", description="d")
        alert_id = self.db.insert_alert(alert)
        ok = self.db.update_alert(alert_id, status="resolved", note="reviewed")
        self.assertTrue(ok)
        fetched = self.db.get_alert(alert_id)
        self.assertEqual(fetched["status"], "resolved")
        self.assertEqual(fetched["note"], "reviewed")

    def test_summary_counts(self):
        for sev in ["low", "medium", "high"]:
            self.db.insert_alert(Alert(alert_type="X", severity=sev, confidence=0.5,
                                        rule_name="r", description="d"))
        summary = self.db.summary()
        self.assertEqual(summary["total_alerts"], 3)
        self.assertEqual(summary["new_alerts"], 3)


if __name__ == "__main__":
    unittest.main()
