import os
import tempfile
import unittest

from nids.dashboard import create_app
from nids.database import Database
from nids.pipeline import Pipeline


class TestPipeline(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.path)
        self.db = Database(self.path)
        self.db.init_db()

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_stop_is_idempotent(self):
        pipeline = Pipeline(
            {"capture": {"stats_interval_seconds": 10}},
            self.db,
        )
        pipeline._window_packet_count = 1
        pipeline._window_byte_count = 100

        pipeline.stop()
        pipeline.stop()

        self.assertEqual(len(self.db.get_recent_traffic(10)), 1)


class TestDashboard(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.remove(self.path)
        self.db = Database(self.path)
        self.db.init_db()
        app, _socketio = create_app(self.db)
        self.client = app.test_client()

    def tearDown(self):
        self.db.close()
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_invalid_limits_use_defaults(self):
        self.assertEqual(self.client.get("/api/alerts?limit=abc").status_code, 200)
        self.assertEqual(self.client.get("/api/traffic?limit=abc").status_code, 200)

    def test_limits_are_bounded(self):
        self.assertEqual(self.client.get("/api/alerts?limit=-5").status_code, 200)
        self.assertEqual(self.client.get("/api/traffic?limit=50000").status_code, 200)


if __name__ == "__main__":
    unittest.main()
