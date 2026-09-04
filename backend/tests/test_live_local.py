from __future__ import annotations

import asyncio
import tempfile
import unittest
from pathlib import Path

from app.models.live_schemas import LiveConnectRequest
from app.services.live_monitor import LiveMonitorService


ACCESS = '10.9.9.9 - - [31/Aug/2026:11:00:00 +0000] "GET /health HTTP/1.1" 200 12\n'
CARBON = "[2026-08-31 11:00:01,010] ERROR {org.apache.synapse.transport.passthru.SourceHandler} - Connection closed\n"


class LiveLocalMonitorTests(unittest.IsolatedAsyncioTestCase):
    async def test_tails_new_lines(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            access = root / "http_access.log"
            carbon = root / "wso2carbon.log"
            access.write_text(ACCESS, encoding="utf-8")
            carbon.write_text(CARBON, encoding="utf-8")
            svc = LiveMonitorService()
            try:
                await svc.connect(
                    LiveConnectRequest(
                        mode="local",
                        log_dir=str(root),
                        extra_log_dirs=["/definitely/missing"],
                        poll_seconds=1.0,
                        report_interval_seconds=-1,
                        seed_bytes=200_000,
                    )
                )
                state = svc.public_state()
                self.assertTrue(state["connected"])
                self.assertGreaterEqual(state["snapshot"]["traffic"]["total_requests"], 1)
                access.write_text(
                    ACCESS + '8.8.8.8 - - [31/Aug/2026:11:00:02 +0000] "GET /fail HTTP/1.1" 500 9\n',
                    encoding="utf-8",
                )
                await asyncio.sleep(1.3)
                later = svc.public_state()
                self.assertGreaterEqual(later["snapshot"]["traffic"]["total_requests"], 2)
                self.assertGreaterEqual(later["snapshot"]["traffic"]["http_errors"], 1)
                names = {f["name"] for f in later["files"]}
                self.assertIn("http_access.log", names)
                self.assertIn("wso2carbon.log", names)
            finally:
                await svc.disconnect()
                self.assertFalse(svc.public_state()["connected"])


if __name__ == "__main__":
    unittest.main()
