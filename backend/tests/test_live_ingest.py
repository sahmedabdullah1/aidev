from __future__ import annotations

import unittest

from app.collectors.live_ingest import (
    LiveAggregator,
    is_active_log_name,
    parse_metrics_script_output,
    split_complete_lines,
)


class LiveIngestTests(unittest.TestCase):
    def test_active_log_names(self) -> None:
        self.assertTrue(is_active_log_name("wso2carbon.log"))
        self.assertTrue(is_active_log_name("http_access.log"))
        self.assertTrue(is_active_log_name("catalina.out"))
        self.assertFalse(is_active_log_name("wso2carbon.log.1"))
        self.assertFalse(is_active_log_name("access.log.gz"))
        self.assertFalse(is_active_log_name("heapdump.hprof"))

    def test_split_complete_lines(self) -> None:
        lines, leftover = split_complete_lines("", "a\nb\ninc")
        self.assertEqual(lines, ["a", "b"])
        self.assertEqual(leftover, "inc")
        lines, leftover = split_complete_lines("inc", "omplete\nnext\n")
        self.assertEqual(lines, ["incomplete", "next"])
        self.assertEqual(leftover, "")

    def test_http_access_and_carbon(self) -> None:
        agg = LiveAggregator(compute_allocation={"vcpu": 16})
        agg.ingest_lines(
            "http_access.log",
            [
                '10.1.1.8 - - [31/Aug/2026:10:00:00 +0000] "GET /api/pay HTTP/1.1" 200 120 0.042',
                '10.1.1.9 - - [31/Aug/2026:10:00:01 +0000] "POST /api/pay HTTP/1.1" 500 32 1.2',
            ],
        )
        agg.ingest_lines(
            "wso2carbon.log",
            [
                "[2026-08-31 10:00:02,100] ERROR {org.apache.synapse.mediators.builtin.LogMediator} - Error: Request failed HTTP 500",
                "[2026-08-31 10:00:03,100] INFO {org.wso2.carbon.core.internal.CarbonCoreActivator} - Started",
            ],
        )
        snap = agg.snapshot()
        self.assertEqual(snap["traffic"]["total_requests"], 2)
        self.assertEqual(snap["traffic"]["http_errors"], 1)
        self.assertGreaterEqual(snap["carbon_log"]["errors"], 1)
        self.assertTrue(snap["recent_errors"])
        self.assertIn("10.1.1.8", snap["traffic"]["top_clients"])

    def test_metrics_script_parse_and_cpu(self) -> None:
        blob = (
            "HOSTNAME=apim-1\n"
            "UNAME=Linux 5.15 x86_64\n"
            "LOAD=1.23 1.10 0.90\n"
            "UPTIME=12345.0\n"
            "CPU=100 0 50 850 0 0 0 0\n"
            "MEM_TOTAL=32768000\n"
            "MEM_AVAIL=16384000\n"
            "DISK=100 70 30 70%\n"
            "NET=1000 2000\n"
            "IPS=10.50.13.126 10.50.13.1\n"
        )
        parsed = parse_metrics_script_output(blob)
        self.assertEqual(parsed["hostname"], "apim-1")
        self.assertEqual(parsed["mem_pct"], 50.0)
        self.assertEqual(parsed["disk_pct"], 70.0)
        agg = LiveAggregator(compute_allocation={"vcpu": 8})
        agg.apply_metrics(parsed, interval_seconds=5)
        parsed2 = dict(parsed)
        idle, total = parsed["cpu_idle_total"]
        parsed2["cpu_idle_total"] = (idle + 50, total + 200)
        out = agg.apply_metrics(parsed2, interval_seconds=5)
        self.assertIsNotNone(out["metrics"]["cpu_pct"])
        self.assertGreater(out["emissions"]["kg_co2_per_hour"], 0)


if __name__ == "__main__":
    unittest.main()
