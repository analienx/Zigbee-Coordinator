"""Local mock NPI TCP server: no radio access or network-device commands."""
from __future__ import annotations

import asyncio
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import unittest
from unittest import mock
import json
import sys


SOURCE = (Path(__file__).resolve().parents[1] /
          "firmware/slzb-06p7u/r4/qualification/npi_startup_poll.py")
spec = importlib.util.spec_from_file_location("npi_startup_poll", SOURCE)
npi = importlib.util.module_from_spec(spec)
spec.loader.exec_module(npi)


PING = bytes.fromhex("fe02610159063d")
VERSION = bytes.fromhex("fe0a6102020002070100000000006f")


class StartupPollTests(unittest.IsolatedAsyncioTestCase):
    def test_actual_ti_version_length_and_fcs(self):
        self.assertEqual(npi.mt_response(PING, 1), bytes.fromhex("5906"))
        self.assertEqual(npi.mt_response(VERSION, 2), bytes.fromhex("02000207010000000000"))
        self.assertIsNone(npi.mt_response(VERSION[:-1] + b"\x00", 2))
        self.assertIsNone(npi.mt_response(PING, 2))
        self.assertEqual(npi.mt_response(b"noise" + PING, 1), bytes.fromhex("5906"))

    async def test_retry_after_initial_not_ready(self):
        with mock.patch.object(npi, "probe", side_effect=[TimeoutError(), True]) as fake:
            result = await npi.poll("127.0.0.1", 6638,
                                    max_seconds=2, probe_timeout=.1, retry_seconds=.05)
            self.assertTrue(result["ready"])
            self.assertEqual(result["attempts"], 2)
            self.assertGreaterEqual(result["retry_reasons"].get(
                "transport_or_response_not_ready", 0), 1)
            self.assertNotIn("02000207", str(result))
            self.assertEqual(fake.await_count, 2)

    async def test_bounded_failure_when_radio_never_responds(self):
        with mock.patch.object(npi, "probe", side_effect=TimeoutError):
            result = await npi.poll("127.0.0.1", 6638,
                                    max_seconds=.15, probe_timeout=.09, retry_seconds=.05)
            self.assertFalse(result["ready"])
            self.assertLess(result["seconds_since_reset"], 1)

    async def test_streamed_frame_and_ten_byte_version(self):
        class FakeWriter:
            def __init__(self):
                self.sent = []

            def write(self, payload):
                self.sent.append(payload)

            async def drain(self):
                return None

        writer = FakeWriter()
        reader = asyncio.StreamReader()
        reader.feed_data(b"noise" + VERSION)
        self.assertEqual(await npi.request(reader, writer, command=2, timeout=.1),
                         bytes.fromhex("02000207010000000000"))
        self.assertEqual(writer.sent, [npi.VERSION_REQUEST])


class StartupPollCommandTests(unittest.TestCase):
    def test_cli_readiness_exit_codes_and_safe_json(self):
        for ready, expected in ((True, 0), (False, 1)):
            receipt = {"ready": ready, "attempts": 3, "retry_reasons": {}}
            output = io.StringIO()
            with (mock.patch.object(sys, "argv", ["poll", "--host", "127.0.0.1"]),
                  mock.patch.object(npi, "poll", new_callable=mock.AsyncMock,
                                    return_value=receipt) as probe,
                  redirect_stdout(output)):
                self.assertEqual(npi.main(), expected)
            self.assertEqual(json.loads(output.getvalue()), receipt)
            self.assertEqual(probe.await_args.args, ("127.0.0.1", 6638))


if __name__ == "__main__":
    unittest.main()
