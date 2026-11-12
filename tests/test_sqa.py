import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import sqa


class StreamAbortFilterTests(unittest.TestCase):
    """The SQA audit must not call an intentional stream teardown a failure."""

    def test_stream_urls_match(self):
        for url in (
            "http://127.0.0.1:7857/api/v1/events/stream",
            "http://127.0.0.1:7857/api/v1/runs/run_x/events/stream",
            "http://127.0.0.1:7857/api/v1/live/stream?since=1",
        ):
            self.assertTrue(sqa._STREAM_ABORT.search(url), url)

    def test_plain_api_urls_do_not_match(self):
        for url in (
            "http://127.0.0.1:7857/api/v1/runs",
            "http://127.0.0.1:7857/api/v1/findings",
            "http://127.0.0.1:7857/api/v1/runs/run_x/events",
        ):
            self.assertIsNone(sqa._STREAM_ABORT.search(url), url)


if __name__ == "__main__":
    unittest.main()
