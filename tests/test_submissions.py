import tempfile
import unittest
from pathlib import Path

from netcast3r.server.index import Index


class SubmissionIndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.index = Index(self.tmp / "index.db")

    def tearDown(self):
        self.index.conn.close()

    def test_create_list_and_filter_submissions(self):
        mission = self.index.create_mission("Operation Test", "example.com")
        draft = self.index.create_submission(
            "Stored XSS in admin console", platform="hackerone", program="acme",
            target="app.example.com", severity="high", mission_id=mission["id"],
            bounty_cents=0, notes="drafting")
        self.assertEqual(draft["status"], "draft")
        self.assertEqual(draft["mission_title"], "Operation Test")
        self.assertEqual(draft["bounty_cents"], 0)
        self.assertIsNone(draft["submitted_at"])

        self.index.create_submission(
            "Open redirect", platform="bugcrowd", program="other", status="submitted")
        items, total = self.index.list_submissions()
        self.assertEqual(total, 2)
        self.assertEqual(len(items), 2)
        only, total = self.index.list_submissions(platform="hackerone")
        self.assertEqual(total, 1)
        self.assertEqual(only[0]["id"], draft["id"])
        by_mission, total = self.index.list_submissions(mission_id=mission["id"])
        self.assertEqual(total, 1)
        self.assertEqual(by_mission[0]["id"], draft["id"])

    def test_status_changes_stamp_times_once(self):
        submission = self.index.create_submission("IDOR", platform="hackerone")
        ready = self.index.patch_submission(submission["id"], status="ready")
        self.assertIsNone(ready["submitted_at"])
        submitted = self.index.patch_submission(submission["id"], status="submitted")
        self.assertIsNotNone(submitted["submitted_at"])
        first_submitted = submitted["submitted_at"]

        triaged = self.index.patch_submission(submission["id"], status="triaged")
        self.assertEqual(triaged["submitted_at"], first_submitted)
        self.assertIsNone(triaged["decided_at"])

        accepted = self.index.patch_submission(
            submission["id"], status="accepted", bounty_cents=50000)
        self.assertEqual(accepted["bounty_cents"], 50000)
        self.assertIsNotNone(accepted["decided_at"])
        self.assertIsNone(accepted["paid_at"])

        paid = self.index.patch_submission(submission["id"], status="paid")
        self.assertIsNotNone(paid["paid_at"])
        self.assertEqual(paid["submitted_at"], first_submitted)

    def test_summary_counts_only_recorded_rows(self):
        empty = self.index.submission_summary()
        self.assertEqual(empty["total"], 0)
        self.assertEqual(empty["by_currency"]["USD"]["awarded_cents"], 0)

        first = self.index.create_submission("One", platform="hackerone")
        second = self.index.create_submission("Two", platform="bugcrowd", status="submitted")
        self.index.patch_submission(first["id"], status="accepted", bounty_cents=25000)
        self.index.patch_submission(second["id"], status="paid", bounty_cents=10000)
        summary = self.index.submission_summary()
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["awaiting"], 0)
        self.assertEqual(summary["accepted"], 2)
        self.assertEqual(summary["paid"], 1)
        self.assertEqual(summary["by_currency"]["USD"]["awarded_cents"], 35000)
        self.assertEqual(summary["by_currency"]["USD"]["paid_cents"], 10000)

    def test_currency_is_not_summed_across_codes(self):
        usd = self.index.create_submission("USD report", platform="hackerone")
        eur = self.index.create_submission(
            "EUR report", platform="yeswehack", currency="EUR")
        self.index.patch_submission(usd["id"], status="paid", bounty_cents=10000)
        self.index.patch_submission(eur["id"], status="paid", bounty_cents=20000)
        summary = self.index.submission_summary()
        self.assertEqual(summary["by_currency"]["USD"]["paid_cents"], 10000)
        self.assertEqual(summary["by_currency"]["EUR"]["paid_cents"], 20000)

    def test_invalid_values_are_refused(self):
        with self.assertRaises(ValueError):
            self.index.create_submission("")
        with self.assertRaises(ValueError):
            self.index.create_submission("Title", platform="unknown")
        with self.assertRaises(ValueError):
            self.index.create_submission("Title", status="paid-later")
        with self.assertRaises(ValueError):
            self.index.create_submission("Title", bounty_cents=-1)
        with self.assertRaises(ValueError):
            self.index.create_submission("Title", currency="US")
        with self.assertRaises(ValueError):
            self.index.create_submission("Title", url="javascript:alert(1)")
        with self.assertRaises(ValueError):
            self.index.create_submission("Title", mission_id="msn_missing")
        with self.assertRaises(ValueError):
            self.index.create_submission("Title", finding_id="fnd_missing")

    def test_links_can_be_cleared(self):
        mission = self.index.create_mission("Operation Test", "example.com")
        submission = self.index.create_submission(
            "Linked", platform="hackerone", mission_id=mission["id"])
        cleared = self.index.patch_submission(submission["id"], mission_id="")
        self.assertEqual(cleared["mission_id"], "")

    def test_delete_removes_one_row(self):
        submission = self.index.create_submission("Delete me", platform="other")
        self.assertTrue(self.index.delete_submission(submission["id"]))
        self.assertIsNone(self.index.get_submission(submission["id"]))
        self.assertFalse(self.index.delete_submission(submission["id"]))


if __name__ == "__main__":
    unittest.main()
