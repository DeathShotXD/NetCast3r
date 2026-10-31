import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r import training


class VerifySignalTests(unittest.TestCase):
    def test_the_current_widget_markup_counts_as_solved(self):
        body = ("<div class='widgetcontainer-lab-status is-solved'>"
                "<p>Solved</p></div>")
        self.assertTrue(training.verify_signal(body))

    def test_the_old_congratulations_banner_still_counts(self):
        self.assertTrue(training.verify_signal(
            "<h4>Congratulations, you solved the lab!</h4>"))

    def test_the_unsolved_widget_does_not_count(self):
        body = ("<div class='widgetcontainer-lab-status is-notsolved'>"
                "<p>Not solved</p></div>")
        self.assertFalse(training.verify_signal(body))

    def test_a_generic_solved_word_is_not_enough(self):
        self.assertFalse(training.verify_signal("<p>The issue is solved.</p>"))


if __name__ == "__main__":
    unittest.main()