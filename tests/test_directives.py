"""Operator directive classification and the live queue semantics."""

import os
import unittest

os.environ.setdefault("NETCAST3R_NO_KEYRING", "1")

from netcast3r.directives import (DirectiveQueue, classify, matches,
                                  matches_enough, terms_for)


class ClassifierTests(unittest.TestCase):
    def test_skip_intent_wins_over_a_bare_verb(self):
        self.assertEqual(classify("skip the admin panel test"), "skip")
        self.assertEqual(classify("park the port scan for later"), "skip")
        self.assertEqual(classify("do not test the upload path"), "skip")

    def test_focus_is_the_safe_default(self):
        self.assertEqual(classify("check the login flow for auth bypass"), "focus")
        self.assertEqual(classify("look at the reset token handling"), "focus")
        self.assertEqual(classify("probe the admin API"), "focus")

    def test_an_explicit_kind_overrides_the_words(self):
        self.assertEqual(classify("check the login flow", "skip"), "skip")
        self.assertEqual(classify("skip the login flow", "focus"), "focus")

    def test_skip_terms_keep_the_subject_and_drop_the_verb(self):
        terms = terms_for("skip the port scan for now", "skip")
        self.assertIn("port", terms)
        self.assertIn("scan", terms)
        self.assertNotIn("skip", terms)
        self.assertNotIn("now", terms)

    def test_matching_is_plural_and_prefix_aware(self):
        terms = terms_for("skip the admin panel", "skip")
        self.assertTrue(matches_enough("Map the administrators panel", terms))
        self.assertEqual(matches("probe the login form", terms), 0)

    def test_a_subjectless_skip_has_no_terms(self):
        self.assertEqual(terms_for("skip that task for now", "skip"), [])

    def test_compound_task_tokens_still_match(self):
        terms = terms_for("skip the IDOR user data test", "skip")
        self.assertIn("idor", terms)
        self.assertTrue(matches_enough(
            "Test for unauthenticated IDOR/BOLA on discovered endpoints", terms))

    def test_the_head_noun_is_enough_when_modifiers_differ(self):
        self.assertTrue(matches_enough("Probe IDOR on the billing object",
                                       ["idor", "user", "data"]))
        self.assertFalse(matches_enough("Probe the billing object",
                                        ["idor", "user", "data"]))

    def test_short_terms_never_match_inside_a_word(self):
        self.assertEqual(matches("map the support endpoints", ["port"]), 0)
        self.assertEqual(matches("map the port endpoints", ["port"]), 1)

    def test_compound_directives_split_into_words(self):
        terms = terms_for("skip the IDOR/BOLA object test", "skip")
        self.assertIn("idor", terms)
        self.assertIn("bola", terms)
        self.assertNotIn("idor/bola", terms)

    def test_stopword_plurals_do_not_leak_into_terms(self):
        terms = terms_for("Skip this task: confirm the login form is reachable",
                          "skip")
        self.assertNotIn("thi", terms)
        self.assertNotIn("is", terms)
        self.assertIn("login", terms)


class QueueTests(unittest.TestCase):
    def test_push_drain_once_and_history_survives(self):
        queue = DirectiveQueue("run_test")
        first = queue.push("check the login flow")
        self.assertEqual(first["kind"], "focus")
        self.assertEqual(first["status"], "queued")
        self.assertIn("login", first["terms"])
        self.assertEqual(queue.pending(), 1)
        batch = queue.drain()
        self.assertEqual([item["id"] for item in batch], [first["id"]])
        self.assertEqual(batch[0]["status"], "delivered")
        self.assertEqual(queue.drain(), [])
        self.assertEqual(queue.pending(), 0)
        history = queue.history()
        self.assertEqual(history[0]["id"], first["id"])
        self.assertEqual(history[0]["status"], "delivered")

    def test_an_empty_directive_is_rejected(self):
        queue = DirectiveQueue("run_test")
        with self.assertRaises(ValueError):
            queue.push("   ")

    def test_mark_updates_the_recorded_status(self):
        queue = DirectiveQueue("run_test")
        item = queue.push("skip the port scan", "skip")
        queue.mark(item["id"], "applied", "dropped one task")
        row = queue.history()[0]
        self.assertEqual(row["status"], "applied")
        self.assertEqual(row["detail"], "dropped one task")


if __name__ == "__main__":
    unittest.main()
