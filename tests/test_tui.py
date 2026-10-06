import contextlib
import io
import unittest

from rich.panel import Panel

from netcast3r import theme as T
from netcast3r.tui import Console, Dashboard


def captured(fn):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn()
    return buf.getvalue()


class ConsoleTests(unittest.TestCase):
    def test_console_records_every_event(self):
        console = Console(show_reasoning=True, color=False)
        console.header("https://a.example")
        console.line("recon", "3 pages")
        console.reasoning("exegete", "reading files")
        console.finding("confirmed", "aws_key", "AKIA" + "x" * 30, "live")
        console.summary({"pages": 3, "findings": 1})

        kinds = [e["kind"] for e in console.events]
        self.assertEqual(kinds, ["header", "line", "reason", "finding", "summary"])
        self.assertEqual(console.events[1]["agent"], "recon")
        self.assertEqual(console.events[3]["status"], "confirmed")
        self.assertEqual(console.events[4]["data"]["pages"], 3)

    def test_console_masks_the_value_in_its_output(self):
        console = Console(color=False)
        out = captured(
            lambda: console.finding(
                "confirmed", "aws_secret_access_key", "wJalrXUtnFEMI/K7MDENG", "live"
            )
        )
        self.assertIn("wJalrX...DENG", out)
        self.assertNotIn("wJalrXUtnFEMI/K7MDENG", out)

    def test_console_without_colour_emits_no_escapes(self):
        console = Console(color=False, show_reasoning=True)

        def run():
            console.header("https://a.example")
            console.line("recon", "hello")
            console.reasoning("exegete", "reading files")
            console.finding("confirmed", "aws_key", "AKIA" + "y" * 30, "live")
            console.summary({"pages": 3, "findings": 0})

        out = captured(run)
        self.assertNotIn("\033[", out)
        self.assertIn("NETCAST3R", out)
        self.assertIn("[recon]", out)
        self.assertIn("SUMMARY", out)

    def test_console_with_colour_paints_the_accent(self):
        console = Console(color=True)
        out = captured(lambda: console.header("https://a.example"))
        self.assertIn("\033[", out)
        self.assertIn("38;2;200;248;26", out)


class DashboardTests(unittest.TestCase):
    def test_dashboard_tracks_the_stage_from_the_agent(self):
        dash = Dashboard(show_reasoning=False)
        dash.header("https://a.example")
        self.assertEqual(dash._stage, 0)
        dash.line("assayer", "planned a check")
        self.assertEqual(dash._stage, T.stage_index("assayer"))
        dash.line("scribe", "report written")
        self.assertEqual(dash._stage, 5)

    def test_dashboard_counters_drive_the_kpi_row(self):
        dash = Dashboard(show_reasoning=False)
        dash.counts(pages=12, js_files=7, verified=2)
        self.assertEqual(dash._counts["pages"], 12)
        row = T.strip(dash._kpi_row())
        self.assertIn("PAGES", row)
        self.assertIn("12", row)

    def test_dashboard_renders_a_panel_with_the_stage_rail(self):
        dash = Dashboard(show_reasoning=False)
        dash.header("https://a.example")
        dash.line("prospector", "12 candidates")
        dash.finding("confirmed", "stripe_key", "sk_live_51H8xQaKz9Vb", "livemode")
        panel = dash._render()
        self.assertIsInstance(panel, Panel)
        text = T.strip(panel.renderable.plain)
        self.assertIn("NETCAST3R", text)
        self.assertIn("VALIDATE", text)
        self.assertIn("FINDINGS", text)
        self.assertIn("sk_liv...z9Vb", text)

    def test_dashboard_records_each_event_exactly_once(self):
        dash = Dashboard(show_reasoning=False)
        dash.header("https://a.example")
        dash.line("recon", "one")
        dash.finding("inferred", "generic", "abcdef" * 8, "no recipe")
        self.assertEqual(len(dash.events), 3)

        dash._live = None
        dash.line("recon", "two")
        dash.finding("unresolved", "generic", "abcdef" * 8, "still no recipe")
        self.assertEqual(len(dash.events), 5)

    def test_dashboard_summary_sets_the_counters(self):
        dash = Dashboard(show_reasoning=False)
        dash.summary({"pages": 4, "js_files": 2, "findings": 1})
        self.assertEqual(dash._counts["pages"], 4)
        self.assertIs(dash._finished, True)
        self.assertEqual(dash._note, "done")

    def test_stage_rail_marks_progress(self):
        dash = Dashboard(show_reasoning=False)
        dash.header("https://a.example")
        dash.line("exegete", "reading")
        rail = T.strip(dash._stage_rail())
        self.assertIn("CRAWL", rail)
        self.assertIn("HUNT", rail)
        dash._finished = True
        self.assertGreater(T.strip(dash._stage_rail()).count(" "), 0)


if __name__ == "__main__":
    unittest.main()
