import unittest

from netcast3r import theme as T


class PaletteTests(unittest.TestCase):
    def test_every_palette_entry_is_a_hex_value(self):
        self.assertEqual(len(T.PALETTE), 18)
        for name, hexv in T.PALETTE.items():
            self.assertTrue(hexv.startswith("#") and len(hexv) == 7, name)
            int(hexv[1:], 16)

    def test_core_brands_are_measured_values(self):
        self.assertEqual(T.ACID, "#C8F81A")
        self.assertEqual(T.VIOLET, "#9F23DD")
        self.assertEqual(T.BONE, "#F5E9DC")
        self.assertEqual(T.VOID, "#000000")

    def test_css_vars_cover_the_whole_palette(self):
        css = T.css_vars()
        for name, hexv in T.PALETTE.items():
            self.assertIn(f"--{name.replace('_', '-')}: {hexv};", css)

    def test_css_vars_use_hyphens_the_stylesheet_expects(self):
        css = T.css_vars()
        self.assertIn("--violet-abyss:", css)
        self.assertIn("--acid-deep:", css)
        self.assertIn("--bone-dust:", css)
        self.assertNotIn("_", css)


class PaintTests(unittest.TestCase):
    def test_paint_and_strip_roundtrip(self):
        painted = T.paint("hello", T.ACID, bold=True)
        self.assertNotEqual(painted, "hello")
        self.assertEqual(T.strip(painted), "hello")
        self.assertEqual(T.visible_len(painted), 5)

    def test_paint_disabled_is_plain(self):
        self.assertEqual(T.paint("hello", T.ACID, color_on=False), "hello")

    def test_pad_accounts_for_escape_sequences(self):
        padded = T.pad(T.paint("hi", T.ACID), 8)
        self.assertEqual(T.strip(padded), "hi      ")
        self.assertEqual(T.visible_len(padded), 8)


class ColourTests(unittest.TestCase):
    def test_mask_shape_matches_the_artwork(self):
        self.assertEqual(T.mask("sk_live_51H8xQaKz9Vb"), "sk_liv...z9Vb")
        self.assertEqual(T.mask("short"), "sh***")
        self.assertEqual(len(T.mask("x" * 40)), 13)

    def test_state_colours_follow_the_ladder(self):
        self.assertEqual(T.state_color("confirmed"), T.ACID)
        self.assertEqual(T.state_color("corroborated"), T.GOLD)
        self.assertEqual(T.state_color("inferred"), T.VIOLET)
        self.assertEqual(T.state_color("unresolved"), T.SLATE)
        self.assertEqual(T.state_color("nonsense"), T.SLATE)
        self.assertEqual(T.state_color(""), T.SLATE)

    def test_severity_colours(self):
        self.assertEqual(T.severity_color("critical"), T.ACID)
        self.assertEqual(T.severity_color("high"), T.ACID_HOT)
        self.assertEqual(T.severity_color("medium"), T.GOLD)
        self.assertEqual(T.severity_color("weird"), T.ASH)

    def test_agent_colour_falls_back(self):
        self.assertEqual(T.agent_color("recon"), T.ACID_DIM)
        self.assertEqual(T.agent_color("assayer"), T.GOLD)
        self.assertEqual(T.agent_color("unknown-agent"), T.BONE_DUST)


class StageTests(unittest.TestCase):
    def test_stage_order_matches_the_banner(self):
        labels = [s["label"] for s in T.STAGES]
        self.assertEqual(
            labels, ["CRAWL", "READ JS", "HUNT", "VALIDATE", "ESCALATE", "REPORT"]
        )

    def test_agent_maps_to_a_stage(self):
        self.assertEqual(T.stage_index("recon"), 0)
        self.assertEqual(T.stage_index("exegete"), 1)
        self.assertEqual(T.stage_index("prospector"), 2)
        self.assertEqual(T.stage_index("assayer"), 3)
        self.assertEqual(T.stage_index("chainer"), 4)
        self.assertEqual(T.stage_index("scribe"), 5)
        self.assertEqual(T.stage_index("not-an-agent"), -1)


class GlyphTests(unittest.TestCase):
    def test_glyphs_are_ascii(self):
        for glyph in (T.PROMPT, T.LIST_MARK, T.LIVE_MARK, T.CHEVRON, T.RULE):
            self.assertTrue(glyph.isascii())


if __name__ == "__main__":
    unittest.main()
