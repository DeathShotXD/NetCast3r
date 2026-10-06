# Banner and logo notes

Everything I found in `NetCast3r-Logo.png` and `NetCast3r-Banner.png` that is
worth fixing by hand. No file here was modified by tooling.

## Fixes needed in NetCast3r-Banner.png

| # | Region | Text as it renders now | Should read | Why it matters |
|---|--------|------------------------|-------------|----------------|
| 1 | Left column, the `//` list, 4th row down | `// ESCADATE & REPORT` | `// ESCALATE & REPORT` | The bottom pipeline rail already says `ESCALATE`, so the two disagree inside one image. |
| 2 | Right side, inside the `REPORT` panel, 2nd check row | `Ividente` | `Evidence` | Reads as a typo in the panel that is supposed to look submission-ready. |
| 3 | Bottom right corner, second line | `AI POWERED` | see below | Directly contradicts the project rule of no AI wording anywhere. |

### Suggested wording for row 3

The block currently reads:

```
OPEN SOURCE
AI POWERED
FOR SECURITY RESEARCH
```

Same three lines, same lime, same size, no layout change:

```
OPEN SOURCE
AUTONOMOUS
FOR SECURITY RESEARCH
```

Alternatives that keep the shape: `AGENT DRIVEN`, `PIPELINED`, `MODULAR`,
`EXTENSIBLE`.

## Optional polish (not blocking)

- The `REPORT` panel uses a check mark on `Submission Ready` while the rows
  above it are still unchecked. Consistent with a finished run, but if the
  panel is meant to show work in progress, drop that check.
- `PoC` and `Evidence` are check-marked, `Steps to Reproduce` is not. Order
  reads slightly out of sequence.
- The two floating `CLIENT_SECRET` cards near the centre-right overlap. Reads
  as depth on purpose, but the lower one is cut by the `REPORT` panel edge.

## Verified good, do not change

- Palette is internally consistent and matches the logo exactly:
  `#C8F81A` acid, `#9F23DD` violet, `#F5E9DC` bone, `#010101` void.
- The validation ladder `CONFIRMED / CORROBORATED / INFERRED / UNRESOLVED`
  matches the tool's own status values. Keep it.
- The six-stage rail `CRAWL > READ JS > HUNT > VALIDATE > ESCALATE > REPORT`
  matches the real pipeline. Keep it.
- Logo is RGBA with a clean transparent background. Safe for README, sidebar,
  and favicon use at any size.

## Sizes as delivered

| File | Dimensions | Mode | Size |
|------|-----------|------|------|
| `NetCast3r-Logo.png` | 1254 x 1254 | RGBA | 2.2 MB |
| `NetCast3r-Banner.png` | 1983 x 793 | RGB | 2.6 MB |

Both are far larger than README use needs. Suggested derivatives once the text
is fixed: logo 512 x 512, banner 1983 x 793 for the header plus a 1280 x 640
crop for the social card.

## Regenerating the derivatives

The four webp files the project ships are cut from these two PNGs: the README
pair in `assets/`, and the pair the HTML dashboard embeds. After any fix to the
artwork, rebuild them with:

```
python3 assets/make_webp.py
```

The script trims the logo to its alpha box, resizes both with Lanczos, and
writes `assets/logo.webp`, `assets/banner.webp`,
`src/netcast3r/dashboard/logo.webp`, and `src/netcast3r/dashboard/banner.webp`.
Then run the tests and commit the artwork with the notes.
