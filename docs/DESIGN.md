# NetCast3r visual identity

The style guide for everything this project draws: terminal output, the HTML
dashboard, README art, badges, and any future screenshots. Written the way DEF
CON writes its yearly Theme and Style Guide: one narrative, a named palette,
named type, and a rule for when each colour is allowed to appear.

Numbers below were measured out of `assets/NetCast3r-Logo.png` and
`assets/NetCast3r-Banner.png`, not guessed.

---

## 1. Theme

**Cast a net over the web.**

A hooded figure stands in total darkness and casts a glowing net. The
backdrop is void; the figure and the net are lit from within. That single
image is the whole product: a dark surface, a scarce bright signal, and
threads that catch what is moving underneath.

Two consequences, applied everywhere:

- **Black is the substrate, not a colour.** The artwork is 69.6 percent true
  black. Panels never get a lighter "card grey" that breaks the darkness.
- **Light means signal.** Anything glowing is something the tool found,
  is doing, or wants you to read. Nothing glows for decoration.

---

## 2. Palette

Measured with a median-cut histogram over the opaque pixels, then confirmed
with HSV median on the saturated population.

### Core

| Token | Hex | Hue / sat / val | Share in artwork | Role |
|-------|-----|-----------------|------------------|------|
| `void` | `#000000` | - | 48.8 % logo, 69.6 % banner | page, panel base, terminal background |
| `void-soft` | `#010101` | - | 50.0 % banner | the only "off black", for lifted surfaces |
| `acid` | `#C8F81A` | 72 deg / 0.94 / 0.97 | 2.1 % banner | **the signal colour**. Primary action, live state, verified, focus ring |
| `acid-hot` | `#F5F87D` | 60 deg / 0.50 / 0.97 | highlights | glow core, hover lift, node centres |
| `acid-dim` | `#B1E61B` | 76 deg / 0.88 / 0.90 | 2.0 % banner | links in the net, secondary signal |
| `acid-deep` | `#6CA52E` | 84 deg / 0.68 / 0.65 | 1.4 % banner | net in shadow, disabled signal |
| `acid-abyss` | `#172603` | 78 deg / 0.89 / 0.15 | 1.2 % banner | acid at rest: tracks, wells, fills behind bars |
| `violet` | `#9F23DD` | 284 deg / 0.85 / 0.87 | 2.1 % banner | structure: panel edges, shard accents, in-progress |
| `violet-deep` | `#4C2377` | 275 deg / 0.76 / 0.47 | 1.2 % banner | borders, dividers, robe shadow |
| `violet-abyss` | `#160334` | 274 deg / 0.94 / 0.20 | 1.0 % banner | deepest panel fill |
| `bone` | `#F5E9DC` | 28 deg / 0.11 / 0.96 | 2.6 % banner | **display type only**. Headings, wordmark, KPI digits |
| `bone-dim` | `#FDF7E8` | 34 deg / 0.06 / 0.99 | 1.0 % banner | brighter bone for large numerals |
| `indigo` | `#281550` | 257 deg / 0.70 / 0.31 | 1.4 % banner | cool panel fill, chart well, cityscape shadow |
| `indigo-deep` | `#170F3F` | 250 deg / 0.74 / 0.25 | 1.2 % banner | recessed areas, code blocks |
| `slate` | `#2C2C4A` | 240 deg / 0.40 / 0.29 | 1.0 % banner | hairlines on dark, table grid |
| `gold` | `#EFE4B1` | 46 deg / 0.30 / 0.94 | 0.9 % banner | **rare**. Corroborated state, hero badge, emblem only |
| `bone-dust` | `#A89591` | 12 deg / 0.10 / 0.66 | 1.4 % banner | muted body text |
| `ash` | `#9698A2` | - | - | tertiary text, captions, axis labels |

### Derived operational colours

These are computed from the palette so status colour never drifts from brand
colour. They are not new hues.

| State | Colour | Source |
|-------|--------|--------|
| `confirmed` | `#C8F81A` | acid, highest signal |
| `corroborated` | `#EFE4B1` | gold, second strongest |
| `inferred` | `#9F23DD` | violet, provisional |
| `unresolved` | `#2C2C4A` | slate, no verdict yet |
| `rejected` | `#4C2377` | violet-deep, ruled out |
| `critical` | `#C8F81A` on `#172603` | acid on acid-abyss |
| `high` | `#F5F87D` | acid-hot |
| `medium` | `#EFE4B1` | gold |
| `low` | `#A89591` | bone-dust |
| `error` | `#9F23DD` | violet, inverted meaning from normal use |

---

## 3. The scarcity rule

Taken from how the artwork actually behaves, then written down as law:

> Acid is the only colour that is allowed to grab attention, and it is never
> allowed to fill a large area.

Concretely:

1. **Acid** appears on: verified values, the live stage, the primary button,
   the focus ring, the net nodes, the active chart series, the KPI delta.
   Never on: a card background, a section background, body text, a gradient
   wash.
2. **Violet** carries structure. Borders, panel edges, the shard accents,
   in-progress states, the grid. It is the colour that holds acid in place.
3. **Bone** is type, and only display type. If it is a paragraph, it is
   `bone-dust`, not bone.
4. **Indigo** is depth: anything that should look carved into the surface
   rather than sitting on it.
5. **Gold** is used at most once per screen. Two golds on one view means the
   hierarchy is broken.

Under 8 percent of any screen may be acid by area. That is what makes it read
as designed instead of as a template.

---

## 4. Type

The artwork uses two families and nothing else.

| Role | Face | Notes |
|------|------|-------|
| Wordmark and display | brush/grunge condensed caps, hand-inked | from the logo. Only ever used for `NETCAST3R` and section titles. Never for data |
| Marker scrawl | rough marker caps, tilted 6 to 10 degrees | only for callouts: `MORE THAN JUST A CRAWLER`, `FIND VALIDATE ESCALATE` |
| Everything else | monospace | data, tables, terminal, KPI labels, axis ticks, buttons |

Rules:

- Display type is bone with an acid shadow offset 3 to 4 px, exactly as the
  `3R` sits in the wordmark.
- Monospace is the truth-telling face. A number never appears in the display
  face.
- Letter spacing on monospace labels is 0.08 em, uppercase, `bone-dust`.
- The `>`, `//`, `[*]`, and `<>` glyphs are part of the type system, not
  decoration: `>` is navigation, `//` is a list, `[*]` is a live status line,
  `<>` is code.

Web stack, free and licence-clear:

- Display: **Rubik Dirt** (brush), fallback **Anton** / system condensed
- Marker: **Permanent Marker**, fallback **Caveat**
- Mono: **JetBrains Mono**, fallback **IBM Plex Mono**, `ui-monospace`
- Body: **Inter**, fallback `system-ui`

Terminal stack: whatever the host resolves for `monospace`, with all weight
carried by colour and glyphs rather than by face.

---

## 5. Motifs

These are the shapes the artwork is built from. Each one maps to a job.

| Motif | Where it comes from | Where it is used |
|-------|--------------------|------------------|
| **Net mesh** | radial node-and-link sphere behind the figure | progress graph, crawl topology, the empty state |
| **Node glow** | acid dots where links cross | a live event, a counted item, a focus point |
| **Shatter shards** | angular violet brush shards exploding out | section transitions, the alert state, a finding landing |
| **Circuit terrain** | dark green board texture under the net | panel background at 6 percent opacity, never at full strength |
| **Scanline** | terminal CRT | one overlay across the whole page at 3 percent, 2 px pitch |
| **Grain** | print noise on the brush type | 4 percent noise over large black areas so black does not band |
| **Hairline** | 1 px `violet-deep` with an acid segment at 12 px | panel edges: the edge is violet, the corner that matters is acid |
| **Chevron rail** | `>` between pipeline stages | stage transitions, breadcrumb, table sort |
| **Prompt block** | `>_` in a box | identity lockup, command echo, footer |
| **Masked value** | `sk_live_••••••••` | every credential representation, including charts |

Geometry:

- Radius: 2 px on data chips, 6 px on panels, 12 px on cards. Never more.
- Borders: 1 px, never 2.
- Grid: 12 column, 24 px gutter, 32 px page margin.
- Depth: no drop shadows. Separation comes from a 1 px violet hairline plus a
  1 px inset black edge. Glow is permitted only on acid elements, at 0 0 16 px
  / 0.35 alpha.

---

## 6. Motion

The rule: **motion reports state, it does not decorate.**

| Event | Motion | Duration |
|-------|--------|----------|
| Stage advances | chevron fills left to right, node lights | 420 ms, `cubic-bezier(.2,.8,.2,1)` |
| Counter changes | counts up from the previous value | 700 ms ease-out |
| Finding lands | shard burst from the row, then the row settles | 260 ms, then 180 ms |
| Log line arrives | 1 line slides up 8 px and fades in | 180 ms linear |
| Panel opens | clip-path reveal from the left edge | 320 ms |
| Hover | hairline goes violet to acid, no scale | 140 ms |
| Idle | net mesh nodes pulse between 0.35 and 1.0 opacity on a 2.4 s cycle | infinite |
| Boot | `>_` types, then the six stages resolve in order | 1.6 s total, skippable |

`prefers-reduced-motion: reduce` removes the pulse, the shard burst, the
count-up, and the typewriter. The scanline and grain stay, because they are
texture, not motion.

No parallax. No scroll hijacking. No loader longer than 1.6 seconds.

---

## 7. Layout of the dashboard

Mirrors the banner, which already laid the product out correctly.

```
+--------------------------------------------------------------+
| [_] NETCAST3R   target   stage rail   live clock   [ >_ ]    |  header
+--------+-----------------------------------------------------+
|        |  KPI   KPI   KPI   KPI   KPI   KPI                  |  counters
|        +-----------------------------------------------------+
|  SIDE  |  pipeline rail: CRAWL > READ JS > HUNT > ...        |  progress
|  BAR   +---------------------------+-------------------------+
|        |  chart / net mesh         |  secret cards           |  main
|        +---------------------------+-------------------------+
|        |  findings table with state chips                    |  results
|        +-----------------------------------------------------+
|        |  >_ live log                                          |  stream
+--------+-----------------------------------------------------+
```

Sidebar is 208 px, collapses under 900 px. Header is 56 px. Log is capped at
240 px and scrolls itself.

---

## 8. Terminal

The terminal carries the same system in ANSI. It cannot do brush type, so the
identity rests on colour, glyphs, and rhythm.

- Header: `NETCAST3R` in acid with a violet underline rule, target in bone.
- Stage rail: `CRAWL > READ JS > HUNT > VALIDATE > ESCALATE > REPORT`, active
  stage acid, done stages bone-dust, pending `violet-deep`.
- Agent lines: `[recon]` padded to 11 and coloured by agent family.
- Findings: state word first, in its state colour, value masked to the same
  `sk_live_...` shape the banner uses.
- Summary: two columns, label `bone-dust`, value acid when non-zero and
  `ash` when zero.

`--no-color` and a missing `rich` both fall back to plain ASCII with the same
glyphs and no escape codes. Nothing is lost but the colour.

---

## 9. Access

- Text on `void` is checked at 4.5:1 minimum. `bone` on `void` is 17.2:1,
  `acid` on `void` is 14.6:1, `bone-dust` on `void` is 7.1:1.
- `ash` on `void` is 5.9:1 and is only used at 13 px and above.
- Every state is carried by a word as well as a colour. Colour is never the
  only channel.
- Focus ring: 1 px `acid` with a 2 px `void` offset, visible on every
  interactive element.
- All motion honours `prefers-reduced-motion`.

---

## 10. Rules that never bend

1. No model imagery, no model wording, no brains, visors, sparkles, or chat
   bubbles anywhere in the artwork, the code, the comments, or the commits.
2. No emoji. Glyphs come from the type system above.
3. No second bright hue. If it is not acid, it is violet, bone, indigo, gold,
   or a neutral.
4. No gradient background. Gradients are allowed only as the acid glow falloff
   on a single element.
5. No stock photography. The only imagery is the NetCast3r figure and the net.
6. ASCII in the repository, always.
