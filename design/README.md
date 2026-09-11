# Depth — novel reading platform (design pass 1)

First design exploration for an immersive, animated novel-reading site, built
as a multi-artboard canvas with [Claude Design](https://claude.ai/design).

**Live design canvas:** https://claude.ai/code/artifact/0b9781a9-0840-4aca-a389-819fdcbf6eb3

## Concept

Reference points: Royal Road / Webnovel (reader UX, library/discovery
patterns) and scrollytelling/parallax sites (The Boat, Scrambler Ducati) for
the "4D" motion language — depth conveyed through drifting layered gradients,
floating particle motion, and animated hover/tilt, rather than literal 3D
geometry.

- **Typography** — Libre Caslon Display (headlines), Literata (reading body
  copy, designed for on-screen reading), Manrope (UI chrome).
- **Palette** — dark "ink" background (oklch), warm amber + cool violet
  accents at matched chroma/lightness.
- **Motion** — drifting aurora gradient blobs, upward-floating particle dust,
  cover-tilt on hover; the reader screen carries the most ambient motion
  since that's the core experience.

## Screens (`canvas/`)

- `Main.dc.html` — landing page (hero, continue reading, trending)
- `Library.dc.html` — discover/browse grid with search + genre filters
- `NovelDetail.dc.html` — novel page (synopsis, chapters, related titles)
- `Reader.dc.html` — the reading experience itself — the main "4D
  animatable" showcase
- `canvas.json` — layout of the four artboards on one pan/zoom canvas

These are the editable design sources. The full canvas (~2.5MB, editor
bundled in) is not checked into git — it's regenerated from these files and
published as the Artifact above. To regenerate it, use the Claude Design
`design` skill's `seed-canvas.mjs` helper against these `.dc.html` files.

## Status

Design only — no application code yet. Next step, pending direction
feedback: build the real front-end (routing between these screens, real
data, working reader interactions).
