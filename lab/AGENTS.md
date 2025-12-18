# Attack Lab Agent Guide

This guide applies to everything under `lab/` and supplements the root `AGENTS.md` (non-negotiable). Follow the root rules first; use this to stay aligned with the Attack Lab’s stack and intent.

## Purpose
- Interactive OAuth security lab with three modules: Control Panel (toggle defenses), Dual Perspective (attacker/defender stories), and Request Forge (hands-on request builder).
- Goal: teach attacks vs. defenses through clear cause/effect, not production-hardening.

## Tech Stack
- Static HTML/CSS/JS only; no bundlers or build steps.
- Alpine.js v3 via CDN for state and interactivity. Use `Alpine.store` for shared state (`config-store.js`, `mock-api-store.js`, `flow-store.js`, `theme-store.js`) and `Alpine.data` for components.
- Reuse shared components (`lab/js/components`), utilities (`lab/js/utils` including `JWTUtils`), and data definitions (`lab/js/data`). Extend these rather than adding ad-hoc globals.
- Styles live in `lab/css`: prefer `shared.css` tokens/utilities; add module-specific rules in the matching file.
- Only add third-party libraries if they are lightweight, CDN-friendly, and justified for teaching; avoid framework swaps.

## Principles
- Keep logic readable and declarative; avoid new globals—bind behavior to Alpine components/stores.
- Preserve the educational narrative: show how toggles/config drive attack outcomes; keep copy concise and actionable.
- Mock API interactions stay local and deterministic; do not introduce real network dependencies.
- Maintain accessibility basics (semantic HTML, focusable controls, sufficient contrast) and responsive layouts.
- Favor reuse: shared animations/formatting/JWT helpers over duplicated code.

## Workflow
- Manual verification is expected: load `lab/index.html` (or run a simple static server), exercise module flows, and confirm state toggles affect visuals/results as intended.
- Place assets in `lab/images` and optimize for size; keep new data/config in `lab/js/data` or the relevant store.

