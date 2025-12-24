# Attack Lab - Siren Scramble

A kid-friendly mini-game that lives inside the Attack Lab static site. It uses Alpine.js, shared styles (`lab/css/shared.css`), and lightweight scripts under `lab/js/siren-scramble`.

## Run
- Serve the `lab/` folder with any static server (or open `lab/siren-scramble.html` directly in a modern browser).
- Theme toggle, motion toggle, and mute state persist via `localStorage`.

## Test
- The game logic is covered by a small Node test. From the repo root run:
  ```bash
  node --test lab/js/tests/game-engine.test.js
  ```

## Tweak difficulty
- Edit `lab/js/siren-scramble/alert-catalog.js` to adjust steps, decoys, and UI copy.
- Tune level pacing, windows, and timers in `DEFAULT_LEVELS` within `lab/js/siren-scramble/game-engine.js`.
- Update styles in `lab/css/siren-scramble.css` (animations respect `prefers-reduced-motion`).
