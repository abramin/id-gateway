(function (global) {
  function buildPasswordMeter(tiles, options) {
    const hasNumber = tiles.some((t) => /\d/.test(t));
    const hasSymbol = tiles.some((t) => /[^\w]/.test(t));
    const hasWord = tiles.some((t) => /^[A-Za-z]+$/.test(t));
    const lengthOk = tiles.length >= (options.targetLength || 3);
    const banned = (options.banned || []).some((b) => tiles.includes(b));

    if (banned) return { label: 'Too obvious', value: 25 };
    let score = 0;
    if (hasWord) score += 25;
    if (hasNumber) score += 25;
    if (hasSymbol) score += 25;
    if (lengthOk) score += 25;
    const label = score >= 75 ? 'Strong' : score >= 50 ? 'Okay' : 'Weak';
    return { label, value: score, hasNumber, hasSymbol, lengthOk };
  }

  document.addEventListener('alpine:init', () => {
    Alpine.data('alertOverlay', (options = {}) => ({
      alert: options.alert,
      countdown: options.countdown,
      reducedMotion: options.reducedMotion || false,
      onAction: options.onAction,
      showHint: options.showHint,
      playfulMessage: null,
      init() {
        this.$watch(
          () => this.$root.countdown,
          (value) => {
            this.countdown = value;
          }
        );
      },
      bounce() {
        if (this.reducedMotion) return;
        const el = this.$refs.overlay;
        if (!el) return;
        el.classList.remove('alert-pop');
        // force reflow
        void el.offsetWidth;
        el.classList.add('alert-pop');
      },
      handle(actionId) {
        if (this.onAction) {
          this.onAction(actionId);
        }
      },
      react(reaction) {
        this.playfulMessage = reaction;
        this.bounce();
        setTimeout(() => (this.playfulMessage = null), 1200);
      }
    }));

    Alpine.data('phishingCard', (alert, callbacks = {}) => ({
      alert,
      clueVisible: false,
      revealClue() {
        this.clueVisible = true;
        if (callbacks.onReveal) callbacks.onReveal();
      }
    }));

    Alpine.data('passwordBuilder', (alert, callbacks = {}) => ({
      alert,
      chosen: [],
      meter: { label: 'Weak', value: 0 },
      playful: null,
      drop(tile) {
        if (this.chosen.includes(tile)) return;
        this.chosen.push(tile);
        this.updateMeter();
      },
      removeTile(tile) {
        this.chosen = this.chosen.filter((t) => t !== tile);
        this.updateMeter();
      },
      updateMeter() {
        this.meter = buildPasswordMeter(this.chosen, this.alert.ui || {});
      },
      submit() {
        this.updateMeter();
        const { hasNumber, hasSymbol, lengthOk } = this.meter;
        const meetsRules = hasNumber && hasSymbol && lengthOk;
        if (meetsRules && callbacks.onStrong) {
          callbacks.onStrong();
          return;
        }
        this.playful = 'Add a number + symbol to power it up!';
        setTimeout(() => (this.playful = null), 1200);
      },
      decoy(reaction) {
        this.playful = reaction;
        setTimeout(() => (this.playful = null), 1000);
      }
    }));

    Alpine.data('loginCheck', (alert, callbacks = {}) => ({
      alert,
      pulse: false,
      choose(actionId) {
        if (callbacks.onAction) callbacks.onAction(actionId);
        this.triggerPulse();
      },
      triggerPulse() {
        if (this.pulse) this.pulse = false;
        requestAnimationFrame(() => {
          this.pulse = true;
          setTimeout(() => (this.pulse = false), 400);
        });
      }
    }));
  });

  const exported = { buildPasswordMeter };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exported;
  } else {
    global.SirenComponents = exported;
  }
})(typeof window !== 'undefined' ? window : globalThis);
