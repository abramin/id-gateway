(function () {
  const PERSIST_KEYS = {
    mute: 'siren-scramble-mute',
    reduceMotion: 'siren-scramble-reduce-motion'
  };

  const TASKS = [
    { title: 'Secure the vault', detail: 'Tighten bolts and check the glowing lock.' },
    { title: 'Sort messages', detail: 'Slide safe mail to the inbox tray.' },
    { title: 'Check login', detail: 'Watch the radar for new sign-ins.' }
  ];

  function loadBool(key, fallback = false) {
    try {
      const value = localStorage.getItem(key);
      if (value === 'true') return true;
      if (value === 'false') return false;
    } catch (e) {
      console.warn('Unable to load preference', key, e);
    }
    return fallback;
  }

  function saveBool(key, value) {
    try {
      localStorage.setItem(key, value ? 'true' : 'false');
    } catch (e) {
      console.warn('Unable to save preference', key, e);
    }
  }

  function playChime(muted) {
    if (muted) return;
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'triangle';
      osc.frequency.setValueAtTime(660, ctx.currentTime);
      gain.gain.setValueAtTime(0.0001, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.2, ctx.currentTime + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + 0.4);
      osc.connect(gain).connect(ctx.destination);
      osc.start();
      osc.stop(ctx.currentTime + 0.45);
    } catch (e) {
      console.warn('Audio unavailable', e);
    }
  }

  document.addEventListener('alpine:init', () => {
    Alpine.data('sirenScramblePage', () => ({
      engine: null,
      level: 1,
      mode: 'task',
      countdown: 0,
      nextIn: 0,
      currentAlert: null,
      reactionMessage: null,
      nextTimer: null,
      countdownTimer: null,
      muted: loadBool(PERSIST_KEYS.mute, false),
      reduceMotion: false,
      playfulShake: false,
      task: TASKS[0],

      init() {
        this.reduceMotion = loadBool(
          PERSIST_KEYS.reduceMotion,
          window.matchMedia('(prefers-reduced-motion: reduce)').matches
        );
        this.engine = SirenGameEngine.createGameEngine(SirenAlertCatalog, { seed: Date.now() });
        this.startSession();
      },

      startSession() {
        this.engine.resetSession(this.level);
        this.task = this.randomTask();
        this.mode = 'task';
        this.reactionMessage = null;
        this.scheduleAlert();
      },

      randomTask() {
        return TASKS[Math.floor(Math.random() * TASKS.length)];
      },

      scheduleAlert() {
        clearTimeout(this.nextTimer);
        const wait = this.engine.getNextWindow();
        this.nextIn = Math.round(wait / 1000);
        this.nextTimer = setTimeout(() => this.triggerAlert(), wait);
      },

      triggerAlert() {
        this.currentAlert = this.engine.nextAlert();
        if (!this.currentAlert) return;
        this.mode = 'alert';
        this.countdown = Math.round(this.currentAlert.timeLimit);
        this.startCountdown();
        this.flashScreen();
        playChime(this.muted);
      },

      startCountdown() {
        clearInterval(this.countdownTimer);
        this.countdownTimer = setInterval(() => {
          this.countdown -= 1;
          if (this.countdown <= 0) {
            clearInterval(this.countdownTimer);
            this.handleTimeout();
          }
        }, 1000);
      },

      flashScreen() {
        if (this.reduceMotion) return;
        this.playfulShake = false;
        requestAnimationFrame(() => {
          this.playfulShake = true;
          setTimeout(() => (this.playfulShake = false), 500);
        });
      },

      handleAction(actionId) {
        const elapsed = (this.currentAlert?.timeLimit || 0) - this.countdown;
        const result = this.engine.handleAction(actionId, elapsed);
        if (result.status === 'decoy') {
          this.reactionMessage = result.reaction || 'Silly decoy! Try the defense buttons.';
          this.countdown = Math.max(0, this.countdown - 1);
          return;
        }
        if (result.status === 'progress') {
          this.reactionMessage = 'Step locked in!';
          return;
        }
        if (result.status === 'complete') {
          this.finishAlert(true);
        }
      },

      handlePasswordStrong() {
        this.handleAction('build-strong');
      },

      handleTimeout() {
        this.engine.recordTimeout();
        this.finishAlert(false);
      },

      finishAlert(success) {
        clearInterval(this.countdownTimer);
        this.mode = 'resolve';
        this.reactionMessage = success
          ? 'Defense complete! Ready for the next mission.'
          : 'Timer ran out. Hints are coming back!';

        if (success && this.engine.state.streak % 3 === 0) {
          this.engine.advanceLevel();
          this.level = this.engine.state.level;
        }

        setTimeout(() => {
          this.currentAlert = null;
          this.mode = 'task';
          this.task = this.randomTask();
          this.scheduleAlert();
        }, 1200);
      },

      toggleMute() {
        this.muted = !this.muted;
        saveBool(PERSIST_KEYS.mute, this.muted);
      },

      toggleMotion() {
        this.reduceMotion = !this.reduceMotion;
        saveBool(PERSIST_KEYS.reduceMotion, this.reduceMotion);
      },

      setLevel(level) {
        this.level = level;
        this.engine.setLevel(level);
        this.startSession();
      },

      hintIntensity() {
        return this.currentAlert?.hintIntensity || 'medium';
      }
    }));
  });
})();
