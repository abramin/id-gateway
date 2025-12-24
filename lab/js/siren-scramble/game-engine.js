(function (global) {
  const DEFAULT_LEVELS = {
    1: { timerSeconds: 16, windowRange: [12000, 20000], comboAllowed: false, hintIntensity: 'high', typeWeights: { phishing: 5, password: 0, login: 0 } },
    2: { timerSeconds: 14, windowRange: [12000, 19000], comboAllowed: false, hintIntensity: 'high', typeWeights: { phishing: 3, password: 2, login: 2 } },
    3: { timerSeconds: 12, windowRange: [11000, 17000], comboAllowed: true, hintIntensity: 'medium', typeWeights: { phishing: 4, password: 3, login: 2 } },
    4: { timerSeconds: 10, windowRange: [10000, 16000], comboAllowed: true, hintIntensity: 'medium', typeWeights: { phishing: 3, password: 3, login: 3 } },
    5: { timerSeconds: 9, windowRange: [9000, 15000], comboAllowed: true, hintIntensity: 'low', typeWeights: { phishing: 3, password: 3, login: 4 } }
  };

  function createRNG(seed = Date.now()) {
    let value = seed % 2147483647;
    if (value <= 0) value += 2147483646;
    return () => {
      value = (value * 48271) % 2147483647;
      return (value - 1) / 2147483646;
    };
  }

  function weightedPick(items, weightFn, rand) {
    const total = items.reduce((sum, item) => sum + weightFn(item), 0);
    if (total <= 0) return items[0];
    let threshold = rand() * total;
    for (const item of items) {
      threshold -= weightFn(item);
      if (threshold <= 0) return item;
    }
    return items[items.length - 1];
  }

  function filterByLevel(catalog, level, allowCombos) {
    return catalog.filter((alert) => {
      const within = level >= (alert.minLevel || 1) && level <= (alert.maxLevel || 5);
      if (!allowCombos && alert.steps && alert.steps.length > 1) return false;
      return within;
    });
  }

  function createGameEngine(catalog, options = {}) {
    const levels = options.levels || DEFAULT_LEVELS;
    const rng = options.seed !== undefined ? createRNG(options.seed) : Math.random;

    const state = {
      level: options.level || 1,
      score: 0,
      streak: 0,
      mode: 'task',
      currentAlert: null,
      lastResult: null
    };

    function getLevelSettings(level) {
      return levels[level] || levels[1];
    }

    function getAlertPool(level) {
      const settings = getLevelSettings(level);
      return filterByLevel(catalog, level, settings.comboAllowed);
    }

    function pickAlert(level) {
      const settings = getLevelSettings(level);
      const pool = getAlertPool(level);
      if (!pool.length) return null;
      return weightedPick(
        pool,
        (alert) => settings.typeWeights[alert.type] || 1,
        rng
      );
    }

    function buildAlertInstance(alertDef, level) {
      const settings = getLevelSettings(level);
      const timeLimit = Math.max(6, settings.timerSeconds - (alertDef.timeBonus || 0) / 2);
      return {
        ...alertDef,
        stepIndex: 0,
        completedSteps: [],
        timeLimit,
        hintIntensity: settings.hintIntensity,
        startedAt: Date.now()
      };
    }

    function nextAlert() {
      const alertDef = pickAlert(state.level);
      if (!alertDef) return null;
      state.currentAlert = buildAlertInstance(alertDef, state.level);
      state.mode = 'alert';
      return state.currentAlert;
    }

    function advanceLevel() {
      if (state.level < 5) {
        state.level += 1;
      }
    }

    function addScore(base, timeRemaining = 0) {
      const speedBonus = Math.max(0, Math.floor(timeRemaining * 2));
      const streakBonus = state.streak >= 3 ? 5 : 0;
      state.score += base + speedBonus + streakBonus;
    }

    function resolveAlert(success, timeRemaining = 0) {
      if (success) {
        state.streak += 1;
        addScore(15 * (state.currentAlert.steps.length || 1), timeRemaining);
      } else {
        state.streak = 0;
      }
      state.lastResult = success ? 'success' : 'timeout';
      state.mode = 'resolve';
    }

    function handleAction(actionId, elapsedSeconds = 0) {
      const alert = state.currentAlert;
      if (!alert) return { status: 'idle' };

      const expectedStep = alert.steps[alert.stepIndex];
      if (expectedStep && expectedStep.id === actionId) {
        alert.completedSteps.push(actionId);
        alert.stepIndex += 1;
        const remaining = Math.max(0, alert.timeLimit - elapsedSeconds);
        if (alert.stepIndex >= alert.steps.length) {
          resolveAlert(true, remaining);
          return { status: 'complete', step: actionId, remaining };
        }
        return { status: 'progress', step: actionId, remaining };
      }

      const decoy = (alert.decoys || []).find((d) => d.id === actionId);
      if (decoy) {
        state.lastResult = 'decoy';
        return { status: 'decoy', reaction: decoy.reaction, hint: expectedStep?.hint };
      }

      return { status: 'invalid' };
    }

    function recordTimeout() {
      resolveAlert(false, 0);
      return state.mode;
    }

    function getNextWindow() {
      const settings = getLevelSettings(state.level);
      const [min, max] = settings.windowRange;
      return Math.floor(min + (max - min) * rng());
    }

    function setLevel(newLevel) {
      state.level = Math.max(1, Math.min(5, newLevel));
    }

    function resetSession(level = 1) {
      state.level = level;
      state.score = 0;
      state.streak = 0;
      state.mode = 'task';
      state.currentAlert = null;
      state.lastResult = null;
    }

    return {
      state,
      nextAlert,
      handleAction,
      recordTimeout,
      getNextWindow,
      setLevel,
      resetSession,
      advanceLevel,
      getLevelSettings
    };
  }

  const exported = { createGameEngine, createRNG, weightedPick, DEFAULT_LEVELS };
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exported;
  } else {
    global.SirenGameEngine = exported;
  }
})(typeof window !== 'undefined' ? window : globalThis);
