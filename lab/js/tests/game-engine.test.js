const assert = require('assert');
const { describe, it } = require('node:test');
const { createGameEngine, createRNG, DEFAULT_LEVELS } = require('../siren-scramble/game-engine.js');
const { SirenAlertCatalog } = require('../siren-scramble/alert-catalog.js');

const comboFriendlyLevels = {
  1: { timerSeconds: 10, windowRange: [1000, 1000], comboAllowed: true, hintIntensity: 'high', typeWeights: { login: 5, phishing: 0, password: 0 } }
};

describe('Siren Scramble game engine', () => {
  it('creates deterministic randomness from a seed', () => {
    const rngA = createRNG(42);
    const rngB = createRNG(42);
    const seqA = [rngA(), rngA(), rngA()];
    const seqB = [rngB(), rngB(), rngB()];

    assert.deepStrictEqual(seqA, seqB);
    assert.ok(seqA[0] > 0 && seqA[0] < 1);
  });

  it('follows ordered combos and scores on completion', () => {
    const catalog = [
      {
        id: 'combo-test',
        type: 'login',
        title: 'Test Alert',
        steps: [
          { id: 'step-one', label: 'First' },
          { id: 'step-two', label: 'Second' }
        ],
        decoys: [{ id: 'decoy', reaction: 'funny' }]
      }
    ];

    const engine = createGameEngine(catalog, { seed: 1, levels: comboFriendlyLevels });
    engine.resetSession(1);
    const alert = engine.nextAlert();

    assert.strictEqual(alert.id, 'combo-test');
    const decoyResult = engine.handleAction('decoy', 0);
    assert.strictEqual(decoyResult.status, 'decoy');

    const firstStep = engine.handleAction('step-one', 2);
    assert.strictEqual(firstStep.status, 'progress');
    assert.strictEqual(alert.completedSteps.length, 1);

    const secondStep = engine.handleAction('step-two', 3);
    assert.strictEqual(secondStep.status, 'complete');
    assert.strictEqual(engine.state.mode, 'resolve');
    assert.ok(engine.state.score > 0, 'score should increase after completion');
  });

  it('resets streak on timeout', () => {
    const engine = createGameEngine(SirenAlertCatalog, { seed: 3, levels: DEFAULT_LEVELS });
    engine.resetSession(2);
    engine.nextAlert();
    engine.state.streak = 2;

    engine.recordTimeout();
    assert.strictEqual(engine.state.mode, 'resolve');
    assert.strictEqual(engine.state.streak, 0);
  });
});
