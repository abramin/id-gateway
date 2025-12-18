/**
 * Flow State Store
 * Manages the shared state for attack flow visualization
 * Used by Flow Diagram, Terminal, and Inspector windows
 */

document.addEventListener('alpine:init', () => {
  Alpine.store('flow', {
    // Current scenario
    currentScenario: '',
    scenarioName: '',

    // Step tracking
    stepIndex: -1,
    currentStep: null,
    steps: [],

    // Attack state
    isAttacking: false,
    isComplete: false,
    attackResult: null,

    // Active visualization
    activeNodes: [],
    activeConnection: null,

    // Request/Response capture
    currentRequest: null,
    currentResponse: null,
    capturedToken: null,
    capturedCode: null,

    // History of all captured data
    requestHistory: [],

    // Set a new scenario
    setScenario(scenarioId, scenarioName, steps) {
      this.currentScenario = scenarioId;
      this.scenarioName = scenarioName;
      this.steps = steps;
      this.stepIndex = -1;
      this.currentStep = null;
      this.isComplete = false;
      this.isAttacking = false;
      this.activeNodes = [];
      this.activeConnection = null;
      this.attackResult = null;
    },

    // Move to next step
    nextStep() {
      if (this.stepIndex < this.steps.length - 1) {
        this.stepIndex++;
        this.currentStep = this.steps[this.stepIndex];
        this.activeNodes = this.currentStep.nodes || [];
        this.activeConnection = this.currentStep.connection || null;
        this.isAttacking = this.currentStep.isAttack || false;

        // Simulate request/response if step has them
        if (this.currentStep.request) {
          this.currentRequest = {
            method: this.currentStep.method || 'GET',
            url: this.currentStep.request,
            headers: this.currentStep.headers || {},
            body: this.currentStep.body || null
          };
        }

        if (this.currentStep.response) {
          this.currentResponse = this.currentStep.response;
        }

        return true;
      }

      this.isComplete = true;
      this.isAttacking = false;
      return false;
    },

    // Go to previous step
    prevStep() {
      if (this.stepIndex > 0) {
        this.stepIndex--;
        this.currentStep = this.steps[this.stepIndex];
        this.activeNodes = this.currentStep.nodes || [];
        this.isComplete = false;
        return true;
      }
      return false;
    },

    // Jump to specific step
    goToStep(index) {
      if (index >= 0 && index < this.steps.length) {
        this.stepIndex = index;
        this.currentStep = this.steps[index];
        this.activeNodes = this.currentStep.nodes || [];
        this.isComplete = index === this.steps.length - 1;
        return true;
      }
      return false;
    },

    // Reset flow to beginning
    reset() {
      this.stepIndex = -1;
      this.currentStep = null;
      this.isComplete = false;
      this.isAttacking = false;
      this.activeNodes = [];
      this.activeConnection = null;
      this.currentRequest = null;
      this.currentResponse = null;
      this.attackResult = null;
    },

    // Clear everything including scenario
    clear() {
      this.currentScenario = '';
      this.scenarioName = '';
      this.steps = [];
      this.reset();
      this.capturedToken = null;
      this.capturedCode = null;
      this.requestHistory = [];
    },

    // Capture a token
    captureToken(token) {
      this.capturedToken = token;
      this.requestHistory.push({
        type: 'token',
        data: token,
        timestamp: Date.now()
      });
    },

    // Capture an authorization code
    captureCode(code) {
      this.capturedCode = code;
      this.requestHistory.push({
        type: 'code',
        data: code,
        timestamp: Date.now()
      });
    },

    // Log a request
    logRequest(request) {
      this.currentRequest = request;
      this.requestHistory.push({
        type: 'request',
        data: request,
        timestamp: Date.now()
      });
    },

    // Log a response
    logResponse(response) {
      this.currentResponse = response;
      this.requestHistory.push({
        type: 'response',
        data: response,
        timestamp: Date.now()
      });
    },

    // Set attack result
    setAttackResult(success, message) {
      this.attackResult = { success, message };
      this.isAttacking = false;
    },

    // Check if a specific node is active
    isNodeActive(nodeId) {
      return this.activeNodes.includes(nodeId);
    },

    // Get progress percentage
    get progress() {
      if (this.steps.length === 0) return 0;
      return Math.round(((this.stepIndex + 1) / this.steps.length) * 100);
    },

    // Get status text
    get statusText() {
      if (!this.currentScenario) return 'No scenario loaded';
      if (this.isComplete) return 'Attack complete';
      if (this.isAttacking) return 'Attack in progress...';
      if (this.stepIndex === -1) return 'Ready to start';
      return `Step ${this.stepIndex + 1} of ${this.steps.length}`;
    }
  });
});
