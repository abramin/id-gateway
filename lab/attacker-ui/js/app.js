function attackerLab() {
  return {
    loading: false,
    scenarios: [],
    result: null,
    formatJSON(value) {
      try {
        return JSON.stringify(value, null, 2);
      } catch (_) {
        return value;
      }
    },
    async fetchScenarios() {
      try {
        const resp = await fetch('/api/scenarios');
        if (!resp.ok) {
          this.scenarios = [];
          // Optionally, handle/display error: e.g., console.error('Failed to fetch scenarios:', resp.statusText);
          return;
        }
        const json = await resp.json();
        this.scenarios = json.scenarios || [];
      } catch (err) {
        this.scenarios = [];
        // Optionally, handle/display error: e.g., console.error('Fetch error:', err);
      }
    },
    async runScenario(id) {
      this.loading = true;
      this.result = null;
      try {
        const resp = await fetch('/api/scenarios', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ scenarioId: id }),
        });
        this.result = await resp.json();
      } catch (err) {
        this.result = { scenario: { title: 'Error' }, steps: [{ title: 'Failed', response: err.message }] };
      } finally {
        this.loading = false;
      }
    },
    init() {
      this.fetchScenarios();
    }
  };
}

document.addEventListener('alpine:init', () => {
  Alpine.data('attackerLab', attackerLab);
});
