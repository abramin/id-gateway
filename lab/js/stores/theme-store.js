/**
 * Theme Store
 * Handles light/dark mode with localStorage persistence
 */

document.addEventListener('alpine:init', () => {
  const STORAGE_KEY = 'attack-lab-theme';

  // Detect system preference
  const getSystemTheme = () => {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  };

  // Load saved theme or use system preference
  const loadTheme = () => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      if (saved === 'light' || saved === 'dark') {
        return saved;
      }
    } catch (e) {
      console.warn('Failed to load theme from localStorage:', e);
    }
    return getSystemTheme();
  };

  // Apply theme to document
  const applyTheme = (theme) => {
    document.documentElement.setAttribute('data-theme', theme);
  };

  const initialTheme = loadTheme();
  applyTheme(initialTheme);

  Alpine.store('theme', {
    current: initialTheme,

    get isDark() {
      return this.current === 'dark';
    },

    get isLight() {
      return this.current === 'light';
    },

    toggle() {
      this.current = this.current === 'dark' ? 'light' : 'dark';
      this.save();
      applyTheme(this.current);
    },

    setDark() {
      this.current = 'dark';
      this.save();
      applyTheme(this.current);
    },

    setLight() {
      this.current = 'light';
      this.save();
      applyTheme(this.current);
    },

    setSystem() {
      this.current = getSystemTheme();
      localStorage.removeItem(STORAGE_KEY);
      applyTheme(this.current);
    },

    save() {
      try {
        localStorage.setItem(STORAGE_KEY, this.current);
      } catch (e) {
        console.warn('Failed to save theme to localStorage:', e);
      }
    }
  });

  // Listen for system theme changes
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    // Only auto-switch if user hasn't manually set a preference
    if (!localStorage.getItem(STORAGE_KEY)) {
      const theme = e.matches ? 'dark' : 'light';
      Alpine.store('theme').current = theme;
      applyTheme(theme);
    }
  });
});
