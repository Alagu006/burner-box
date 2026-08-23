import { writable } from 'svelte/store';

// Theme preference stored in localStorage only — never synced anywhere
const STORAGE_KEY = 'burnerbox_theme';

function createThemeStore() {
  const stored = typeof localStorage !== 'undefined' ? localStorage.getItem(STORAGE_KEY) : null;
  const initial = stored === 'light' ? 'light' : 'dark';

  const { subscribe, set, update } = writable(initial);

  function apply(theme) {
    if (typeof document !== 'undefined') {
      document.documentElement.setAttribute('data-theme', theme);
      document.documentElement.classList.toggle('light', theme === 'light');
    }
  }

  // Apply on initial load
  apply(initial);

  return {
    subscribe,
    toggle: () => {
      update(current => {
        const next = current === 'dark' ? 'light' : 'dark';
        localStorage.setItem(STORAGE_KEY, next);
        apply(next);
        return next;
      });
    },
    set: (theme) => {
      localStorage.setItem(STORAGE_KEY, theme);
      apply(theme);
      set(theme);
    },
  };
}

export const theme = createThemeStore();
