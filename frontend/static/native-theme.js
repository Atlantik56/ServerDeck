// Only presentation preferences, in this panel's private loopback origin.
// Run before the native React modules so components and charts use dark tokens.
(() => {
  const preferences = {
    'dark-mode': 'true',
    'isUltraDarkThemeEnabled': 'false',
    'lucx-theme-palette': 'default',
    'mtproxyl-panel-theme': 'dark'
  };
  try {
    for (const [key, value] of Object.entries(preferences)) localStorage.setItem(key, value);
  } catch (_) { /* The native apps retain their own storage error handling. */ }
  document.documentElement.style.colorScheme = 'dark';
  document.documentElement.setAttribute('data-theme', 'dark');
  document.documentElement.setAttribute('data-palette', 'default');
})();
