// Theme bootstrap - must run in <head> BEFORE first paint to avoid FOUC.
// External (not inline) so it stays inside the page CSP `script-src 'self'`.
try {
  if (localStorage.getItem('vn_theme') === 'dark') {
    document.documentElement.setAttribute('data-theme', 'dark');
  }
} catch (e) { /* storage unavailable (private mode) */ }