// Theme bootstrap - must run in <head> BEFORE first paint to avoid FOUC.
// External (not inline) so it stays inside the page CSP `script-src 'self'`.
// Precedence: an explicit choice in localStorage wins; otherwise follow the
// OS preference, so a dark-desktop first-time visitor doesn't get a white
// flash before the stylesheet loads.
try {
  var saved = localStorage.getItem('vn_theme');
  var dark = saved === 'dark' ||
    (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  if (dark) document.documentElement.setAttribute('data-theme', 'dark');
} catch (e) { /* storage/matchMedia unavailable (private mode, old browser) */ }
