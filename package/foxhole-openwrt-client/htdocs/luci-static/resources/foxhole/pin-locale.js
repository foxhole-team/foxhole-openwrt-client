// Apply the saved appearance before the PIN form is painted.
try {
  const theme = localStorage.getItem('foxhole.theme');
  document.documentElement.classList.toggle('theme-foxhole', theme === 'foxhole');
  document.documentElement.classList.toggle('theme-light', theme === 'light');
  const chosen = localStorage.getItem('foxhole.language');
  if (['en', 'ru', 'de', 'fr', 'es', 'ja', 'zh', 'ar'].includes(chosen))
    document.documentElement.lang = chosen;
} catch {}
