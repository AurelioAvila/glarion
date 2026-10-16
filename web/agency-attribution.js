const button = document.getElementById('copy-attribution');
button?.addEventListener('click', async () => {
  const code = document.getElementById('attribution-code');
  const status = document.getElementById('copy-status');
  if (!code || !status) return;
  try {
    await navigator.clipboard.writeText(code.textContent);
    status.textContent = 'HTML copied. Add it only to a site you actually checked.';
  } catch {
    status.textContent = 'Copy is unavailable in this browser. Select the HTML above and copy it manually.';
  }
});
