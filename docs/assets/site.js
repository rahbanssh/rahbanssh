const buttons = document.querySelectorAll('[data-copy]');

for (const button of buttons) {
  button.addEventListener('click', async () => {
    const target = document.querySelector(button.dataset.copy);
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent.trim());
      const original = button.textContent;
      button.textContent = button.dataset.success || 'Copied';
      button.dataset.copied = 'true';
      window.setTimeout(() => {
        button.textContent = original;
        delete button.dataset.copied;
      }, 1800);
    } catch {
      const range = document.createRange();
      range.selectNodeContents(target);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
  });
}

for (const year of document.querySelectorAll('[data-year]')) {
  year.textContent = String(new Date().getFullYear());
}
