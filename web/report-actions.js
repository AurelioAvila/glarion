// The public sample shares the report renderer; its print action runs from
// this same-origin script because the website CSP disallows inline handlers.
document.querySelector('.save button')?.addEventListener('click', () => window.print());
