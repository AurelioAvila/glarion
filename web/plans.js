// Without JavaScript every offer still links to the monthly selection.
document.querySelectorAll('.purchase-options').forEach((options) => {
  options.querySelectorAll('[data-billing]').forEach((button) => {
    button.addEventListener('click', () => {
      const yearly = button.dataset.billing === 'yearly';
      options.querySelectorAll('[data-billing]').forEach((tab) => tab.setAttribute('aria-pressed', String(tab === button)));
      options.querySelectorAll('[data-plan]').forEach((card) => {
        card.querySelector('[data-price]').textContent = `€${yearly ? card.dataset.yearly : card.dataset.monthly}`;
        card.querySelector('[data-unit]').textContent = yearly ? '/ year' : '/ month';
        card.querySelector('[data-saving]').textContent = yearly
          ? `Billed yearly · save €${Number(card.dataset.monthly) * 12 - Number(card.dataset.yearly)} a year`
          : `Or €${card.dataset.yearly} / year`;
        card.href = `/app/#/signup?plan=${card.dataset.plan}&interval=${yearly ? 'yearly' : 'monthly'}`;
      });
    });
  });
});
