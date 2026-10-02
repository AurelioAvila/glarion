import { annualOffer } from './dist/annual-offer.js';

// Without JavaScript every offer still links to the monthly selection.
document.querySelectorAll('.purchase-options').forEach((options) => {
  options.querySelectorAll('[data-billing]').forEach((button) => {
    button.addEventListener('click', () => {
      const yearly = button.dataset.billing === 'yearly';
      options.querySelectorAll('[data-billing]').forEach((tab) => tab.setAttribute('aria-pressed', String(tab === button)));
      options.querySelectorAll('[data-plan]').forEach((card) => {
        const offer = annualOffer(Number(card.dataset.monthly), Number(card.dataset.yearly));
        card.querySelector('[data-price]').textContent = `€${yearly ? card.dataset.yearly : card.dataset.monthly}`;
        card.querySelector('[data-unit]').textContent = yearly ? '/ year' : '/ month';
        card.querySelector('[data-comparison]').hidden = !yearly;
        card.querySelector('[data-saving]').textContent = yearly
          ? `Equivalent to €${offer.monthlyEquivalent}/month. Billed €${card.dataset.yearly} yearly.`
          : `€${card.dataset.yearly}/year with annual billing · save ${offer.discount}%.`;
        card.href = `/app/#/signup?plan=${card.dataset.plan}&interval=${yearly ? 'yearly' : 'monthly'}`;
      });
    });
  });
});
