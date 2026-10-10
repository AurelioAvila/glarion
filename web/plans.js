import { annualOffer } from './dist/annual-offer.js';
import { euro, promoBanner, promoPercent, promoThen, updatePromoClock, watchPromo } from './dist/promo.js';

// Without JavaScript every offer still links to the monthly selection and
// shows the regular prices; a running offer replaces them only once the
// server has confirmed it, and they come back the moment it ends.
document.querySelectorAll('.purchase-options').forEach((options) => {
  let yearly = false;
  let view = null;
  let banner = null;

  const paint = () => {
    options.querySelectorAll('[data-billing]').forEach((tab) => tab.setAttribute('aria-pressed', String((tab.dataset.billing === 'yearly') === yearly)));
    options.querySelectorAll('[data-plan]').forEach((card) => {
      const offer = annualOffer(Number(card.dataset.monthly), Number(card.dataset.yearly));
      const promo = view?.offer(card.dataset.plan, yearly ? 'yearly' : 'monthly') ?? null;
      const cost = card.querySelector('.purchase-cost');
      cost.querySelectorAll('[data-promo]').forEach((node) => node.remove());
      card.querySelector('[data-price]').textContent = promo ? euro(promo.price) : `€${yearly ? card.dataset.yearly : card.dataset.monthly}`;
      card.querySelector('[data-unit]').textContent = yearly ? '/ year' : '/ month';
      if (promo) {
        const was = Object.assign(document.createElement('s'), { textContent: euro(promo.reference) });
        const off = Object.assign(document.createElement('span'), { className: 'promo-off', textContent: `−${promoPercent(promo)}%` });
        was.dataset.promo = off.dataset.promo = '';
        cost.prepend(was);
        cost.append(off);
      }
      // One struck price at a time: during the offer the twelve-payments comparison steps aside.
      card.querySelector('[data-comparison]').hidden = !yearly || Boolean(promo);
      card.querySelector('[data-saving]').textContent = promo
        ? `${promoThen(promo)}${yearly ? '' : ` Or €${card.dataset.yearly}/year with annual billing.`}`
        : yearly
          ? `Equivalent to €${offer.monthlyEquivalent}/month. Billed €${card.dataset.yearly} yearly.`
          : `€${card.dataset.yearly}/year with annual billing · save ${offer.discount}%.`;
      card.href = `/app/#/signup?plan=${card.dataset.plan}&interval=${yearly ? 'yearly' : 'monthly'}`;
    });
  };

  options.querySelectorAll('[data-billing]').forEach((button) => {
    button.addEventListener('click', () => {
      yearly = button.dataset.billing === 'yearly';
      paint();
    });
  });

  watchPromo((next) => {
    const changed = Boolean(view?.promo) !== Boolean(next.promo);
    view = next;
    if (changed) {
      banner?.remove();
      banner = next.promo ? promoBanner(next.promo, true) : null;
      if (banner) options.querySelector('.purchase-switch').before(banner);
      paint();
    }
    if (banner) updatePromoClock(banner, next.remaining);
  });
});
