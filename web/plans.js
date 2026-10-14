import { annualOffer } from './dist/annual-offer.js';
import { euro, mountPromo, promoPercent, promoThen } from './dist/promo.js';
import { firstChargeDate, loadPrices, priceFor, trialLine } from './dist/trial.js';

// Without JavaScript every offer still links to the monthly selection and
// shows the regular prices; a running offer replaces them only once the
// server has confirmed it, and they come back the moment it ends. The same
// goes for the three-day trial: the static page describes things as they are
// with the trial switched off, and the trial copy appears only when the
// server says it is on, with the Stripe price and the charge date in it.
const TRIAL_NOTE = (days) => `Prices exclude VAT. Choose a plan, create your account and confirm your email, then start a ${days}-day free trial or subscribe straight away. The trial needs a card or another payment method Stripe accepts, charges nothing for ${days} days and renews automatically unless you cancel before it ends. One trial per account, card and site; during the trial a plan covers up to 3 sites and its reports carry no branding.`;

let trial = null;

document.querySelectorAll('.purchase-options').forEach((options) => {
  let yearly = false;
  let view = null;

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
      paintTrial(card, yearly ? 'yearly' : 'monthly', promo);
    });
    const note = options.parentElement?.querySelector('.purchase-note');
    if (note && trial) note.textContent = TRIAL_NOTE(trial.list.trialDays);
  };

  options.querySelectorAll('[data-billing]').forEach((button) => {
    button.addEventListener('click', () => {
      yearly = button.dataset.billing === 'yearly';
      paint();
    });
  });

  mountPromo((banner) => options.querySelector('.purchase-switch').before(banner), (next) => {
    view = next;
    paint();
  });

  void loadPrices().then((list) => {
    if (!list?.trialEnabled) return;
    trial = { list, at: performance.now() };
    paint();
  });
});

// Every paid card gets the trial badge, its own action label and the line
// "Free for 3 days, then €39/month from 17 October 2026", in place of the
// Solo-only 14-day trial the static page carries.
function paintTrial(card, interval, promo) {
  if (!trial) return;
  const price = priceFor(trial.list, card.dataset.plan, interval);
  const days = trial.list.trialDays;
  let badge = card.querySelector('.purchase-trial');
  let line = card.querySelector('.purchase-trial-line');
  if (!price) {
    badge?.remove();
    line?.remove();
    return;
  }
  if (!badge) {
    badge = Object.assign(document.createElement('p'), { className: 'purchase-trial' });
    card.querySelector('.purchase-allowance').after(badge);
  }
  badge.textContent = `${days}-day free trial`;
  if (!line) {
    line = Object.assign(document.createElement('p'), { className: 'purchase-trial-line' });
    badge.after(line);
  }
  line.textContent = trialLine(days, price, firstChargeDate(trial.list, performance.now() - trial.at), promo);
  const action = card.querySelector('.purchase-action');
  if (action?.firstChild?.nodeType === Node.TEXT_NODE) action.firstChild.textContent = 'Start free trial ';
}
