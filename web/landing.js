/*
  The free check, wired to the same endpoint the product uses. Values from
  remote sites are always rendered as text, never interpreted as markup.
*/

const api = document.querySelector('meta[name="glarion-api"]')?.content?.trim() || '';

const form = document.getElementById('check-form');
const input = document.getElementById('domain');
const button = document.getElementById('check-go');
const note = document.getElementById('check-note');
const result = document.getElementById('result');

const DEFAULT_NOTE =
  'No account, no email. This reads only what the site already publishes to every visitor.';

function setNote(text, isError) {
  note.textContent = text;
  note.classList.toggle('is-error', Boolean(isError));
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const domain = input.value.trim();
  if (!domain) {
    setNote('Enter a domain first.', true);
    input.focus();
    return;
  }

  button.disabled = true;
  button.textContent = 'Checking';
  setNote(DEFAULT_NOTE, false);
  result.hidden = false;
  result.replaceChildren();
  const running = el('ul', 'running');
  for (const step of [
    'Resolving the domain',
    'Reading the certificate',
    'Requesting the front page',
    'Looking for robots.txt and security.txt',
  ]) running.append(el('li', null, step));
  result.append(running);

  try {
    const response = await fetch(`${api}/api/preview`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ domain }),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      result.hidden = true;
      result.replaceChildren();
      setNote(payload.message || 'That domain could not be checked.', true);
      return;
    }
    render(payload);
    setNote(DEFAULT_NOTE, false);
  } catch {
    result.hidden = true;
    result.replaceChildren();
    setNote('The check could not be run. Try again in a moment.', true);
  } finally {
    button.disabled = false;
    button.textContent = 'Check';
  }
});

function render(payload) {
  const observations = Array.isArray(payload.observations) ? payload.observations : [];
  const findings = observations.filter((observation) => observation.is_finding);
  result.replaceChildren();

  const verdict = el('p', 'verdict');
  verdict.append(document.createTextNode('On '));
  verdict.append(el('strong', null, payload.domain || 'that domain'));
  verdict.append(document.createTextNode(', reading only what it publishes, '));
  if (findings.length === 0) {
    verdict.append(el('span', 'clear', 'nothing stood out'));
    verdict.append(document.createTextNode('.'));
  } else {
    verdict.append(el('span', findings.length > 2 ? 'alarm' : 'caution',
      `${findings.length} thing${findings.length === 1 ? '' : 's'}`));
    verdict.append(document.createTextNode(' stood out.'));
  }
  result.append(verdict);
  result.append(el('p', 'verdict-meta',
    `${observations.length} check${observations.length === 1 ? '' : 's'} · no account used`));

  const facts = el('div', 'facts');
  for (const observation of [...findings, ...observations.filter((item) => !item.is_finding)]) {
    const row = el('div', `fact ${observation.is_finding ? 'fact-flagged' : 'fact-ok'}`);
    row.append(el('span', 'fact-label', observation.label));
    row.append(el('span', 'fact-value', observation.value));
    facts.append(row);
  }
  result.append(facts);

  for (const text of Array.isArray(payload.notes) ? payload.notes : []) {
    result.append(el('p', 'caveat', text));
  }
  if (payload.caveat) result.append(el('p', 'caveat', payload.caveat));

  const cta = el('div', 'cta-row');
  const signup = el('a', 'primary', 'Scan this properly');
  signup.href = '/app/#/signup';
  signup.style.display = 'inline-block';
  cta.append(signup);
  cta.append(el('span', 'foot-note',
    'A full scan checks far more, and needs you to prove the domain is yours.'));
  result.append(cta);

  result.append(emailCapture(payload.domain));
}

/*
  A way to leave with the result instead of leaving with nothing.

  Signing up is four steps and an email round-trip; somebody who has just
  watched a check run on a client's domain is warm now, and asking for one
  field is the smallest thing that keeps the conversation open. The endpoint
  behind it answers identically whatever happens, so nothing here can be
  used to test which addresses exist.
*/
function emailCapture(domain) {
  const form = el('form', 'check');
  const row = el('div', 'check-row');
  const field = el('div', 'check-field');

  const label = el('label', 'check-label', 'Email me this report');
  label.htmlFor = 'preview-email';

  const email = document.createElement('input');
  email.id = 'preview-email';
  email.type = 'email';
  email.required = true;
  email.autocomplete = 'email';
  email.placeholder = 'you@agency.example';

  const send = el('button', 'ghost', 'Send it');
  send.type = 'submit';

  const note = el('p', 'check-note foot-note',
    'One message with what you just saw. No account, and nothing follows it.');

  field.append(label, email);
  row.append(field, send);
  form.append(row, note);

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const address = email.value.trim();
    if (!address) {
      note.textContent = 'Enter an address first.';
      note.classList.add('is-error');
      email.focus();
      return;
    }

    send.disabled = true;
    send.textContent = 'Sending';
    note.classList.remove('is-error');

    try {
      const response = await fetch(`${api}/api/preview/email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain, email: address }),
      });
      const payload = await response.json().catch(() => ({}));

      if (!response.ok) {
        note.textContent = payload.message || 'That could not be sent. Try again in a moment.';
        note.classList.add('is-error');
        send.disabled = false;
        send.textContent = 'Send it';
        return;
      }

      // The success answer is deliberately non-committal — see the endpoint.
      // Replacing the form rather than leaving it armed: a second identical
      // send would be refused by the cooldown, and offering an action that
      // is going to be refused reads as a broken page.
      form.replaceChildren(el('p', 'foot-note',
        payload.message || 'If that address can receive it, the report is on its way.'));
    } catch {
      note.textContent = 'That could not be sent. Try again in a moment.';
      note.classList.add('is-error');
      send.disabled = false;
      send.textContent = 'Send it';
    }
  });

  return form;
}
