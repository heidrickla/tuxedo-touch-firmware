// The status page: live state from /ui/events, arm without a code, and a code
// pad that opens only for Disarm. Every state shown comes from the panel; the
// page keeps no timer of its own.
'use strict';

(function () {
  const $ = (id) => document.getElementById(id);
  const csrf = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
  const armButtons = Array.from(document.querySelectorAll('button.arm'));
  const disarmButton = $('disarm');
  const pad = $('pad');
  const code = $('code');
  const padOk = $('pad-ok');
  let view = null;
  let busy = false;
  let opener = null;

  function setResult(text, kind) {
    const r = $('result');
    r.textContent = text;
    r.className = 'result' + (kind ? ' ' + kind : '');
  }

  function banner(id, text) {
    const b = $(id);
    b.textContent = text || '';
    b.hidden = !text;
  }

  function updateButtons() {
    const armed = view ? view.armed : null;
    armButtons.forEach((b) => { b.disabled = busy || armed !== false; });
    disarmButton.disabled = busy || armed !== true;
  }

  function renderZones(zones) {
    const section = $('zones');
    const list = $('zone-list');
    if (!Array.isArray(zones) || zones.length === 0) {
      section.hidden = true;
      return;
    }
    list.replaceChildren(...zones.map((z) => {
      const li = document.createElement('li');
      const name = document.createElement('span');
      const state = document.createElement('span');
      name.textContent = z.name;
      state.textContent = z.state;
      state.className = 'zone-' + z.state;
      li.append(name, state);
      return li;
    }));
    section.hidden = false;
  }

  function render(v) {
    view = v;
    const h = $('headline');
    h.textContent = v.headline;
    h.className = 'headline phase-' + v.phase;
    $('status').textContent = v.status && v.status !== v.headline ? v.status : '';
    const lcd = Array.isArray(v.lcd) ? v.lcd : [];
    $('lcd1').textContent = lcd[0] || '';
    $('lcd2').textContent = lcd[1] || '';
    if (v.link === 'lost') {
      banner('link', 'The keypad cannot hear the alarm panel. What is shown may be out of date.');
    } else if (v.link === 'offline') {
      banner('link', 'The alarm panel reports itself offline or busy.');
    } else {
      banner('link', '');
    }
    updateButtons();
    renderZones(v.zones);
  }

  async function post(path, fields) {
    let r;
    try {
      r = await fetch(path, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
          'X-CSRF-Token': csrf,
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams(fields).toString(),
      });
    } catch (e) {
      return { ok: false, message: 'Could not reach the server.' };
    }
    if (r.status === 401) {
      location.assign('/login');
      return { ok: false, message: 'Signed out.' };
    }
    let body = {};
    try {
      body = await r.json();
    } catch (e) {
      body = {};
    }
    return { ok: r.ok && body.ok === true, message: body.message || 'The server answered ' + r.status + '.' };
  }

  async function send(path, fields, sending) {
    busy = true;
    updateButtons();
    setResult(sending, '');
    const r = await post(path, fields);
    busy = false;
    updateButtons();
    setResult(r.message, r.ok ? 'ok' : 'bad');
  }

  armButtons.forEach((b) => {
    b.addEventListener('click', () => {
      send('/ui/arm', { mode: b.dataset.mode }, 'Sending ' + b.textContent.toLowerCase() + '.');
    });
  });

  // The code pad. It opens only for Disarm; arming takes no code.
  function syncPad() {
    code.value = code.value.replace(/[^0-9]/g, '').slice(0, 4);
    padOk.disabled = code.value.length !== 4;
  }

  function openPad() {
    opener = document.activeElement;
    code.value = '';
    syncPad();
    pad.hidden = false;
    pad.querySelector('[data-key="1"]').focus();
  }

  function closePad() {
    pad.hidden = true;
    code.value = '';
    syncPad();
    if (opener && typeof opener.focus === 'function') {
      opener.focus();
    }
  }

  function press(key) {
    if (key === 'clear') {
      code.value = '';
    } else if (key === 'back') {
      code.value = code.value.slice(0, -1);
    } else {
      code.value += key;
    }
    syncPad();
  }

  disarmButton.addEventListener('click', openPad);
  pad.querySelectorAll('[data-key]').forEach((k) => {
    k.addEventListener('click', () => press(k.dataset.key));
  });
  code.addEventListener('input', syncPad);
  $('pad-cancel').addEventListener('click', closePad);

  pad.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      e.preventDefault();
      closePad();
      return;
    }
    if (e.target !== code && /^[0-9]$/.test(e.key)) {
      e.preventDefault();
      press(e.key);
      return;
    }
    if (e.target !== code && e.key === 'Backspace') {
      e.preventDefault();
      press('back');
      return;
    }
    if (e.key === 'Tab') {
      // Keep focus inside the dialog while it is open.
      const items = Array.from(pad.querySelectorAll('button, input')).filter((el) => !el.disabled);
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  $('pad-form').addEventListener('submit', (e) => {
    e.preventDefault();
    if (code.value.length !== 4) {
      return;
    }
    const value = code.value;
    closePad();
    send('/ui/disarm', { code: value }, 'Sending disarm.');
  });

  $('signout').addEventListener('click', async () => {
    await post('/logout', {});
    location.assign('/login');
  });

  // Live state. EventSource reconnects by itself after a dropped connection;
  // a refused one (signed out, or the server restarted and forgot the session)
  // ends CLOSED, and reloading the page lands on the sign-in page.
  const events = new EventSource('/ui/events');
  events.addEventListener('state', (e) => {
    try {
      render(JSON.parse(e.data));
    } catch (err) {
      setResult('The server sent a state this page could not read.', 'bad');
    }
  });
  events.addEventListener('open', () => banner('conn', ''));
  events.addEventListener('error', () => {
    if (events.readyState === EventSource.CLOSED) {
      banner('conn', 'Lost the connection to the server. Reloading.');
      setTimeout(() => location.assign('/'), 3000);
    } else {
      banner('conn', 'Reconnecting to the server.');
    }
  });
})();
