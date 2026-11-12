// Team site: everything except this shell is encrypted (AES-256-GCM, key from the password with
// PBKDF2-SHA256). The page and the download are decrypted in the browser after the password is entered.
(() => {
  const $ = (id) => document.getElementById(id);
  const enc = new TextEncoder();
  const b64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const toB64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
  const STORE = 'snow-watch-site';
  let vault = null;
  let key = null;

  const msg = (t, err = true) => { $('gate-msg').textContent = t; $('gate-msg').classList.toggle('err', err); };

  async function fetchBytes(name) {
    const r = await fetch(name, { cache: 'no-store' });
    if (!r.ok) throw new Error(`${name}: ${r.status}`);
    return new Uint8Array(await r.arrayBuffer());
  }

  async function decrypt(name, k = key) {
    const buf = await fetchBytes(name);
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: buf.slice(0, 12), additionalData: enc.encode(`${vault.id}|${name}`) }, k, buf.slice(12));
    return new Uint8Array(plain);
  }

  async function derive(password) {
    const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64(vault.salt), iterations: vault.iter },
      base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }

  async function open(k) {
    const html = new TextDecoder().decode(await decrypt(vault.content, k));
    key = k;
    $('gate').hidden = true;
    const app = $('app');
    app.innerHTML = html;
    app.hidden = false;
    document.title = `SNOW Watch ${vault.version}`;
    wire(app);
  }

  function wire(app) {
    for (const b of app.querySelectorAll('[data-copy]')) {
      b.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(b.dataset.copy); } catch { return; }
        const t = b.textContent;
        b.textContent = 'Copied';
        setTimeout(() => { b.textContent = t; }, 1400);
      });
    }
    for (const b of app.querySelectorAll('[data-download]')) b.addEventListener('click', () => download(b));
    const out = app.querySelector('[data-signout]');
    if (out) out.addEventListener('click', (e) => { e.preventDefault(); try { localStorage.removeItem(STORE); } catch { /* private window */ } location.reload(); });
  }

  async function download(btn) {
    const label = btn.querySelector('span') || btn;
    const was = label.textContent;
    btn.disabled = true;
    label.textContent = 'Preparing…';
    try {
      const bytes = await decrypt(vault.zip.file);
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
      const a = document.createElement('a');
      a.href = url; a.download = vault.zip.name;
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 30000);
      label.textContent = 'Downloaded';
    } catch {
      label.textContent = 'Download failed, try again';
    } finally {
      btn.disabled = false;
      setTimeout(() => { label.textContent = was; }, 2500);
    }
  }

  $('unlock').addEventListener('submit', async (e) => {
    e.preventDefault();
    const pw = $('pw').value;
    if (!pw || !vault) return;
    $('open').disabled = true;
    msg('Opening…', false);
    try {
      const k = await derive(pw);
      await open(k);
      if ($('remember').checked) {
        try { localStorage.setItem(STORE, JSON.stringify({ salt: vault.salt, k: toB64(await crypto.subtle.exportKey('raw', k)) })); } catch { /* storage blocked */ }
      }
    } catch {
      msg('That password did not work.');
      $('pw').select();
    } finally {
      $('open').disabled = false;
    }
  });

  (async () => {
    try {
      vault = await (await fetch('vault.json', { cache: 'no-store' })).json();
    } catch {
      msg('The page could not load. Reload to try again.');
      return;
    }
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(STORE) || 'null'); } catch { /* private window */ }
    if (saved?.salt === vault.salt && saved.k) {
      try {
        const k = await crypto.subtle.importKey('raw', b64(saved.k), 'AES-GCM', true, ['decrypt']);
        await open(k);
        return;
      } catch { try { localStorage.removeItem(STORE); } catch { /* ignore */ } }
    }
    $('pw').focus();
  })();
})();
