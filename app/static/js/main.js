/* ── Helpers ──────────────────────────────────────────── */
const TOKEN_KEY = 'vaultkey_token';
const getToken  = () => localStorage.getItem(TOKEN_KEY);
const setToken  = (t) => localStorage.setItem(TOKEN_KEY, t);
const clearToken = () => localStorage.removeItem(TOKEN_KEY);

const escapeHtml = (s) =>
  String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

const showMsg = (id, html, isError = false) => {
  const el = document.getElementById(id);
  if (el) el.innerHTML = `<div class="${isError ? 'error' : 'success'}">${html}</div>`;
};

const api = async (url, opts = {}) => {
  const res = await fetch(url, opts);
  let data;
  try { data = await res.json(); } catch { data = {}; }
  if (!res.ok) throw new Error(data.message || `Server error (${res.status})`);
  return data;
};

const authHeaders = () => ({ Authorization: `Bearer ${getToken()}` });
const jsonHeaders = () => ({ 'Content-Type': 'application/json', ...authHeaders() });

/* ── Nav sync ─────────────────────────────────────────── */
const syncNav = () => {
  const in_ = !!getToken();
  const s   = (id, v) => { const e = document.getElementById(id); if (e) e.style.display = v ? '' : 'none'; };
  s('nav-register', !in_); s('nav-login', !in_);
  s('nav-dashboard', in_); s('nav-vault', in_);
  s('nav-documents', in_); s('nav-admin', in_);
  s('nav-logout', in_);
};

/* ── Logout ───────────────────────────────────────────── */
const attachLogout = () => {
  const btn = document.getElementById('nav-logout');
  if (!btn) return;
  btn.addEventListener('click', async (e) => {
    e.preventDefault();
    try { await api('/api/auth/logout', { method: 'POST', headers: authHeaders() }); } catch {}
    clearToken(); syncNav();
    window.location.href = '/login';
  });
};

/* ── Register ─────────────────────────────────────────── */
const attachRegister = () => {
  const form = document.getElementById('register-form');
  if (!form) return;

  // Password strength meter
  const pwInput = document.getElementById('reg-password');
  if (pwInput) {
    pwInput.addEventListener('input', () => updateStrength(pwInput.value));
  }

  const generateBtn = document.getElementById('generate-password-btn');
  const toggleBtn   = document.getElementById('toggle-password-visibility');
  const confirmInput = document.getElementById('reg-password-confirm');

  const generateStrongPassword = (length = 15) => {
    const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const lower = 'abcdefghijklmnopqrstuvwxyz';
    const digits = '0123456789';
    const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';
    const charset = upper + lower + digits + symbols;

    const randChars = (set, count) => {
      const values = new Uint32Array(count);
      crypto.getRandomValues(values);
      return Array.from(values, (v) => set[v % set.length]).join('');
    };

    let password = [
      randChars(upper, 1),
      randChars(lower, 1),
      randChars(digits, 1),
      randChars(symbols, 1),
      randChars(charset, Math.max(0, length - 4)),
    ].join('');

    const data = new Uint32Array(password.length);
    crypto.getRandomValues(data);
    const passwordArr = password.split('');
    for (let i = passwordArr.length - 1; i > 0; i--) {
      const j = data[i] % (i + 1);
      [passwordArr[i], passwordArr[j]] = [passwordArr[j], passwordArr[i]];
    }
    return passwordArr.join('');
  };

  if (generateBtn && pwInput && confirmInput) {
    generateBtn.addEventListener('click', () => {
      const pwd = generateStrongPassword(15);
      pwInput.value = pwd;
      confirmInput.value = pwd;
      updateStrength(pwd);
      showMsg('register-output', 'Generated a strong password. You can edit it before submitting.');
    });
  }

  if (toggleBtn && pwInput && confirmInput) {
    toggleBtn.addEventListener('click', () => {
      const show = pwInput.type === 'password';
      pwInput.type = show ? 'text' : 'password';
      confirmInput.type = show ? 'text' : 'password';
      toggleBtn.textContent = show ? 'Hide password' : 'Show password';
    });
  }

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = form.querySelector('button[type="submit"]');
    const origText = btn ? btn.textContent : '';
    if (btn) { btn.textContent = 'Generating certificate…'; btn.disabled = true; }

    const username = document.getElementById('username').value.trim();
    const email    = document.getElementById('email').value.trim();
    const password = document.getElementById('reg-password').value;
    const confirm  = document.getElementById('reg-password-confirm').value;

    if (password !== confirm) {
      showMsg('register-output', 'Passwords do not match.', true);
      if (btn) { btn.textContent = origText; btn.disabled = false; }
      return;
    }
    if (password.length < 8) {
      showMsg('register-output', 'Password must be at least 8 characters.', true);
      if (btn) { btn.textContent = origText; btn.disabled = false; }
      return;
    }

    try {
      const data = await api('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password }),
      });

      const outEl = document.getElementById('register-output');
      if (outEl) {
        outEl.innerHTML = `<div class="success">
          <strong>Registration successful!</strong><br>
          Your X.509 certificate and RSA private key have been generated.
          <strong style="color:var(--red)"> Save your private key now — it cannot be recovered.</strong>
          <div style="display:flex;gap:10px;margin-top:14px;flex-wrap:wrap">
            <button id="dl-cert-btn" style="background:var(--primary);color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:0.85rem">Download Certificate (.pem)</button>
            <button id="dl-key-btn" style="background:var(--surface-3);color:var(--text);border:1px solid var(--border-hi);padding:8px 16px;border-radius:8px;cursor:pointer;font-size:0.85rem">Download Private Key (.pem)</button>
          </div>
          <details style="margin-top:14px">
            <summary style="cursor:pointer;color:var(--text-2);font-size:0.82rem;user-select:none">View Certificate PEM</summary>
            <pre>${escapeHtml(data.certificate_pem)}</pre>
          </details>
          <p style="margin-top:12px;font-size:0.8rem;color:var(--text-2)">You can now <a href="/login" style="color:var(--primary)">login</a> with your email and password.</p>
        </div>`;

        document.getElementById('dl-cert-btn').addEventListener('click', () =>
          downloadText('vaultkey_certificate.pem', data.certificate_pem));
        document.getElementById('dl-key-btn').addEventListener('click', () =>
          downloadText('vaultkey_private_key.pem', data.private_key_pem));
      }
    } catch (err) {
      showMsg('register-output', escapeHtml(err.message), true);
    } finally {
      if (btn) { btn.textContent = origText; btn.disabled = false; }
    }
  });
};

/* ── Login ────────────────────────────────────────────── */
const attachLogin = () => {
  // Tab switching
  const tabPw   = document.getElementById('tab-password');
  const tabCert = document.getElementById('tab-cert');
  const formPw  = document.getElementById('login-form-password');
  const formCert = document.getElementById('login-form-cert');

  if (tabPw && tabCert) {
    tabPw.addEventListener('click', () => {
      tabPw.classList.add('active'); tabCert.classList.remove('active');
      formPw.style.display = ''; formCert.style.display = 'none';
    });
    tabCert.addEventListener('click', () => {
      tabCert.classList.add('active'); tabPw.classList.remove('active');
      formCert.style.display = ''; formPw.style.display = 'none';
    });
  }

  // Email + password login
  if (formPw) {
    formPw.addEventListener('submit', async (e) => {
      e.preventDefault();
      const email    = document.getElementById('login-email').value.trim();
      const password = document.getElementById('login-password').value;
      try {
        const data = await api('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        setToken(data.access_token); syncNav();
        showMsg('login-output', 'Login successful. Redirecting…');
        setTimeout(() => { window.location.href = '/dashboard'; }, 700);
      } catch (err) {
        showMsg('login-output', err.message, true);
      }
    });
  }

  // Certificate login
  if (formCert) {
    formCert.addEventListener('submit', async (e) => {
      e.preventDefault();
      const certPem = document.getElementById('certificate-pem').value.trim();
      try {
        const data = await api('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ certificate_pem: certPem }),
        });
        setToken(data.access_token); syncNav();
        showMsg('login-output', 'Certificate login successful. Redirecting…');
        setTimeout(() => { window.location.href = '/dashboard'; }, 700);
      } catch (err) {
        showMsg('login-output', err.message, true);
      }
    });
  }
};

/* ── Dashboard ────────────────────────────────────────── */
const attachDashboard = () => {
  if (!document.getElementById('dashboard-root')) return;

  if (!getToken()) { window.location.href = '/login'; return; }

  api('/api/auth/me', { headers: authHeaders() })
    .then((d) => {
      setText('dash-username', d.username);
      const rolePill = document.getElementById('dash-role');
      if (rolePill) { rolePill.textContent = d.role; rolePill.className = `role-badge role-${d.role}`; }

      setText('stat-vault', d.stats.vault_entries);
      setText('stat-docs',  d.stats.signed_documents);

      if (d.certificate) {
        const expiry = new Date(d.certificate.expiry_date);
        const days   = Math.max(0, Math.ceil((expiry - Date.now()) / 86400000));
        setText('stat-cert-status', d.certificate.status);
        setText('stat-cert-expiry', days + ' days');
        setText('cert-serial',  d.certificate.serial_number);
        setText('cert-cn',      d.username);
        setText('cert-expiry',  expiry.toLocaleDateString());

        const pill = document.getElementById('cert-status-pill');
        if (pill) {
          pill.textContent = d.certificate.status;
          pill.className = `cert-status-pill ${d.certificate.status === 'ACTIVE' ? 'pill-active' : 'pill-revoked'}`;
        }

        // Show/hide PEM button
        const btnShow = document.getElementById('btn-show-cert');
        const pemBlock = document.getElementById('cert-pem-block');
        if (btnShow && pemBlock && d.certificate.certificate_pem) {
          pemBlock.textContent = d.certificate.certificate_pem;
          btnShow.addEventListener('click', () => {
            const hidden = pemBlock.style.display === 'none';
            pemBlock.style.display = hidden ? 'block' : 'none';
            btnShow.textContent = hidden ? 'Hide PEM' : 'Show PEM';
          });
        }

        // Download certificate
        const btnDl = document.getElementById('btn-dl-cert');
        if (btnDl && d.certificate.certificate_pem) {
          btnDl.addEventListener('click', () => {
            downloadText(`${d.username}_certificate.pem`, d.certificate.certificate_pem);
          });
        }
      } else {
        setText('stat-cert-status', 'None');
        setText('stat-cert-expiry', '—');
      }

      // Recent activity
      const actEl = document.getElementById('dash-activity');
      if (actEl) {
        if (!d.recent_activity.length) {
          actEl.innerHTML = '<div class="dash-empty">No activity yet.</div>';
        } else {
          actEl.innerHTML = d.recent_activity.map((log) => `
            <div class="activity-row">
              <span class="activity-badge ${log.status === 'SUCCESS' ? 'badge-ok' : 'badge-fail'}">${escapeHtml(log.status)}</span>
              <span class="activity-action">${escapeHtml(log.action)}</span>
              <span class="activity-time">${new Date(log.timestamp).toLocaleString()}</span>
            </div>`).join('');
        }
      }

      // Show admin card only for admins
      if (d.role === 'admin') {
        const ac = document.getElementById('admin-card');
        if (ac) ac.style.display = '';
      }
    })
    .catch((err) => {
      if (err.message.includes('401') || err.message.toLowerCase().includes('token')) {
        clearToken(); syncNav(); window.location.href = '/login';
      } else {
        showMsg('dash-output', err.message, true);
      }
    });
};

/* ── Vault ────────────────────────────────────────────── */
const attachVault = () => {
  const form    = document.getElementById('vault-form');
  const listEl  = document.getElementById('vault-entries');
  const countEl = document.getElementById('vault-count');

  const loadEntries = async () => {
    if (!listEl) return;
    try {
      const data = await api('/api/vault', { headers: authHeaders() });
      if (countEl) countEl.textContent = data.vault_entries.length;
      if (!data.vault_entries.length) {
        listEl.innerHTML = '<div class="dash-empty">No entries yet. Add one above.</div>';
        return;
      }
      listEl.innerHTML = data.vault_entries.map((entry) => `
        <div class="entry-row" data-id="${entry.id}">
          <div class="entry-top">
            <strong>${escapeHtml(entry.site_name)}</strong>
            ${entry.username_hint ? `<span class="entry-hint">${escapeHtml(entry.username_hint)}</span>` : ''}
          </div>
          <div class="entry-meta">${new Date(entry.created_at).toLocaleString()}</div>
          <div class="entry-actions">
            <button class="btn-reveal" data-id="${entry.id}">👁 Reveal</button>
            <button class="btn-delete" data-id="${entry.id}">🗑 Delete</button>
          </div>
          <div class="entry-password" id="pw-${entry.id}" style="display:none"></div>
        </div>`).join('');

      listEl.querySelectorAll('.btn-reveal').forEach((btn) => {
        btn.addEventListener('click', async () => {
          const id   = btn.dataset.id;
          const pwEl = document.getElementById(`pw-${id}`);
          if (pwEl.style.display !== 'none') {
            pwEl.style.display = 'none'; btn.textContent = '👁 Reveal'; return;
          }
          try {
            const d = await api(`/api/vault/${id}`, { headers: authHeaders() });
            pwEl.textContent = d.password;
            pwEl.style.display = 'block';
            btn.textContent = '🙈 Hide';
          } catch (err) { pwEl.textContent = err.message; pwEl.style.display = 'block'; }
        });
      });

      listEl.querySelectorAll('.btn-delete').forEach((btn) => {
        btn.addEventListener('click', async () => {
          if (!confirm('Delete this entry?')) return;
          try {
            await api(`/api/vault/${btn.dataset.id}`, { method: 'DELETE', headers: authHeaders() });
            loadEntries();
          } catch (err) { showMsg('vault-output', err.message, true); }
        });
      });
    } catch (err) {
      if (err.message.includes('401')) { clearToken(); syncNav(); window.location.href = '/login'; return; }
      if (listEl) listEl.innerHTML = `<div class="error">${escapeHtml(err.message)}</div>`;
    }
  };

  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const siteName     = document.getElementById('site-name').value.trim();
      const password     = document.getElementById('password').value;
      const usernameHint = (document.getElementById('vault-username')?.value || '').trim();
      try {
        await api('/api/vault', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({ site_name: siteName, password, username_hint: usernameHint }),
        });
        showMsg('vault-output', 'Entry stored securely ✅');
        form.reset();
        loadEntries();
      } catch (err) { showMsg('vault-output', err.message, true); }
    });
  }

  loadEntries();
};

/* ── Password Generator ───────────────────────────────── */
const attachGenerator = () => {
  const toggle   = document.getElementById('gen-toggle');
  const body     = document.getElementById('generator-body');
  const genBtn   = document.getElementById('gen-generate');
  const copyBtn  = document.getElementById('gen-copy');
  const output   = document.getElementById('gen-output');
  const slider   = document.getElementById('gen-length');
  const lenLabel = document.getElementById('gen-len-label');

  if (!toggle || !body) return;

  toggle.addEventListener('click', () => {
    const open = body.style.display !== 'none';
    body.style.display = open ? 'none' : '';
    toggle.textContent = open ? 'Show ▾' : 'Hide ▴';
  });

  if (slider && lenLabel) {
    slider.addEventListener('input', () => { lenLabel.textContent = slider.value; });
  }

  const generate = () => {
    const len  = parseInt(slider?.value || '16');
    const sets = [];
    if (document.getElementById('gen-upper')?.checked) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (document.getElementById('gen-lower')?.checked) sets.push('abcdefghijklmnopqrstuvwxyz');
    if (document.getElementById('gen-nums')?.checked)  sets.push('0123456789');
    if (document.getElementById('gen-syms')?.checked)  sets.push('!@#$%^&*()_+-=[]{}|;:,.<>?');
    if (!sets.length) { if (output) output.value = 'Select at least one character set'; return; }

    const pool = sets.join('');
    const arr  = new Uint32Array(len);
    crypto.getRandomValues(arr);
    const pwd = Array.from(arr, (n) => pool[n % pool.length]).join('');
    if (output) output.value = pwd;
  };

  if (genBtn) genBtn.addEventListener('click', generate);

  if (copyBtn && output) {
    copyBtn.addEventListener('click', async () => {
      if (!output.value) return;
      try {
        await navigator.clipboard.writeText(output.value);
        const orig = copyBtn.textContent;
        copyBtn.textContent = '✅ Copied!';
        setTimeout(() => { copyBtn.textContent = orig; }, 1500);
      } catch { output.select(); document.execCommand('copy'); }
    });
  }

  // "Use this" button fills vault password field
  if (output) {
    output.addEventListener('click', () => {
      const pwField = document.getElementById('password');
      if (pwField && output.value) { pwField.value = output.value; }
    });
  }
};

/* ── Password Strength Meter ──────────────────────────── */
const updateStrength = (pw) => {
  const bar   = document.getElementById('strength-bar');
  const label = document.getElementById('strength-label');
  if (!bar || !label) return;

  let score = 0;
  if (pw.length >= 8)  score++;
  if (pw.length >= 12) score++;
  if (/[A-Z]/.test(pw)) score++;
  if (/[0-9]/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;

  const levels = [
    { pct: '15%',  color: '#ef4444', text: 'Very Weak' },
    { pct: '30%',  color: '#f97316', text: 'Weak' },
    { pct: '55%',  color: '#eab308', text: 'Fair' },
    { pct: '80%',  color: '#22c55e', text: 'Strong' },
    { pct: '100%', color: '#10b981', text: 'Very Strong' },
  ];
  const lvl = levels[Math.max(0, Math.min(score - 1, 4))];

  if (pw.length === 0) { bar.style.width = '0'; label.textContent = '—'; return; }
  bar.style.width      = lvl.pct;
  bar.style.background = lvl.color;
  label.textContent    = lvl.text;
  label.style.color    = lvl.color;
};

/* ── Documents ────────────────────────────────────────── */
const attachDocuments = () => {
  const signForm   = document.getElementById('sign-form');
  const verifyForm = document.getElementById('verify-form');

  if (signForm) {
    signForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fileName = document.getElementById('sign-file-name').value.trim();
      const hash     = document.getElementById('sign-document-hash').value.trim();
      try {
        const d = await api('/api/documents/sign', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({ file_name: fileName, document_hash: hash }),
        });
        showMsg('sign-output', `<strong>✅ Signature generated.</strong><pre>${escapeHtml(d.signature)}</pre>`);
      } catch (err) { showMsg('sign-output', err.message, true); }
    });
  }

  if (verifyForm) {
    verifyForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const hash    = document.getElementById('verify-document-hash').value.trim();
      const sig     = document.getElementById('verify-signature').value.trim();
      const certPem = document.getElementById('verify-certificate-pem').value.trim();
      try {
        const d = await api('/api/documents/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ document_hash: hash, signature: sig, certificate_pem: certPem }),
        });
        showMsg('verify-output', d.valid ? '✅ Signature is VALID.' : '❌ Signature is INVALID.', !d.valid);
      } catch (err) { showMsg('verify-output', err.message, true); }
    });
  }
};

/* ── Admin ────────────────────────────────────────────── */
const attachAdmin = () => {
  const revokeForm = document.getElementById('revoke-form');
  const logsEl     = document.getElementById('audit-logs');
  const refreshBtn = document.getElementById('refresh-logs');

  const loadLogs = async () => {
    if (!logsEl) return;
    try {
      const d = await api('/api/admin/audit-logs?limit=50', { headers: authHeaders() });
      logsEl.innerHTML = d.audit_logs.length
        ? d.audit_logs.map((log) => `
            <div class="log-row">
              <strong>${escapeHtml(log.action)}</strong>
              <span class="${log.status === 'SUCCESS' ? '' : 'log-fail'}">${escapeHtml(log.status)}</span>
              <span>${new Date(log.timestamp).toLocaleString()}</span><br>
              <small>${escapeHtml(log.ip_address)} &nbsp;/&nbsp; user: ${log.user_id || 'anon'}</small>
            </div>`).join('')
        : '<div class="dash-empty">No audit logs yet.</div>';
    } catch (err) { logsEl.innerHTML = `<div class="error">${escapeHtml(err.message)}</div>`; }
  };

  if (revokeForm) {
    revokeForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const serial = document.getElementById('serial-number').value.trim();
      try {
        await api('/api/admin/revoke', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', ...authHeaders() },
          body: JSON.stringify({ serial_number: serial }),
        });
        showMsg('revoke-output', 'Certificate revoked successfully ✅');
        revokeForm.reset();
      } catch (err) { showMsg('revoke-output', err.message, true); }
    });
  }

  if (refreshBtn) refreshBtn.addEventListener('click', loadLogs);
  loadLogs();
};

/* ── Utilities ────────────────────────────────────────── */
const setText = (id, val) => { const e = document.getElementById(id); if (e) e.textContent = val; };

const downloadText = (filename, text) => {
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
  a.download = filename;
  a.click();
};
window.downloadText = downloadText;

/* ── Boot ─────────────────────────────────────────────── */
const boot = () => {
  syncNav();
  attachLogout();
  attachRegister();
  attachLogin();
  attachDashboard();
  attachVault();
  attachGenerator();
  attachDocuments();
  attachAdmin();
};

document.readyState === 'loading'
  ? document.addEventListener('DOMContentLoaded', boot)
  : boot();
