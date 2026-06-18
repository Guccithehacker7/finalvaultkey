const getToken = () => window.localStorage.getItem('vaultkey_token');

const showMessage = (elementId, message, error = false) => {
  const element = document.getElementById(elementId);
  if (!element) return;
  element.innerHTML = `<div class="${error ? 'error' : 'success'}">${message}</div>`;
};

const requestJson = async (url, options = {}) => {
  const response = await fetch(url, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.message || 'Unexpected error');
  return data;
};

const attachRegisterHandler = () => {
  const form = document.getElementById('register-form');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const email = document.getElementById('email').value.trim();
    try {
      const payload = await requestJson('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email }),
      });
      showMessage('register-output', `<strong>Registration complete.</strong><br>Download and store your certificate and private key securely.<pre>${payload.certificate_pem}</pre>`);
    } catch (error) {
      showMessage('register-output', error.message, true);
    }
  });
};

const attachLoginHandler = () => {
  const form = document.getElementById('login-form');
  if (!form) return;
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const certificatePem = document.getElementById('certificate-pem').value.trim();
    try {
      const payload = await requestJson('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ certificate_pem: certificatePem }),
      });
      window.localStorage.setItem('vaultkey_token', payload.access_token);
      showMessage('login-output', 'Login successful. JWT token stored in browser session.');
    } catch (error) {
      showMessage('login-output', error.message, true);
    }
  });
};

const attachVaultHandlers = () => {
  const form = document.getElementById('vault-form');
  const entriesContainer = document.getElementById('vault-entries');
  if (form) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const siteName = document.getElementById('site-name').value.trim();
      const password = document.getElementById('password').value;
      try {
        await requestJson('/api/vault', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${getToken()}`,
          },
          body: JSON.stringify({ site_name: siteName, password }),
        });
        showMessage('vault-output', 'Vault entry created successfully.');
        form.reset();
        loadVaultEntries();
      } catch (error) {
        showMessage('vault-output', error.message, true);
      }
    });
  }

  const loadVaultEntries = async () => {
    if (!entriesContainer) return;
    try {
      const data = await requestJson('/api/vault', {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      entriesContainer.innerHTML = data.vault_entries.length
        ? data.vault_entries.map((entry) => `<div class="entry-row"><strong>${entry.site_name}</strong><div>${entry.created_at}</div></div>`).join('')
        : '<div>No vault entries found.</div>';
    } catch (error) {
      entriesContainer.innerHTML = `<div class="error">${error.message}</div>`;
    }
  };

  loadVaultEntries();
};

const attachDocumentHandlers = () => {
  const signForm = document.getElementById('sign-form');
  const verifyForm = document.getElementById('verify-form');
  if (signForm) {
    signForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const fileName = document.getElementById('sign-file-name').value.trim();
      const hash = document.getElementById('sign-document-hash').value.trim();
      try {
        const payload = await requestJson('/api/documents/sign', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${getToken()}`,
          },
          body: JSON.stringify({ file_name: fileName, document_hash: hash }),
        });
        showMessage('sign-output', `<strong>Signature generated.</strong><pre>${payload.signature}</pre>`);
      } catch (error) {
        showMessage('sign-output', error.message, true);
      }
    });
  }

  if (verifyForm) {
    verifyForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const hash = document.getElementById('verify-document-hash').value.trim();
      const signature = document.getElementById('verify-signature').value.trim();
      const certificatePem = document.getElementById('verify-certificate-pem').value.trim();
      try {
        const payload = await requestJson('/api/documents/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ document_hash: hash, signature, certificate_pem: certificatePem }),
        });
        showMessage('verify-output', payload.valid ? 'Signature is valid.' : 'Signature is invalid.', !payload.valid);
      } catch (error) {
        showMessage('verify-output', error.message, true);
      }
    });
  }
};

const attachAdminHandlers = () => {
  const revokeForm = document.getElementById('revoke-form');
  const logsContainer = document.getElementById('audit-logs');
  const refreshButton = document.getElementById('refresh-logs');
  if (revokeForm) {
    revokeForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const serialNumber = document.getElementById('serial-number').value.trim();
      try {
        await requestJson('/api/admin/revoke', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${getToken()}`,
          },
          body: JSON.stringify({ serial_number: serialNumber }),
        });
        showMessage('revoke-output', 'Certificate revoked successfully.');
        revokeForm.reset();
      } catch (error) {
        showMessage('revoke-output', error.message, true);
      }
    });
  }

  const loadLogs = async () => {
    if (!logsContainer) return;
    try {
      const data = await requestJson('/api/admin/audit-logs?limit=50', {
        headers: { Authorization: `Bearer ${getToken()}` },
      });
      logsContainer.innerHTML = data.audit_logs.length
        ? data.audit_logs.map((log) => `<div class="log-row"><strong>${log.action}</strong> ${log.status} <span>${log.timestamp}</span><br/><small>${log.ip_address} / user:${log.user_id || 'anonymous'}</small></div>`).join('')
        : '<div>No audit logs available.</div>';
    } catch (error) {
      logsContainer.innerHTML = `<div class="error">${error.message}</div>`;
    }
  };

  if (refreshButton) {
    refreshButton.addEventListener('click', loadLogs);
  }
  loadLogs();
};

const attachPageHandlers = () => {
  attachRegisterHandler();
  attachLoginHandler();
  attachVaultHandlers();
  attachDocumentHandlers();
  attachAdminHandlers();
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', attachPageHandlers);
} else {
  attachPageHandlers();
}
