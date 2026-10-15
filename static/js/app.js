// Anwendungslogik & UI Controller für Lizenzmanager

// Globaler Interceptor: CSRF-Header (X-Requested-With) & automatische Weiterleitung zum Login bei 401
const _origFetch = window.fetch;
window.fetch = async function(url, options = {}) {
  options = options || {};
  options.headers = options.headers || {};
  if (options.headers instanceof Headers) {
    if (!options.headers.has('X-Requested-With')) {
      options.headers.append('X-Requested-With', 'XMLHttpRequest');
    }
  } else if (Array.isArray(options.headers)) {
    options.headers.push(['X-Requested-With', 'XMLHttpRequest']);
  } else {
    options.headers['X-Requested-With'] = 'XMLHttpRequest';
  }

  const response = await _origFetch.call(this, url, options);
  if (response.status === 401 && !window.location.pathname.startsWith('/login')) {
    window.location.href = '/login?next=' + encodeURIComponent(window.location.pathname + window.location.search);
  }
  return response;
};

let currentTab = 'dashboard';
let currentSortField = 'expiration_date';
let currentSortOrder = 'asc';
let searchDebounceTimeout = null;
let currentLicensesCache = [];

// ==========================================
// THEME SWITCHER (Dark / Light)
// ==========================================
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  applyTheme(savedTheme);
}

function toggleTheme() {
  const current = document.documentElement.getAttribute('data-theme') || 'light';
  const target = (current === 'light') ? 'dark' : 'light';
  applyTheme(target);
  localStorage.setItem('theme', target);
  
  // Charts neu zeichnen damit Gitterlinien und Achsenfarben passen
  fetchStats();
}

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const sunIcon = document.querySelector('.theme-icon-sun');
  const moonIcon = document.querySelector('.theme-icon-moon');
  if (sunIcon && moonIcon) {
    if (theme === 'dark') {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    } else {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    }
  }
}

document.addEventListener('DOMContentLoaded', () => {
  initTheme();
  setupNavigation();
  setupFilterListeners();
  setupAiListeners();
  refreshAll();
  checkAiStatus();
  checkForUpdates(false);
});

function setupNavigation() {
  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });
}

function switchTab(tabId) {
  currentTab = tabId;

  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.getAttribute('data-tab') === tabId);
  });

  document.querySelectorAll('.tab-panel').forEach(p => {
    p.classList.toggle('active', p.id === `tab-${tabId}`);
  });

  if (tabId === 'dashboard') {
    fetchStats();
  } else if (tabId === 'licenses') {
    fetchLicenses();
  } else if (tabId === 'calendar') {
    loadCalendar();
  } else if (tabId === 'costs') {
    fetchStats();
  } else if (tabId === 'settings') {
    checkAiStatus();
    loadUsers();
  }
}

function setupFilterListeners() {
  const searchInput = document.getElementById('licenseSearch');
  if (searchInput) {
    searchInput.addEventListener('input', () => {
      clearTimeout(searchDebounceTimeout);
      searchDebounceTimeout = setTimeout(() => {
        fetchLicenses();
      }, 250);
    });
  }

  const statusFilter = document.getElementById('filterStatus');
  if (statusFilter) {
    statusFilter.addEventListener('change', () => fetchLicenses());
  }

  const catFilter = document.getElementById('filterCategory');
  if (catFilter) {
    catFilter.addEventListener('change', () => fetchLicenses());
  }

  const sortSelect = document.getElementById('sortField');
  if (sortSelect) {
    sortSelect.addEventListener('change', (e) => {
      currentSortField = e.target.value;
      fetchLicenses();
    });
  }
}

function refreshAll() {
  fetchStats();
  fetchLicenses();
  loadCalendar();
}

// ==========================================
// API & STATS
// ==========================================
async function fetchStats() {
  try {
    const res = await fetch('/api/stats');
    const stats = await res.json();
    renderStats(stats);
  } catch (err) {
    console.error('Fehler beim Abrufen der Statistiken:', err);
  }
}

function renderStats(stats) {
  // Header Badges
  const headerActive = document.getElementById('headerActiveCount');
  if (headerActive) headerActive.textContent = `${stats.active_count} aktiv`;

  const tabBadge = document.getElementById('tabUrgentBadge');
  if (tabBadge) {
    if (stats.urgent_count > 0) {
      tabBadge.textContent = stats.urgent_count;
      tabBadge.style.display = 'inline-block';
    } else {
      tabBadge.style.display = 'none';
    }
  }

  // Dashboard KPIs
  document.getElementById('kpiActiveCount').textContent = stats.active_count;
  document.getElementById('kpiUrgentCount').textContent = stats.urgent_count;
  document.getElementById('kpiMrr').textContent = formatCurrency(stats.total_mrr);
  document.getElementById('kpiArr').textContent = formatCurrency(stats.total_arr);
  document.getElementById('kpiCostNext30').textContent = `${formatCurrency(stats.cost_next_30)} anstehend`;
  const kpiSeats = document.getElementById('kpiTotalSeats');
  if (kpiSeats) {
    kpiSeats.textContent = `${stats.total_seats_used !== undefined ? stats.total_seats_used : 0} von ${stats.total_seats || 0} Plätzen genutzt`;
  }

  // Costs Tab KPIs
  const costMrr = document.getElementById('costMrr');
  if (costMrr) costMrr.textContent = formatCurrency(stats.total_mrr);
  const costArr = document.getElementById('costArr');
  if (costArr) costArr.textContent = formatCurrency(stats.total_arr);
  const costNext90 = document.getElementById('costNext90');
  if (costNext90) costNext90.textContent = formatCurrency(stats.cost_next_90);

  // Urgent Banner
  const banner = document.getElementById('urgentAlertBanner');
  const bannerCount = document.getElementById('urgentBannerCount');
  const bannerList = document.getElementById('urgentBannerList');

  if (stats.urgent_licenses && stats.urgent_licenses.length > 0) {
    banner.style.display = 'flex';
    bannerCount.textContent = stats.urgent_licenses.length;
    let bHtml = '';
    stats.urgent_licenses.slice(0, 6).forEach(lic => {
      let deadlineText = '';
      if (lic.cancellation_deadline) {
        deadlineText = `Kündigungsfrist: ${formatGermanDate(lic.cancellation_deadline)}`;
      } else if (lic.expiration_date) {
        deadlineText = `Ablauf: ${formatGermanDate(lic.expiration_date)}`;
      }

      bHtml += `
        <div class="urgent-item-card">
          <div class="urgent-item-info">
            <span class="urgent-item-name">${escapeHtml(lic.name)}</span>
            <span class="urgent-item-meta">${deadlineText} • ${escapeHtml(lic.badge_label)}</span>
          </div>
          <div style="display:flex; gap:0.35rem;">
            ${isCurrentUserAdmin() ? `
              <button class="btn btn-sm btn-primary" onclick="quickRenewLicense(${lic.id})" title="Um 1 Zyklus verlängern">
                Verlängern
              </button>
              <button class="btn btn-sm btn-secondary" onclick="openLicenseModal(${lic.id})">
                Bearbeiten
              </button>
            ` : `
              <button class="btn btn-sm btn-secondary" onclick="openDetailModalById(${lic.id})">
                Details
              </button>
            `}
          </div>
        </div>
      `;
    });
    bannerList.innerHTML = bHtml;
  } else {
    banner.style.display = 'none';
  }

  // Dashboard Diagramme
  if (stats.monthly_renewal_forecast) {
    initOrUpdateForecastChart(stats.monthly_renewal_forecast);
  }
  if (stats.category_costs) {
    initOrUpdateCategoriesChart(stats.category_costs);
  }

  // Kosten Tab Diagramme & Listen
  if (stats.vendor_costs) {
    initOrUpdateVendorsChart(stats.vendor_costs);
  }

  // Top Expensive List
  const topTable = document.getElementById('topCostTableBody');
  if (topTable && stats.top_expensive) {
    let tHtml = '';
    stats.top_expensive.forEach(lic => {
      tHtml += `
        <tr>
          <td><strong>${escapeHtml(lic.name)}</strong><br><span style="font-size:0.75rem; color:var(--text-secondary);">${escapeHtml(lic.vendor || '')}</span></td>
          <td>${formatCycleName(lic.billing_cycle, lic.billing_cycle_months)}</td>
          <td style="font-weight:600; font-variant-numeric: tabular-nums;">${formatCurrency(lic.yearly_equivalent)}</td>
        </tr>
      `;
    });
    topTable.innerHTML = tHtml || '<tr><td colspan="3" style="text-align:center;">Keine Daten</td></tr>';
  }
}

// ==========================================
// LICENSES TABLE & FILTERING
// ==========================================
async function fetchLicenses() {
  const search = document.getElementById('licenseSearch')?.value || '';
  const status = document.getElementById('filterStatus')?.value || 'all';
  const category = document.getElementById('filterCategory')?.value || 'all';

  const params = new URLSearchParams({
    search: search,
    status: status,
    category: category,
    sort_by: currentSortField,
    sort_order: currentSortOrder
  });

  try {
    const res = await fetch(`/api/licenses?${params.toString()}`);
    const licenses = await res.json();
    currentLicensesCache = licenses;
    renderLicenseTable(licenses);
    renderDashboardUpcomingTable(licenses);
  } catch (err) {
    console.error('Fehler beim Abrufen der Lizenzen:', err);
  }
}

function setSort(field) {
  if (currentSortField === field) {
    currentSortOrder = (currentSortOrder === 'asc' ? 'desc' : 'asc');
  } else {
    currentSortField = field;
    currentSortOrder = 'asc';
  }
  const sortSelect = document.getElementById('sortField');
  if (sortSelect) sortSelect.value = field;
  fetchLicenses();
}

function filterByUrgent() {
  switchTab('licenses');
  const sel = document.getElementById('filterStatus');
  if (sel) {
    sel.value = 'urgent';
    fetchLicenses();
  }
}

function renderLicenseTable(licenses) {
  const tbody = document.getElementById('licenseTableBody');
  if (!tbody) return;

  if (licenses.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="10" style="text-align:center; padding: 2.5rem; color: var(--text-tertiary);">
          Keine Lizenzen gefunden. <br>
          <button class="btn btn-primary btn-sm" style="margin-top:0.75rem;" onclick="openLicenseModal()">
            Neue Lizenz erfassen
          </button>
        </td>
      </tr>
    `;
    return;
  }

  const isAdmin = isCurrentUserAdmin();
  let html = '';
  licenses.forEach(lic => {
    const badgeClass = `badge badge-${escapeHtml(lic.badge_color || 'green')}`;
    const seatsUsed = (lic.seats_used !== undefined && lic.seats_used !== null) ? lic.seats_used : 0;
    const seatsTotal = lic.seats_total || 1;
    const seatPercent = Math.min(100, Math.round((seatsUsed / seatsTotal) * 100));

    let expDisplay = '<span style="color:var(--text-tertiary);">Unbefristet</span>';
    if (lic.expiration_date) {
      expDisplay = `<strong>${formatGermanDate(lic.expiration_date)}</strong>`;
      if (lic.days_until_expiration !== null) {
        if (lic.days_until_expiration < 0) {
          expDisplay += `<br><span style="font-size:0.72rem; color:var(--status-urgent-dot); font-weight:600;">vor ${Math.abs(lic.days_until_expiration)} Tagen abgelaufen</span>`;
        } else if (lic.days_until_expiration === 0) {
          expDisplay += `<br><span style="font-size:0.72rem; color:var(--status-urgent-dot); font-weight:600;">Heute fällig</span>`;
        } else {
          expDisplay += `<br><span style="font-size:0.72rem; color:var(--text-secondary);">in ${escapeHtml(lic.days_until_expiration)} Tagen</span>`;
        }
      }
    }

    let candDisplay = '-';
    if (lic.cancellation_deadline && lic.auto_renewal) {
      candDisplay = `<strong>${formatGermanDate(lic.cancellation_deadline)}</strong>`;
      if (lic.days_until_cancellation !== null) {
        if (lic.days_until_cancellation < 0) {
          candDisplay += `<br><span style="font-size:0.72rem; color:var(--status-warning-dot);">Frist verpasst</span>`;
        } else {
          candDisplay += `<br><span style="font-size:0.72rem; color:var(--text-secondary);">in ${escapeHtml(lic.days_until_cancellation)} Tagen</span>`;
        }
      }
    }

    const keyMasked = lic.license_key ? (
      lic.license_key.length > 15 ? (lic.license_key.slice(0, 5) + '...' + lic.license_key.slice(-4)) : lic.license_key
    ) : '-';

    html += `
      <tr>
        <td>
          <span class="${badgeClass}">
            <span class="badge-dot"></span>
            ${escapeHtml(lic.badge_label || 'Aktiv')}
          </span>
        </td>
        <td>
          <strong style="cursor:pointer;" onclick="openDetailModalById(${lic.id})">${escapeHtml(lic.name)}</strong>
          ${lic.login_portal_url && sanitizeUrl(lic.login_portal_url) ? `<a href="${sanitizeUrl(lic.login_portal_url)}" target="_blank" rel="noopener noreferrer" title="Portal öffnen" style="font-size:0.75rem; margin-left:0.35rem; color:var(--accent); text-decoration:none;">↗</a>` : ''}
          ${lic.assigned_to ? `<br><span style="font-size:0.72rem; color:var(--text-secondary);">${escapeHtml(lic.assigned_to)}</span>` : ''}
        </td>
        <td>${escapeHtml(lic.vendor || '-')}</td>
        <td><span style="font-size:0.75rem; color:var(--text-secondary); background:var(--bg-subtle); padding:2px 6px; border-radius:4px; border:1px solid var(--border);">${escapeHtml(lic.category || 'Sonstiges')}</span></td>
        <td>
          <div class="seats-bar-wrap">
            <span style="font-size:0.72rem; font-variant-numeric: tabular-nums;">${seatsUsed} / ${seatsTotal}</span>
            <div class="seats-bar">
              <div class="seats-bar-fill" style="width: ${seatPercent}%;"></div>
            </div>
          </div>
        </td>
        <td>${expDisplay}</td>
        <td>${candDisplay}</td>
        <td>
          <strong style="font-variant-numeric: tabular-nums;">${formatCurrency(lic.cost || 0)}</strong>
          <br><span style="font-size:0.72rem; color:var(--text-secondary);">${formatCycleName(lic.billing_cycle, lic.billing_cycle_months)}</span>
        </td>
        <td>
          ${lic.license_key ? `
            <button class="btn btn-secondary btn-sm" onclick="copyKeyById(${lic.id})" title="Schlüssel kopieren">
              <code class="code-mono">${escapeHtml(keyMasked)}</code>
            </button>
          ` : '<span style="color:var(--text-tertiary);">-</span>'}
        </td>
        <td style="text-align: right;">
          <div style="display:inline-flex; gap:0.25rem;">
            ${isAdmin ? `
              ${lic.expiration_date ? `
                <button class="btn btn-secondary btn-sm" onclick="quickRenewLicense(${lic.id})" title="Schnell-Verlängerung (+1 Intervall)">
                  Verlängern
                </button>
              ` : ''}
              <button class="btn btn-secondary btn-sm" onclick="openLicenseModal(${lic.id})" title="Bearbeiten">
                Bearbeiten
              </button>
            ` : ''}
            <button class="btn btn-secondary btn-sm" onclick="openDetailModalById(${lic.id})" title="Details">
              Details
            </button>
            ${isAdmin ? `
              <button class="btn btn-secondary btn-sm" onclick="confirmDeleteLicense(${lic.id})" title="Löschen" style="color:var(--status-urgent-dot);">
                ✕
              </button>
            ` : ''}
          </div>
        </td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

function renderDashboardUpcomingTable(licenses) {
  const tbody = document.getElementById('dashboardUpcomingTable');
  if (!tbody) return;

  const upcoming = licenses
    .filter(l => l.status === 'active' && l.expiration_date)
    .sort((a, b) => (a.days_until_expiration || 9999) - (b.days_until_expiration || 9999))
    .slice(0, 5);

  if (upcoming.length === 0) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:1.5rem; color:var(--text-tertiary);">Keine anstehenden Verlängerungen.</td></tr>`;
    return;
  }

  let html = '';
  upcoming.forEach(lic => {
    html += `
      <tr>
        <td>
          <span class="badge badge-${escapeHtml(lic.badge_color || 'green')}">
            <span class="badge-dot"></span>
            ${escapeHtml(lic.badge_label)}
          </span>
        </td>
        <td><strong>${escapeHtml(lic.name)}</strong></td>
        <td>${escapeHtml(lic.vendor || '-')}</td>
        <td>${lic.cancellation_deadline ? formatGermanDate(lic.cancellation_deadline) : '-'}</td>
        <td><strong>${formatGermanDate(lic.expiration_date)}</strong></td>
        <td style="font-variant-numeric: tabular-nums;">${formatCurrency(lic.cost || 0)} <span style="font-size:0.75rem; color:var(--text-secondary);">(${formatCycleName(lic.billing_cycle, lic.billing_cycle_months)})</span></td>
        <td>
          <button class="btn btn-sm btn-primary" onclick="quickRenewLicense(${lic.id})">
            Verlängern
          </button>
        </td>
      </tr>
    `;
  });

  tbody.innerHTML = html;
}

// ==========================================
// FORM MODAL & CRUD
// ==========================================
function openLicenseModal(licenseId = null) {
  const modal = document.getElementById('licenseModal');
  const title = document.getElementById('licenseModalTitle');
  const form = document.getElementById('licenseForm');
  form.reset();

  clearAiDraftNotice();

  const quickBox = document.getElementById('aiQuickImportBox');
  if (quickBox) {
    quickBox.style.display = licenseId ? 'none' : 'flex';
  }

  document.getElementById('formLicenseId').value = licenseId || '';

  if (licenseId) {
    title.textContent = 'Lizenz bearbeiten';
    fetch(`/api/licenses/${licenseId}`)
      .then(res => res.json())
      .then(lic => {
        document.getElementById('formName').value = lic.name || '';
        document.getElementById('formVendor').value = lic.vendor || '';
        document.getElementById('formCategory').value = lic.category || 'Sonstiges';
        document.getElementById('formLicenseType').value = lic.license_type || 'subscription';
        if (document.getElementById('formStatus')) {
          document.getElementById('formStatus').value = lic.status || 'active';
        }
        
        const cycle = lic.billing_cycle || 'yearly';
        const months = lic.billing_cycle_months || 12;
        const cycleSelect = document.getElementById('formBillingCycle');
        const monthsInput = document.getElementById('formBillingCycleMonths');

        let optionExists = false;
        for (let opt of cycleSelect.options) {
          if (opt.value === cycle) { optionExists = true; break; }
        }

        if (optionExists && cycle !== 'custom') {
          cycleSelect.value = cycle;
          monthsInput.value = months;
        } else {
          cycleSelect.value = 'custom';
          monthsInput.value = months;
        }
        toggleCycleFields();

        document.getElementById('formCost').value = lic.cost || 0.0;
        document.getElementById('formCurrency').value = lic.currency || 'EUR';
        document.getElementById('formSeatsTotal').value = lic.seats_total || 1;
        document.getElementById('formSeatsUsed').value = (lic.seats_used !== undefined && lic.seats_used !== null) ? lic.seats_used : 0;
        document.getElementById('formPurchaseDate').value = lic.purchase_date || '';
        document.getElementById('formExpirationDate').value = lic.expiration_date || '';
        document.getElementById('formNoticePeriod').value = lic.notice_period_days !== undefined ? lic.notice_period_days : 30;
        document.getElementById('formAutoRenewal').value = lic.auto_renewal ? '1' : '0';
        document.getElementById('formLicenseKey').value = lic.license_key || '';
        document.getElementById('formAssignedTo').value = lic.assigned_to || '';
        document.getElementById('formInvoiceNumber').value = lic.invoice_number || '';
        document.getElementById('formPortalUrl').value = lic.login_portal_url || '';
        document.getElementById('formNotes').value = lic.notes || '';
        toggleTypeFields();
      });
  } else {
    title.textContent = 'Neue Lizenz erfassen';
    if (document.getElementById('formStatus')) {
      document.getElementById('formStatus').value = 'active';
    }
    document.getElementById('formLicenseType').value = 'subscription';
    document.getElementById('formBillingCycle').value = 'yearly';
    document.getElementById('formBillingCycleMonths').value = '36';
    document.getElementById('formSeatsTotal').value = '1';
    document.getElementById('formSeatsUsed').value = '1';
    document.getElementById('formNoticePeriod').value = '30';
    document.getElementById('formAutoRenewal').value = '1';
    document.getElementById('formCurrency').value = 'EUR';
    toggleCycleFields();
    toggleTypeFields();
  }

  modal.classList.add('open');
}

function closeLicenseModal() {
  clearAiDraftNotice();
  document.getElementById('licenseModal').classList.remove('open');
}

function toggleCycleFields() {
  const cycle = document.getElementById('formBillingCycle').value;
  const groupCustom = document.getElementById('groupCustomCycle');
  if (groupCustom) {
    if (cycle === 'custom') {
      groupCustom.style.display = 'flex';
    } else {
      groupCustom.style.display = 'none';
    }
  }
}

function toggleTypeFields() {
  const type = document.getElementById('formLicenseType').value;
  const expGroup = document.getElementById('groupExpirationDate');
  const noticeGroup = document.getElementById('groupNoticePeriod');
  const renewalGroup = document.getElementById('groupAutoRenewal');

  if (type === 'perpetual' || type === 'free') {
    noticeGroup.style.display = 'none';
    renewalGroup.style.display = 'none';
  } else {
    noticeGroup.style.display = 'flex';
    renewalGroup.style.display = 'flex';
  }
}

async function handleSaveLicense(e) {
  e.preventDefault();
  const licId = document.getElementById('formLicenseId').value;
  const cycleVal = document.getElementById('formBillingCycle').value;

  let cycleMonths = 12;
  if (cycleVal === 'monthly') cycleMonths = 1;
  else if (cycleVal === 'quarterly') cycleMonths = 3;
  else if (cycleVal === 'semi_annually') cycleMonths = 6;
  else if (cycleVal === 'yearly') cycleMonths = 12;
  else if (cycleVal === 'two_yearly') cycleMonths = 24;
  else if (cycleVal === 'three_yearly') cycleMonths = 36;
  else if (cycleVal === 'custom') {
    cycleMonths = parseInt(document.getElementById('formBillingCycleMonths').value) || 36;
  }

  const statusEl = document.getElementById('formStatus');
  const seatsUsedVal = document.getElementById('formSeatsUsed').value;
  const seatsTotalVal = document.getElementById('formSeatsTotal').value;

  const payload = {
    name: document.getElementById('formName').value,
    vendor: document.getElementById('formVendor').value,
    category: document.getElementById('formCategory').value,
    license_type: document.getElementById('formLicenseType').value,
    status: statusEl ? statusEl.value : 'active',
    billing_cycle: cycleVal,
    billing_cycle_months: cycleMonths,
    cost: parseFloat(document.getElementById('formCost').value) || 0.0,
    currency: document.getElementById('formCurrency').value,
    seats_total: parseInt(seatsTotalVal) || 1,
    seats_used: (seatsUsedVal !== '' && !isNaN(parseInt(seatsUsedVal))) ? parseInt(seatsUsedVal) : 0,
    purchase_date: document.getElementById('formPurchaseDate').value || null,
    expiration_date: document.getElementById('formExpirationDate').value || null,
    notice_period_days: parseInt(document.getElementById('formNoticePeriod').value) || 0,
    auto_renewal: document.getElementById('formAutoRenewal').value === '1',
    license_key: document.getElementById('formLicenseKey').value,
    assigned_to: document.getElementById('formAssignedTo').value,
    invoice_number: document.getElementById('formInvoiceNumber').value,
    login_portal_url: document.getElementById('formPortalUrl').value,
    notes: document.getElementById('formNotes').value
  };

  try {
    let url = '/api/licenses';
    let method = 'POST';
    if (licId) {
      url += `/${licId}`;
      method = 'PUT';
    }

    const res = await fetch(url, {
      method: method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    if (res.ok) {
      closeLicenseModal();
      showToast(licId ? 'Lizenz aktualisiert' : 'Neue Lizenz gespeichert', 'success');
      refreshAll();
    } else {
      const errData = await res.json().catch(() => ({}));
      showToast(errData.error || 'Fehler beim Speichern', 'error');
    }
  } catch (err) {
    console.error('Fehler:', err);
    showToast('Netzwerkfehler beim Speichern', 'error');
  }
}

async function quickRenewLicense(id) {
  if (!confirm('Möchtest du diese Lizenz um einen Abrechnungszyklus verlängern?')) return;

  try {
    const res = await fetch(`/api/licenses/${id}/renew`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    });
    if (res.ok) {
      const renewed = await res.json();
      showToast(`Lizenz verlängert bis ${formatGermanDate(renewed.expiration_date)}`, 'success');
      refreshAll();
    } else {
      const errData = await res.json().catch(() => ({}));
      showToast(errData.error || 'Konnte nicht verlängert werden', 'error');
    }
  } catch (err) {
    showToast('Fehler bei der Verlängerung', 'error');
  }
}

async function confirmDeleteLicense(id, name) {
  if (!name && typeof currentLicensesCache !== 'undefined' && Array.isArray(currentLicensesCache)) {
    const found = currentLicensesCache.find(l => l.id === id);
    if (found) name = found.name;
  }
  const displayName = name ? ` "${name}"` : '';
  if (!confirm(`Möchtest du die Lizenz${displayName} wirklich unwiderruflich löschen?`)) return;

  try {
    const res = await fetch(`/api/licenses/${id}`, { method: 'DELETE' });
    if (res.ok) {
      showToast('Lizenz gelöscht', 'info');
      refreshAll();
    } else {
      const errData = await res.json().catch(() => ({}));
      showToast(errData.error || 'Fehler beim Löschen', 'error');
    }
  } catch (err) {
    showToast('Netzwerkfehler beim Löschen', 'error');
  }
}

// ==========================================
// DETAILS MODAL
// ==========================================
function openDetailModalById(id) {
  fetch(`/api/licenses/${id}`)
    .then(res => res.json())
    .then(lic => {
      document.getElementById('detailModalTitle').textContent = lic.name;
      const editBtn = document.getElementById('detailEditBtn');
      if (editBtn) {
        if (isCurrentUserAdmin()) {
          editBtn.style.display = 'inline-block';
          editBtn.onclick = () => {
            closeDetailModal();
            openLicenseModal(lic.id);
          };
        } else {
          editBtn.style.display = 'none';
        }
      }

      const seatsUsedVal = (lic.seats_used !== undefined && lic.seats_used !== null) ? lic.seats_used : 0;
      const seatsTotalVal = lic.seats_total || 1;

      const body = document.getElementById('detailModalBody');
      body.innerHTML = `
        <div style="display:flex; flex-direction:column; gap:1rem;">
          <div style="display:flex; justify-content:space-between; align-items:center;">
            <span class="badge badge-${escapeHtml(lic.badge_color || 'green')}">
              <span class="badge-dot"></span> ${escapeHtml(lic.badge_label)}
            </span>
            <span style="font-weight:600; font-size:1.05rem; font-variant-numeric: tabular-nums;">
              ${formatCurrency(lic.cost || 0)} <span style="font-size:0.75rem; font-weight:normal; color:var(--text-secondary);">/ ${formatCycleName(lic.billing_cycle, lic.billing_cycle_months)}</span>
              ${lic.monthly_equivalent && lic.billing_cycle_months > 1 ? `<br><span style="font-size:0.75rem; font-weight:normal; color:var(--text-secondary);">(ca. ${formatCurrency(lic.monthly_equivalent)} / Monat)</span>` : ''}
            </span>
          </div>

          <div style="display:grid; grid-template-columns: 1fr 1fr; gap:0.65rem; font-size:0.825rem; background:var(--bg-subtle); padding:0.85rem; border-radius:var(--radius); border:1px solid var(--border);">
            <div><strong style="color:var(--text-secondary);">Hersteller:</strong> ${escapeHtml(lic.vendor || '-')}</div>
            <div><strong style="color:var(--text-secondary);">Kategorie:</strong> ${escapeHtml(lic.category || '-')}</div>
            <div><strong style="color:var(--text-secondary);">Lizenztyp:</strong> ${formatTypeName(lic.license_type)}</div>
            <div><strong style="color:var(--text-secondary);">Plätze (Seats):</strong> ${seatsUsedVal} von ${seatsTotalVal} genutzt</div>
            <div><strong style="color:var(--text-secondary);">Kaufdatum:</strong> ${lic.purchase_date ? formatGermanDate(lic.purchase_date) : '-'}</div>
            <div><strong style="color:var(--text-secondary);">Gültig bis:</strong> ${lic.expiration_date ? formatGermanDate(lic.expiration_date) : 'Unbegrenzt'}</div>
            <div><strong style="color:var(--text-secondary);">Kündigungsfrist:</strong> ${lic.notice_period_days !== undefined ? lic.notice_period_days : 30} Tage vor Verlängerung</div>
            <div><strong style="color:var(--text-secondary);">Kündigungsstichtag:</strong> ${lic.cancellation_deadline ? formatGermanDate(lic.cancellation_deadline) : '-'}</div>
            <div><strong style="color:var(--text-secondary);">Auto-Verlängerung:</strong> ${lic.auto_renewal ? 'Ja' : 'Nein'}</div>
            <div><strong style="color:var(--text-secondary);">Rechnungsnummer:</strong> ${escapeHtml(lic.invoice_number || '-')}</div>
            <div style="grid-column: span 2;"><strong style="color:var(--text-secondary);">Zugewiesen an:</strong> ${escapeHtml(lic.assigned_to || '-')}</div>
          </div>

          ${lic.license_key ? `
            <div>
              <label style="font-size:0.75rem; font-weight:600; color:var(--text-secondary);">Lizenzschlüssel:</label>
              <div style="display:flex; gap:0.4rem; margin-top:0.25rem;">
                <input type="text" class="form-input code-mono" readonly value="${escapeHtml(lic.license_key)}" id="detailKeyInput">
                <button class="btn btn-secondary btn-sm" onclick="copyKeyFromInput('detailKeyInput')">Kopieren</button>
              </div>
            </div>
          ` : ''}

          ${lic.login_portal_url && sanitizeUrl(lic.login_portal_url) ? `
            <div>
              <label style="font-size:0.75rem; font-weight:600; color:var(--text-secondary);">Kundenportal:</label>
              <div><a href="${sanitizeUrl(lic.login_portal_url)}" target="_blank" rel="noopener noreferrer" class="btn btn-secondary btn-sm" style="margin-top:0.25rem;">Portal im Browser öffnen ↗</a></div>
            </div>
          ` : ''}

          ${lic.notes ? `
            <div>
              <label style="font-size:0.75rem; font-weight:600; color:var(--text-secondary);">Notizen:</label>
              <div style="background:var(--bg-surface); border:1px solid var(--border); border-radius:var(--radius); padding:0.6rem; font-size:0.8rem; white-space:pre-wrap; margin-top:0.25rem;">
                ${escapeHtml(lic.notes)}
              </div>
            </div>
          ` : ''}
        </div>
      `;

      document.getElementById('detailModal').classList.add('open');
    });
}

function closeDetailModal() {
  document.getElementById('detailModal').classList.remove('open');
}

// ==========================================
// CSV IMPORT
// ==========================================
function openImportModal() {
  document.getElementById('importModal').classList.add('open');
}

function closeImportModal() {
  document.getElementById('importModal').classList.remove('open');
}

async function handleImportCsv(e) {
  e.preventDefault();
  const fileInput = document.getElementById('importFileInput');
  if (!fileInput.files.length) return;

  const formData = new FormData();
  formData.append('file', fileInput.files[0]);

  try {
    const res = await fetch('/api/import/csv', {
      method: 'POST',
      body: formData
    });
    const result = await res.json();
    if (res.ok) {
      closeImportModal();
      showToast(`${result.imported_count} Lizenzen erfolgreich importiert`, 'success');
      refreshAll();
    } else {
      showToast(result.error || 'Import fehlgeschlagen', 'error');
    }
  } catch (err) {
    showToast('Fehler beim Hochladen der CSV-Datei', 'error');
  }
}

// ==========================================
// SAMPLE DATA & RESET
// ==========================================
async function loadSampleData() {
  if (!confirm('Beispieldaten laden? Dies ersetzt die aktuellen Einträge durch typische Software-Lizenzen.')) return;

  try {
    const res = await fetch('/api/seed', { method: 'POST' });
    if (res.ok) {
      showToast('Beispieldaten geladen', 'success');
      refreshAll();
    } else {
      const errData = await res.json().catch(() => ({}));
      showToast(errData.error || 'Fehler beim Laden der Beispieldaten', 'error');
    }
  } catch (err) {
    showToast('Fehler beim Laden der Beispieldaten', 'error');
  }
}

async function confirmResetAll() {
  if (!confirm('Möchtest du wirklich alle Lizenzen löschen?')) return;

  try {
    const res = await fetch('/api/clear', { method: 'POST' });
    if (res.ok) {
      showToast('Alle Daten gelöscht', 'info');
      refreshAll();
    } else {
      const errData = await res.json().catch(() => ({}));
      showToast(errData.error || 'Fehler beim Löschen', 'error');
    }
  } catch (err) {
    showToast('Fehler beim Löschen', 'error');
  }
}

// ==========================================
// HELPERS
// ==========================================
function copyKey(keyText) {
  if (!keyText) return;
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(keyText).then(() => {
      showToast('Lizenzschlüssel in die Zwischenablage kopiert', 'success');
    }).catch(() => {
      copyKeyFallback(keyText);
    });
  } else {
    copyKeyFallback(keyText);
  }
}

function copyKeyFallback(keyText) {
  try {
    const textArea = document.createElement('textarea');
    textArea.value = keyText;
    textArea.style.position = 'fixed';
    textArea.style.left = '-9999px';
    textArea.style.top = '-9999px';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    const successful = document.execCommand('copy');
    document.body.removeChild(textArea);
    if (successful) {
      showToast('Lizenzschlüssel in die Zwischenablage kopiert', 'success');
    } else {
      showToast('Konnte Schlüssel nicht kopieren', 'error');
    }
  } catch (err) {
    showToast('Konnte Schlüssel nicht kopieren', 'error');
  }
}

function copyKeyById(id) {
  if (typeof currentLicensesCache !== 'undefined' && Array.isArray(currentLicensesCache)) {
    const lic = currentLicensesCache.find(l => l.id === id);
    if (lic && lic.license_key) {
      copyKey(lic.license_key);
      return;
    }
  }
  fetch(`/api/licenses/${id}`)
    .then(res => res.json())
    .then(lic => {
      if (lic && lic.license_key) {
        copyKey(lic.license_key);
      } else {
        showToast('Kein Lizenzschlüssel hinterlegt', 'info');
      }
    })
    .catch(() => showToast('Fehler beim Abrufen des Schlüssels', 'error'));
}

function copyKeyFromInput(inputId) {
  const el = document.getElementById(inputId);
  if (el && el.value) {
    copyKey(el.value);
  }
}

function showToast(msg, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;
  toast.textContent = msg;

  container.appendChild(toast);
  setTimeout(() => {
    toast.remove();
  }, 3500);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function sanitizeUrl(url) {
  if (!url) return '';
  const trimmed = String(url).trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return escapeHtml(trimmed);
  }
  return '';
}

function formatCurrency(val) {
  return new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' }).format(val);
}

function formatCycleName(cycle, months) {
  if (cycle === 'custom' || (months && months !== 1 && months !== 3 && months !== 6 && months !== 12 && months !== 24 && months !== 36)) {
    if (months % 12 === 0) {
      const y = months / 12;
      return `Alle ${months} Mo. (${y} Jahre)`;
    }
    return `Alle ${months} Monate`;
  }
  switch (cycle) {
    case 'monthly': return 'Monat';
    case 'quarterly': return 'Quartal';
    case 'semi_annually': return 'Halbjahr (6 Mo.)';
    case 'yearly': return 'Jahr';
    case 'two_yearly': return '2 Jahre (24 Mo.)';
    case 'three_yearly': return '3 Jahre (36 Mo.)';
    case 'once': return 'Einmalig';
    default:
      if (months) return `Alle ${escapeHtml(months)} Monate`;
      return escapeHtml(cycle) || 'Jahr';
  }
}

function formatTypeName(t) {
  switch (t) {
    case 'subscription': return 'Abonnement';
    case 'perpetual': return 'Dauerlizenz (Einmalkauf)';
    case 'perpetual_maintenance': return 'Dauerlizenz mit Wartung';
    case 'free': return 'Kostenlos / Open Source';
    default: return escapeHtml(t) || 'Abonnement';
  }
}

function formatGermanDate(dateStr) {
  if (!dateStr) return '';
  const parts = dateStr.split('-');
  if (parts.length === 3) {
    return `${parts[2]}.${parts[1]}.${parts[0]}`;
  }
  return dateStr;
}

// ==============================================================================
// KI RECHNUNGSIMPORT (vLLM SERVER ANBINDUNG)
// ==============================================================================
function setupAiListeners() {
  const textarea = document.getElementById('aiInvoiceInput');
  if (textarea) {
    textarea.addEventListener('input', updateAiCharCount);
  }
}

function updateAiCharCount() {
  const input = document.getElementById('aiInvoiceInput');
  const countEl = document.getElementById('aiCharCount');
  if (input && countEl) {
    const len = input.value.length;
    countEl.textContent = `${len} Zeichen`;
  }
}

function openAiInvoiceModal() {
  const modal = document.getElementById('aiInvoiceModal');
  if (!modal) return;

  // Falls das Standard-Lizenzmodal geöffnet war, schließen
  closeLicenseModal();

  const input = document.getElementById('aiInvoiceInput');
  if (input) input.value = '';
  updateAiCharCount();

  const loading = document.getElementById('aiLoadingIndicator');
  if (loading) loading.style.display = 'none';

  const errAlert = document.getElementById('aiErrorAlert');
  if (errAlert) {
    errAlert.style.display = 'none';
    errAlert.textContent = '';
  }

  const btn = document.getElementById('btnRunAiAnalysis');
  if (btn) btn.disabled = false;

  modal.classList.add('open');
  checkAiStatus();

  setTimeout(() => {
    if (input) input.focus();
  }, 100);
}

function closeAiInvoiceModal() {
  const modal = document.getElementById('aiInvoiceModal');
  if (modal) modal.classList.remove('open');
}

function clearAiDraftNotice() {
  const notice = document.getElementById('aiDraftNotice');
  if (notice) notice.style.display = 'none';
}

async function handleAiInvoiceAnalysis() {
  const input = document.getElementById('aiInvoiceInput');
  const text = input ? input.value.trim() : '';

  const errAlert = document.getElementById('aiErrorAlert');
  const loading = document.getElementById('aiLoadingIndicator');
  const btn = document.getElementById('btnRunAiAnalysis');

  if (!text) {
    if (errAlert) {
      errAlert.style.display = 'block';
      errAlert.textContent = 'Bitte füge zuerst den Rechnungstext oder Belegdaten in das Textfeld ein.';
    }
    return;
  }

  if (errAlert) {
    errAlert.style.display = 'none';
    errAlert.textContent = '';
  }
  if (loading) loading.style.display = 'flex';
  if (btn) btn.disabled = true;

  try {
    const res = await fetch('/api/ai/parse-invoice', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });

    const data = await res.json();

    if (res.ok && data.success && data.draft) {
      closeAiInvoiceModal();
      openLicenseModalWithDraft(data.draft);
      showToast('✨ Lizenz-Entwurf erfolgreich aus Rechnung erstellt!', 'success');
    } else {
      if (errAlert) {
        errAlert.style.display = 'block';
        errAlert.textContent = data.error || 'Die KI konnte keine verwertbaren Lizenzdaten aus dem Text extrahieren.';
      }
    }
  } catch (err) {
    if (errAlert) {
      errAlert.style.display = 'block';
      errAlert.textContent = 'Netzwerkfehler bei der Verbindung zum KI-Server: ' + err.message;
    }
  } finally {
    if (loading) loading.style.display = 'none';
    if (btn) btn.disabled = false;
  }
}

function openLicenseModalWithDraft(draft) {
  // Öffnet das Formular im Neuanlage-Modus
  openLicenseModal(null);

  if (!draft) return;

  if (draft.name) document.getElementById('formName').value = draft.name;
  if (draft.vendor) document.getElementById('formVendor').value = draft.vendor;
  if (draft.category) document.getElementById('formCategory').value = draft.category;
  if (draft.license_type) document.getElementById('formLicenseType').value = draft.license_type;
  if (document.getElementById('formStatus')) {
    document.getElementById('formStatus').value = draft.status || 'active';
  }

  const cycle = draft.billing_cycle || 'yearly';
  const months = draft.billing_cycle_months || 12;
  const cycleSelect = document.getElementById('formBillingCycle');
  const monthsInput = document.getElementById('formBillingCycleMonths');

  let optionExists = false;
  for (let opt of cycleSelect.options) {
    if (opt.value === cycle) { optionExists = true; break; }
  }

  if (optionExists && cycle !== 'custom') {
    cycleSelect.value = cycle;
    monthsInput.value = months;
  } else {
    cycleSelect.value = 'custom';
    monthsInput.value = months;
  }
  toggleCycleFields();

  if (draft.cost !== undefined && draft.cost !== null) {
    document.getElementById('formCost').value = draft.cost;
  }
  if (draft.currency) document.getElementById('formCurrency').value = draft.currency;
  if (draft.seats_total) document.getElementById('formSeatsTotal').value = draft.seats_total;
  if (draft.seats_used !== undefined && draft.seats_used !== null) {
    document.getElementById('formSeatsUsed').value = draft.seats_used;
  }
  if (draft.purchase_date) document.getElementById('formPurchaseDate').value = draft.purchase_date;
  if (draft.expiration_date) document.getElementById('formExpirationDate').value = draft.expiration_date;
  if (draft.notice_period_days !== undefined && draft.notice_period_days !== null) {
    document.getElementById('formNoticePeriod').value = draft.notice_period_days;
  }
  if (draft.auto_renewal !== undefined && draft.auto_renewal !== null) {
    document.getElementById('formAutoRenewal').value = draft.auto_renewal ? '1' : '0';
  }
  if (draft.license_key) document.getElementById('formLicenseKey').value = draft.license_key;
  if (draft.assigned_to) document.getElementById('formAssignedTo').value = draft.assigned_to;
  if (draft.invoice_number) document.getElementById('formInvoiceNumber').value = draft.invoice_number;
  if (draft.login_portal_url) document.getElementById('formPortalUrl').value = draft.login_portal_url;
  if (draft.notes) document.getElementById('formNotes').value = draft.notes;

  toggleTypeFields();

  // Hinweisbanner einblenden
  const notice = document.getElementById('aiDraftNotice');
  if (notice) {
    notice.style.display = 'flex';
  }
}

async function checkAiStatus(showFeedback = false) {
  try {
    const res = await fetch('/api/ai/status');
    const status = await res.json();

    const dotModal = document.getElementById('modalAiStatusDot');
    const textModal = document.getElementById('modalAiStatusText');
    const tagModal = document.getElementById('modalAiModelTag');

    const dotSettings = document.getElementById('settingsAiStatusDot');
    const labelSettings = document.getElementById('settingsAiStatusLabel');
    const endpointSettings = document.getElementById('settingsAiEndpoint');
    if (endpointSettings && status.api_base) {
      endpointSettings.textContent = status.api_base;
    }

    if (status.connected) {
      if (dotModal) {
        dotModal.classList.remove('offline');
        dotModal.title = 'Verbunden';
      }
      if (textModal) {
        textModal.textContent = 'Lokaler KI-Server online';
      }
      if (tagModal) {
        tagModal.textContent = status.active_model || 'vLLM';
      }

      if (dotSettings) {
        dotSettings.classList.remove('offline');
      }
      if (labelSettings) {
        labelSettings.textContent = `Online (${status.active_model || 'Bereit'})`;
        labelSettings.style.color = 'var(--status-ok-dot)';
      }

      if (showFeedback) {
        showToast(`KI-Server erreichbar (${status.active_model})`, 'success');
      }
    } else {
      if (dotModal) {
        dotModal.classList.add('offline');
        dotModal.title = 'Nicht erreichbar';
      }
      if (textModal) {
        textModal.textContent = 'KI-Server nicht erreichbar';
      }
      if (dotSettings) {
        dotSettings.classList.add('offline');
      }
      if (labelSettings) {
        labelSettings.textContent = 'Nicht erreichbar';
        labelSettings.style.color = 'var(--status-urgent-dot)';
      }

      if (showFeedback) {
        showToast(status.message || 'Verbindung zum KI-Server fehlgeschlagen', 'error');
      }
    }
  } catch (err) {
    console.warn('KI-Status konnte nicht abgerufen werden:', err);
    if (showFeedback) {
      showToast('Konnte KI-Status nicht abrufen', 'error');
    }
  }
}

// ==============================================================================
// MODAL: LOKALES ADMINISTRATOR-KENNWORT ÄNDERN
// ==============================================================================
function openChangePasswordModal() {
  const modal = document.getElementById('changePasswordModal');
  if (modal) {
    const form = document.getElementById('changePasswordForm');
    if (form) form.reset();
    const err = document.getElementById('changePasswordErrorAlert');
    if (err) err.style.display = 'none';
    modal.classList.add('active');
  }
}

function closeChangePasswordModal() {
  const modal = document.getElementById('changePasswordModal');
  if (modal) modal.classList.remove('active');
}

async function handleChangePassword(e) {
  e.preventDefault();
  const oldPwd = document.getElementById('oldPasswordInput').value;
  const newPwd = document.getElementById('newPasswordInput').value;
  const newConfirm = document.getElementById('newPasswordConfirmInput').value;
  const errDiv = document.getElementById('changePasswordErrorAlert');

  if (newPwd !== newConfirm) {
    errDiv.textContent = 'Die neuen Kennwörter stimmen nicht überein.';
    errDiv.style.display = 'block';
    return;
  }

  try {
    const res = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        old_password: oldPwd,
        new_password: newPwd,
        new_password_confirm: newConfirm
      })
    });
    const data = await res.json();
    if (res.ok && data.success) {
      closeChangePasswordModal();
      showToast('Administrator-Kennwort erfolgreich geändert', 'success');
    } else {
      errDiv.textContent = data.error || 'Fehler beim Ändern des Kennworts';
      errDiv.style.display = 'block';
    }
  } catch (err) {
    errDiv.textContent = 'Verbindungsfehler: ' + err.message;
    errDiv.style.display = 'block';
  }
}

// ==============================================================================
// BENUTZERVERWALTUNG (LOKALE BENUTZER)
// ==============================================================================
let _cachedUsers = [];

function getCurrentUsername() {
  const badge = document.getElementById('userProfileBadge');
  return badge ? (badge.getAttribute('data-username') || '') : '';
}

function isCurrentUserAdmin() {
  const badge = document.getElementById('userProfileBadge');
  if (!badge) return true;
  return badge.getAttribute('data-is-admin') === 'true';
}

async function loadUsers() {
  const tbody = document.getElementById('usersTableBody');
  if (!tbody) return;

  try {
    const res = await fetch('/api/users');
    if (res.status === 403) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-secondary);">
            <em>Nur Administratoren haben Zugriff auf die Benutzerverwaltung.</em>
          </td>
        </tr>
      `;
      return;
    }
    if (!res.ok) {
      throw new Error('Fehler beim Laden der Benutzerliste');
    }
    const users = await res.json();
    _cachedUsers = users;
    renderUsersTable(users);
  } catch (err) {
    console.error('Fehler beim Laden der Benutzer:', err);
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding:1.5rem; color:var(--status-urgent-text);">
          Fehler beim Laden der Benutzerliste (${escapeHtml(err.message)})
        </td>
      </tr>
    `;
  }
}

function renderUsersTable(users) {
  const tbody = document.getElementById('usersTableBody');
  if (!tbody) return;

  if (!users || users.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align:center; padding:1.5rem; color:var(--text-secondary);">
          Keine lokalen Benutzer gefunden.
        </td>
      </tr>
    `;
    return;
  }

  const currentUsername = getCurrentUsername().toLowerCase();

  tbody.innerHTML = users.map(u => {
    const isSelf = (u.username || '').toLowerCase() === currentUsername;
    const roleBadge = u.is_admin
      ? `<span style="display:inline-flex; align-items:center; gap:0.35rem; padding:0.25rem 0.65rem; background:#eff6ff; color:#1d4ed8; border:1px solid #bfdbfe; border-radius:9999px; font-weight:600; font-size:0.75rem;">🛡️ Administrator</span>`
      : `<span style="display:inline-flex; align-items:center; gap:0.35rem; padding:0.25rem 0.65rem; background:#f8fafc; color:#475569; border:1px solid #cbd5e1; border-radius:9999px; font-weight:600; font-size:0.75rem;">👤 Standard-Benutzer</span>`;

    return `
      <tr>
        <td>
          <strong style="font-size:0.875rem;">${escapeHtml(u.username)}</strong>
          ${isSelf ? '<span style="font-size:0.7rem; margin-left:0.4rem; padding:0.15rem 0.4rem; background:var(--bg-subtle); border-radius:4px; color:var(--text-secondary);">(Du)</span>' : ''}
        </td>
        <td>${escapeHtml(u.display_name || '-')}</td>
        <td>${escapeHtml(u.email || '-')}</td>
        <td>${roleBadge}</td>
        <td style="color:var(--text-secondary); font-size:0.8rem;">${escapeHtml(u.created_at || '-')}</td>
        <td style="text-align: right; white-space: nowrap;">
          <button class="btn btn-secondary btn-sm" onclick="openUserModalById(${u.id})" title="Benutzer bearbeiten">
            ✏️ Bearbeiten
          </button>
          <button class="btn btn-danger btn-sm" onclick="deleteUserById(${u.id})" ${isSelf ? 'disabled title="Eigenes Konto kann nicht gelöscht werden"' : 'title="Benutzer löschen"'}>
            🗑️ Löschen
          </button>
        </td>
      </tr>
    `;
  }).join('');
}

function openUserModalById(id) {
  const user = _cachedUsers.find(u => u.id === id);
  if (user) {
    openUserModal(user);
  }
}

function openUserModal(user = null) {
  const modal = document.getElementById('userModal');
  if (!modal) return;

  const form = document.getElementById('userForm');
  if (form) form.reset();

  const errAlert = document.getElementById('userFormErrorAlert');
  if (errAlert) errAlert.style.display = 'none';

  const modalTitle = document.getElementById('userModalTitle');
  const idInput = document.getElementById('userFormId');
  const usernameInput = document.getElementById('userFormUsername');
  const usernameHint = document.getElementById('userFormUsernameHint');
  const displayNameInput = document.getElementById('userFormDisplayName');
  const emailInput = document.getElementById('userFormEmail');
  const roleSelect = document.getElementById('userFormRole');
  const passwordInput = document.getElementById('userFormPassword');
  const passwordReq = document.getElementById('userFormPasswordReq');
  const passwordHint = document.getElementById('userFormPasswordHint');

  if (user) {
    // Bearbeiten-Modus
    if (modalTitle) modalTitle.innerHTML = `<span style="font-size:1.15rem;">✏️</span><span>Benutzer "${escapeHtml(user.username)}" bearbeiten</span>`;
    if (idInput) idInput.value = user.id;
    if (usernameInput) {
      usernameInput.value = user.username;
      usernameInput.disabled = true;
    }
    if (usernameHint) usernameHint.textContent = 'Der Benutzername kann nachträglich nicht geändert werden.';
    if (displayNameInput) displayNameInput.value = user.display_name || '';
    if (emailInput) emailInput.value = user.email || '';
    if (roleSelect) roleSelect.value = user.is_admin ? 'admin' : 'user';
    if (passwordInput) {
      passwordInput.value = '';
      passwordInput.required = false;
    }
    if (passwordReq) passwordReq.style.display = 'none';
    if (passwordHint) passwordHint.style.display = 'block';
  } else {
    // Neu-Anlegen-Modus
    if (modalTitle) modalTitle.innerHTML = `<span style="font-size:1.15rem;">👤</span><span>Neuen Benutzer anlegen</span>`;
    if (idInput) idInput.value = '';
    if (usernameInput) {
      usernameInput.value = '';
      usernameInput.disabled = false;
    }
    if (usernameHint) usernameHint.textContent = 'Dient als Login-Name (kann nachträglich nicht geändert werden).';
    if (displayNameInput) displayNameInput.value = '';
    if (emailInput) emailInput.value = '';
    if (roleSelect) roleSelect.value = 'user';
    if (passwordInput) {
      passwordInput.value = '';
      passwordInput.required = true;
    }
    if (passwordReq) passwordReq.style.display = 'inline';
    if (passwordHint) passwordHint.style.display = 'none';
  }

  modal.classList.add('active');
}

function closeUserModal() {
  const modal = document.getElementById('userModal');
  if (modal) modal.classList.remove('active');
}

async function handleSaveUser(e) {
  e.preventDefault();
  const id = document.getElementById('userFormId').value;
  const username = document.getElementById('userFormUsername').value.trim();
  const displayName = document.getElementById('userFormDisplayName').value.trim();
  const email = document.getElementById('userFormEmail').value.trim();
  const role = document.getElementById('userFormRole').value;
  const password = document.getElementById('userFormPassword').value;
  const errDiv = document.getElementById('userFormErrorAlert');

  const isAdmin = (role === 'admin');

  try {
    let res;
    if (id) {
      // Update
      const payload = {
        display_name: displayName,
        email: email,
        is_admin: isAdmin
      };
      if (password) {
        if (password.length < 8) {
          errDiv.textContent = 'Das neue Kennwort muss mindestens 8 Zeichen lang sein.';
          errDiv.style.display = 'block';
          return;
        }
        payload.password = password;
      }
      res = await fetch(`/api/users/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
    } else {
      // Create
      if (!username) {
        errDiv.textContent = 'Bitte geben Sie einen Benutzernamen ein.';
        errDiv.style.display = 'block';
        return;
      }
      if (!password || password.length < 8) {
        errDiv.textContent = 'Das Kennwort muss mindestens 8 Zeichen lang sein.';
        errDiv.style.display = 'block';
        return;
      }
      res = await fetch('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username,
          password: password,
          display_name: displayName,
          email: email,
          is_admin: isAdmin
        })
      });
    }

    const data = await res.json();
    if (res.ok && data.success) {
      closeUserModal();
      showToast(id ? 'Benutzer erfolgreich aktualisiert' : 'Benutzer erfolgreich angelegt', 'success');
      loadUsers();
    } else {
      errDiv.textContent = data.error || 'Fehler beim Speichern des Benutzers';
      errDiv.style.display = 'block';
    }
  } catch (err) {
    errDiv.textContent = 'Verbindungsfehler: ' + err.message;
    errDiv.style.display = 'block';
  }
}

function deleteUserById(userId) {
  const user = _cachedUsers.find(u => u.id === userId);
  const username = user ? user.username : `ID ${userId}`;
  deleteUser(userId, username);
}

async function deleteUser(userId, username) {
  if (!confirm(`Möchten Sie das Benutzerkonto "${username}" wirklich unwiderruflich löschen?`)) {
    return;
  }

  try {
    const res = await fetch(`/api/users/${userId}`, {
      method: 'DELETE'
    });
    const data = await res.json();
    if (res.ok && data.success) {
      showToast(`Benutzer "${username}" gelöscht`, 'info');
      loadUsers();
    } else {
      showToast(data.error || 'Fehler beim Löschen des Benutzers', 'error');
    }
  } catch (err) {
    showToast('Verbindungsfehler: ' + err.message, 'error');
  }
}

// ==============================================================================
// UPDATE-PRÜFUNG & BENACHRICHTIGUNG
// ==============================================================================
let _latestUpdateData = null;

async function checkForUpdates(force = false) {
  try {
    const url = force ? '/api/system/update-check?force=1' : '/api/system/update-check';
    const res = await fetch(url);
    if (!res.ok) {
      if (force) {
        const errData = await res.json().catch(() => ({}));
        showToast(errData.error || 'Update-Prüfung fehlgeschlagen', 'error');
      }
      return;
    }
    const data = await res.json();
    _applyUpdateInfo(data);
    if (force) {
      if (data.error) {
        showToast(data.error, 'error');
      } else if (data.update_available) {
        showToast(`Neues Update verfügbar: ${data.latest_version}`, 'info');
      } else {
        showToast('Lizenzmanager ist auf dem neuesten Stand', 'success');
      }
    }
  } catch (err) {
    console.warn('Update-Prüfung konnte nicht durchgeführt werden:', err);
  }
}

async function simulateUpdateTest() {
  try {
    const res = await fetch('/api/system/update-check?simulate=1');
    if (!res.ok) {
      const errData = await res.json().catch(() => ({}));
      showToast(errData.error || 'Fehler bei der Update-Simulation (Berechtigung fehlt)', 'error');
      return;
    }
    const data = await res.json();
    _applyUpdateInfo(data);
    showToast(`Test-Modus: Update-Benachrichtigung für ${data.latest_version} aktiviert!`, 'info');
  } catch (err) {
    showToast('Fehler bei der Update-Simulation: ' + err.message, 'error');
  }
}

function _formatVersionLabel(val) {
  if (!val) return '';
  const s = String(val).trim();
  if (/^\d/.test(s)) return 'v' + s;
  return s;
}

function _applyUpdateInfo(data) {
  _latestUpdateData = data;

  const headerBadge = document.getElementById('headerUpdateBadge');
  const headerText = document.getElementById('headerUpdateText');
  const tabDot = document.getElementById('tabUpdateDot');

  const currEl = document.getElementById('settingsCurrentVersion');
  const latestEl = document.getElementById('settingsLatestVersion');
  const labelEl = document.getElementById('settingsUpdateLabel');
  const dotEl = document.getElementById('settingsUpdateDot');
  const btnView = document.getElementById('btnSettingsViewUpdate');

  if (currEl && data.current_version) {
    currEl.textContent = _formatVersionLabel(data.current_version);
  }
  if (latestEl && data.latest_version) {
    latestEl.textContent = _formatVersionLabel(data.latest_version);
  }

  if (data.update_available) {
    const isCommit = data.update_type === 'commit';
    // 1. Header Pill anzeigen
    if (headerBadge) {
      headerBadge.style.display = 'inline-flex';
      if (headerText) {
        headerText.textContent = isCommit
          ? `Neuer Build (${data.latest_commit || data.latest_version})`
          : `Update ${data.latest_version} verfügbar!`;
      }
    }
    // 2. Punkt auf dem Settings-Tab
    if (tabDot) {
      tabDot.style.display = 'inline-block';
    }
    // 3. Status in Settings Card
    if (labelEl) {
      labelEl.textContent = isCommit
        ? `Neuer Docker-Build (${data.latest_commit || data.latest_version})`
        : `Update verfügbar (${data.latest_version})`;
      labelEl.style.color = '#2563eb';
    }
    if (dotEl) {
      dotEl.style.display = 'inline-block';
    }
    if (btnView) {
      btnView.style.display = 'inline-flex';
    }
  } else {
    // Aktuell
    if (headerBadge) {
      headerBadge.style.display = 'none';
    }
    if (tabDot) {
      tabDot.style.display = 'none';
    }
    if (labelEl) {
      labelEl.textContent = 'Auf dem neuesten Stand';
      labelEl.style.color = 'var(--status-active-text, #16a34a)';
    }
    if (dotEl) {
      dotEl.style.display = 'none';
    }
    if (btnView) {
      btnView.style.display = 'none';
    }
  }
}

function openUpdateModal() {
  const modal = document.getElementById('updateModal');
  if (!modal) return;

  const data = _latestUpdateData || {
    current_version: 'v1.1.0',
    latest_version: 'v1.2.0',
    update_type: 'release',
    release_name: 'Lizenzmanager Update',
    release_notes: 'Keine Versionshinweise vorhanden.',
    release_url: 'https://github.com/Speedy2524/lizenzmanager/releases'
  };

  const nameEl = document.getElementById('updateModalReleaseName');
  const tagEl = document.getElementById('updateModalTag');
  const currEl = document.getElementById('updateModalCurrentVer');
  const latestEl = document.getElementById('updateModalLatestVer');
  const notesEl = document.getElementById('updateModalNotes');
  const linkEl = document.getElementById('updateModalReleaseLink');
  const modalTitleText = document.getElementById('updateModalTitleText');

  const isCommit = data.update_type === 'commit';

  if (modalTitleText) {
    modalTitleText.textContent = isCommit ? 'Neuer Docker-Build verfügbar!' : 'Neues Update verfügbar!';
  }

  if (nameEl) nameEl.textContent = data.release_name || (isCommit ? `Build ${data.latest_version}` : `Version ${data.latest_version}`);
  if (tagEl) {
    tagEl.textContent = isCommit ? (data.latest_commit ? `Build ${data.latest_commit}` : 'Docker :latest') : (data.latest_version || 'Update');
  }
  if (currEl) currEl.textContent = _formatVersionLabel(data.current_version || 'v1.1.0');
  if (latestEl) latestEl.textContent = _formatVersionLabel(data.latest_version || 'v1.2.0');
  if (notesEl) {
    notesEl.textContent = data.release_notes || 'Es liegen keine detaillierten Versionsnotizen vor.';
  }
  if (linkEl && data.release_url) {
    if (typeof data.release_url === 'string' && data.release_url.startsWith('https://github.com/')) {
      linkEl.href = data.release_url;
    } else {
      linkEl.href = 'https://github.com/Speedy2524/lizenzmanager/releases';
    }
    const linkSpan = linkEl.querySelector('span');
    if (linkSpan) {
      linkSpan.textContent = isCommit ? 'Commit auf GitHub ansehen ↗' : 'GitHub Release öffnen ↗';
    }
  }

  modal.classList.add('active');
}

function closeUpdateModal() {
  const modal = document.getElementById('updateModal');
  if (modal) modal.classList.remove('active');
}

