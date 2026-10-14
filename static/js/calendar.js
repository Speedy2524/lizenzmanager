// Jährlicher Kalender & Fristenmatrix (Stripe & Apple Business Design)

let currentCalendarYear = new Date().getFullYear();
let currentCalendarMonth = new Date().getMonth() + 1; // 1-12
let currentCalendarView = 'matrix'; // 'matrix' oder 'month'
let calendarRawData = null;

const GERMAN_MONTH_NAMES = [
  '', 'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni',
  'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember'
];

const GERMAN_WEEKDAYS = ['Mo', 'Di', 'Mi', 'Do', 'Fr', 'Sa', 'So'];

async function loadCalendar(year) {
  if (year) currentCalendarYear = year;
  const yearDisp = document.getElementById('calendarYearDisplay');
  if (yearDisp) yearDisp.textContent = currentCalendarYear;

  try {
    const res = await fetch(`/api/calendar?year=${currentCalendarYear}`);
    calendarRawData = await res.json();
    renderCalendar();
  } catch (err) {
    console.error('Fehler beim Laden des Kalenders:', err);
    showToast('Kalenderdaten konnten nicht geladen werden', 'error');
  }
}

function changeCalendarYear(delta) {
  currentCalendarYear += delta;
  loadCalendar(currentCalendarYear);
}

function resetCalendarYear() {
  currentCalendarYear = new Date().getFullYear();
  loadCalendar(currentCalendarYear);
}

function setCalendarView(viewMode) {
  currentCalendarView = viewMode;
  const matrixBtn = document.getElementById('viewToggleMatrix');
  const monthBtn = document.getElementById('viewToggleMonth');
  const matrixView = document.getElementById('calendarMatrixView');
  const monthView = document.getElementById('calendarMonthDetailView');

  if (viewMode === 'matrix') {
    matrixBtn.className = 'btn btn-primary btn-sm';
    monthBtn.className = 'btn btn-secondary btn-sm';
    matrixView.style.display = 'grid';
    monthView.style.display = 'none';
  } else {
    matrixBtn.className = 'btn btn-secondary btn-sm';
    monthBtn.className = 'btn btn-primary btn-sm';
    matrixView.style.display = 'none';
    monthView.style.display = 'block';
    renderMonthDetailView();
  }
}

function renderCalendar() {
  if (!calendarRawData) return;
  if (currentCalendarView === 'matrix') {
    renderAnnualMatrix();
  } else {
    renderMonthDetailView();
  }
}

function renderAnnualMatrix() {
  const container = document.getElementById('calendarMatrixView');
  if (!container || !calendarRawData) return;

  const today = new Date();
  const currentMonthNum = today.getFullYear() === currentCalendarYear ? (today.getMonth() + 1) : -1;

  let html = '';

  for (let m = 1; m <= 12; m++) {
    const mData = calendarRawData.months[m] || { renewals: [], cancellations: [], total_renewal_cost: 0 };
    const renewals = mData.renewals || [];
    const cancellations = mData.cancellations || [];
    const totalCost = mData.total_renewal_cost || 0;

    const isCurrent = (m === currentMonthNum);
    const hasEvents = (renewals.length > 0 || cancellations.length > 0);
    const hasUrgent = cancellations.length > 0;

    let cardClasses = 'month-card';
    if (isCurrent) cardClasses += ' current-month';
    if (hasUrgent) cardClasses += ' has-urgent';

    html += `
      <div class="${cardClasses}">
        <div class="month-header">
          <div style="display:flex; align-items:center; gap:0.35rem;">
            <span class="month-name">${GERMAN_MONTH_NAMES[m]}</span>
            ${isCurrent ? '<span class="badge badge-blue" style="font-size:0.65rem;">Aktuell</span>' : ''}
          </div>
          <span class="month-cost-badge">${formatCurrency(totalCost)}</span>
        </div>

        <div class="month-events-list">
    `;

    if (!hasEvents) {
      html += `<div class="month-empty">Keine Termine</div>`;
    } else {
      // Kündigungsfristen (rot)
      cancellations.forEach(evt => {
        html += `
          <div class="calendar-pill pill-cancellation" onclick="openDetailModalById(${evt.id})" title="Kündigungsfrist für ${escapeHtml(evt.name)} (Stichtag: ${formatGermanDate(evt.date)})">
            <div style="display:flex; align-items:center; gap:0.35rem; min-width:0;">
              <span class="badge-dot" style="background:var(--status-urgent-dot);"></span>
              <span class="pill-title">${escapeHtml(evt.name)}</span>
            </div>
            <span class="pill-date">${evt.day}. ${GERMAN_MONTH_NAMES[m].slice(0, 3)}</span>
          </div>
        `;
      });

      // Verlängerungen (grün)
      renewals.forEach(evt => {
        html += `
          <div class="calendar-pill pill-renewal" onclick="openDetailModalById(${evt.id})" title="Verlängerung: ${escapeHtml(evt.name)} (${formatCurrency(evt.cost)})">
            <div style="display:flex; align-items:center; gap:0.35rem; min-width:0;">
              <span class="badge-dot" style="background:var(--status-ok-dot);"></span>
              <span class="pill-title">${escapeHtml(evt.name)}</span>
            </div>
            <span class="pill-date">${evt.day}. ${GERMAN_MONTH_NAMES[m].slice(0, 3)}</span>
          </div>
        `;
      });
    }

    html += `
        </div>
        <div style="margin-top: 0.5rem; padding-top: 0.4rem; border-top: 1px solid var(--border); display: flex; justify-content: space-between; align-items:center; font-size: 0.72rem; color: var(--text-tertiary);">
          <span>${renewals.length} Fälligkeit${renewals.length === 1 ? '' : 'en'}</span>
          <button class="btn btn-sm btn-secondary" style="padding: 1px 6px; font-size: 0.7rem;" onclick="jumpToMonth(${m})">Öffnen</button>
        </div>
      </div>
    `;
  }

  container.innerHTML = html;
}

function jumpToMonth(m) {
  currentCalendarMonth = m;
  setCalendarView('month');
}

function navMonthDetail(delta) {
  currentCalendarMonth += delta;
  if (currentCalendarMonth > 12) {
    currentCalendarMonth = 1;
    currentCalendarYear += 1;
    loadCalendar(currentCalendarYear);
    return;
  } else if (currentCalendarMonth < 1) {
    currentCalendarMonth = 12;
    currentCalendarYear -= 1;
    loadCalendar(currentCalendarYear);
    return;
  }
  renderMonthDetailView();
}

function renderMonthDetailView() {
  const title = document.getElementById('monthDetailTitle');
  const badge = document.getElementById('monthDetailCostBadge');
  const grid = document.getElementById('monthDetailGrid');
  if (!grid || !calendarRawData) return;

  title.textContent = `${GERMAN_MONTH_NAMES[currentCalendarMonth]} ${currentCalendarYear}`;

  const mData = calendarRawData.months[currentCalendarMonth] || { renewals: [], cancellations: [], total_renewal_cost: 0 };
  badge.textContent = `${formatCurrency(mData.total_renewal_cost)} in diesem Monat`;

  let html = '';

  // Wochentagsköpfe (Mo-So)
  GERMAN_WEEKDAYS.forEach(wd => {
    html += `<div class="weekday-header">${wd}</div>`;
  });

  const firstDay = new Date(currentCalendarYear, currentCalendarMonth - 1, 1);
  const lastDay = new Date(currentCalendarYear, currentCalendarMonth, 0);
  const totalDays = lastDay.getDate();

  let startWeekday = (firstDay.getDay() + 6) % 7;
  const prevMonthLastDay = new Date(currentCalendarYear, currentCalendarMonth - 1, 0).getDate();

  for (let i = startWeekday - 1; i >= 0; i--) {
    const dayNum = prevMonthLastDay - i;
    html += `
      <div class="day-cell other-month">
        <span class="day-number">${dayNum}</span>
      </div>
    `;
  }

  const today = new Date();
  const isThisMonth = (today.getFullYear() === currentCalendarYear && (today.getMonth() + 1) === currentCalendarMonth);

  for (let d = 1; d <= totalDays; d++) {
    const isToday = isThisMonth && (today.getDate() === d);

    const dayRenewals = (mData.renewals || []).filter(e => e.day === d);
    const dayCancellations = (mData.cancellations || []).filter(e => e.day === d);

    html += `
      <div class="day-cell ${isToday ? 'today' : ''}">
        <span class="day-number">${d}</span>
    `;

    dayCancellations.forEach(evt => {
      html += `
        <div class="calendar-pill pill-cancellation" onclick="openDetailModalById(${evt.id})" title="Kündigungsstichtag: ${escapeHtml(evt.name)}">
          <span class="pill-title">${escapeHtml(evt.name)}</span>
        </div>
      `;
    });

    dayRenewals.forEach(evt => {
      html += `
        <div class="calendar-pill pill-renewal" onclick="openDetailModalById(${evt.id})" title="Verlängerung: ${escapeHtml(evt.name)} (${formatCurrency(evt.cost)})">
          <span class="pill-title">${escapeHtml(evt.name)}</span>
        </div>
      `;
    });

    html += `</div>`;
  }

  const totalCells = startWeekday + totalDays;
  const remainingCells = (7 - (totalCells % 7)) % 7;
  for (let n = 1; n <= remainingCells; n++) {
    html += `
      <div class="day-cell other-month">
        <span class="day-number">${n}</span>
      </div>
    `;
  }

  grid.innerHTML = html;
}
