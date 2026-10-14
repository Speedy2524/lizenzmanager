// Diagramm-Verwaltung mit Chart.js (Stripe & Apple Business Theme)

let chartForecastInstance = null;
let chartCategoriesInstance = null;
let chartVendorsInstance = null;

function formatCurrency(val) {
  return new Intl.NumberFormat('de-DE', { style: 'currency', currency: 'EUR' }).format(val);
}

function getThemeColors() {
  const isDark = (document.documentElement.getAttribute('data-theme') === 'dark');
  return {
    grid: isDark ? '#1f293d' : '#f1f5f9',
    ticks: isDark ? '#94a3b8' : '#64748b',
    border: isDark ? '#111827' : '#ffffff',
    barPrimary: isDark ? '#3b82f6' : '#0f172a',
    barSecondary: isDark ? '#10b981' : '#334155'
  };
}

function initOrUpdateForecastChart(forecastData) {
  const ctx = document.getElementById('chartForecast');
  if (!ctx || !window.Chart) return;

  if (chartForecastInstance) {
    chartForecastInstance.destroy();
  }

  const themeColors = getThemeColors();
  const labels = forecastData.labels || [];
  const costs = forecastData.costs || [];

  chartForecastInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Anstehende Kosten',
        data: costs,
        backgroundColor: themeColors.barPrimary,
        borderRadius: 4,
        maxBarThickness: 32
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f172a',
          titleFont: { size: 12, weight: '600' },
          bodyFont: { size: 12 },
          padding: 10,
          cornerRadius: 6,
          callbacks: {
            label: function(context) {
              return 'Kosten: ' + formatCurrency(context.parsed.y);
            }
          }
        }
      },
      scales: {
        y: {
          beginAtZero: true,
          ticks: {
            color: themeColors.ticks,
            font: { size: 11 },
            callback: function(value) {
              return value + ' €';
            }
          },
          grid: { color: themeColors.grid }
        },
        x: {
          ticks: { color: themeColors.ticks, font: { size: 11 } },
          grid: { display: false }
        }
      }
    }
  });
}

function initOrUpdateCategoriesChart(catCosts) {
  const ctx = document.getElementById('chartCategories');
  if (!ctx || !window.Chart) return;

  if (chartCategoriesInstance) {
    chartCategoriesInstance.destroy();
  }

  const themeColors = getThemeColors();
  const labels = Object.keys(catCosts || {});
  const data = Object.values(catCosts || {});

  if (labels.length === 0) {
    labels.push('Keine Daten');
    data.push(0);
  }

  // Seriöse, abgestimmte Farbpalette
  const colors = [
    '#2563eb', '#0d9488', '#f59e0b', '#6366f1',
    '#ec4899', '#0284c7', '#64748b', '#84cc16'
  ];

  chartCategoriesInstance = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: labels,
      datasets: [{
        data: data,
        backgroundColor: colors.slice(0, labels.length),
        borderWidth: 2,
        borderColor: themeColors.border
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'right',
          labels: {
            boxWidth: 10,
            boxHeight: 10,
            padding: 12,
            font: { size: 11 },
            color: themeColors.ticks
          }
        },
        tooltip: {
          backgroundColor: '#0f172a',
          titleFont: { size: 12, weight: '600' },
          bodyFont: { size: 12 },
          padding: 10,
          cornerRadius: 6,
          callbacks: {
            label: function(context) {
              return context.label + ': ' + formatCurrency(context.parsed);
            }
          }
        }
      },
      cutout: '70%'
    }
  });
}

function initOrUpdateVendorsChart(vendorCosts) {
  const ctx = document.getElementById('chartVendors');
  if (!ctx || !window.Chart) return;

  if (chartVendorsInstance) {
    chartVendorsInstance.destroy();
  }

  const themeColors = getThemeColors();
  const sortedVendors = Object.entries(vendorCosts || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);

  const labels = sortedVendors.map(v => v[0]);
  const data = sortedVendors.map(v => v[1]);

  chartVendorsInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        axis: 'y',
        label: 'Jährliche Kosten',
        data: data,
        backgroundColor: themeColors.barSecondary,
        borderRadius: 4,
        maxBarThickness: 24
      }]
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: '#0f172a',
          titleFont: { size: 12, weight: '600' },
          bodyFont: { size: 12 },
          padding: 10,
          cornerRadius: 6,
          callbacks: {
            label: function(context) {
              return 'Jährlich: ' + formatCurrency(context.parsed.x);
            }
          }
        }
      },
      scales: {
        x: {
          beginAtZero: true,
          ticks: {
            color: themeColors.ticks,
            font: { size: 11 },
            callback: function(value) {
              return value + ' €';
            }
          },
          grid: { color: themeColors.grid }
        },
        y: {
          ticks: { color: themeColors.ticks, font: { size: 11 } },
          grid: { display: false }
        }
      }
    }
  });
}
