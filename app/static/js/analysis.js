document.addEventListener("DOMContentLoaded", () => {
  if (typeof Chart === "undefined" || !window.NIDS_ANALYSIS) return;
  if (window.NIDS_CHART_DEFAULTS) window.NIDS_CHART_DEFAULTS();
  const { timeline: t, distribution: d } = window.NIDS_ANALYSIS;

  const distEl = document.getElementById("analysisDist");
  if (distEl && d && d.has_data) {
    new Chart(distEl, {
      type: "bar",
      data: {
        labels: (d.categories || d.items || []).map((i) => i.label_ar),
        datasets: [
          {
            label: "العدد",
            data: (d.categories || d.items || []).map((i) => i.count),
            backgroundColor: ["#f97316", "#a855f7", "#38bdf8", "#22c55e", "#14b8a6"],
            borderRadius: 8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: { y: { beginAtZero: true } },
      },
    });
  }

  const tlEl = document.getElementById("analysisTimeline");
  if (tlEl && t && t.has_data) {
    new Chart(tlEl, {
      type: "line",
      data: {
        labels: t.labels,
        datasets: [
          {
            label: "مشبوه",
            data: t.suspicious,
            borderColor: "#f59e0b",
            tension: 0.3,
          },
          {
            label: "خبيث",
            data: t.malicious,
            borderColor: "#ef4444",
            tension: 0.3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: { y: { beginAtZero: true } },
      },
    });
  }
});
