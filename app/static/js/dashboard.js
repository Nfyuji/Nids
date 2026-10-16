document.addEventListener("DOMContentLoaded", () => {
  if (typeof Chart === "undefined" || !window.NIDS_DASH) return;
  if (window.NIDS_CHART_DEFAULTS) window.NIDS_CHART_DEFAULTS();

  const t = window.NIDS_DASH.timeline;
  const d = window.NIDS_DASH.distribution;
  const trafficEl = document.getElementById("trafficChart");
  const distEl = document.getElementById("distChart");

  if (trafficEl && t && t.has_data) {
    new Chart(trafficEl, {
      type: "line",
      data: {
        labels: t.labels,
        datasets: [
          {
            label: "طبيعي",
            data: t.normal,
            borderColor: "#22c55e",
            backgroundColor: "rgba(34,197,94,0.15)",
            fill: true,
            tension: 0.35,
          },
          {
            label: "مشبوه",
            data: t.suspicious,
            borderColor: "#f59e0b",
            backgroundColor: "rgba(245,158,11,0.12)",
            fill: true,
            tension: 0.35,
          },
          {
            label: "خبيث",
            data: t.malicious,
            borderColor: "#ef4444",
            backgroundColor: "rgba(239,68,68,0.12)",
            fill: true,
            tension: 0.35,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: "top", align: "end" } },
        scales: { x: { grid: { display: false } }, y: { beginAtZero: true } },
      },
    });
  }

  if (distEl && d && d.has_data) {
    const colors = ["#f97316", "#a855f7", "#38bdf8", "#22c55e", "#14b8a6", "#ef4444"];
    new Chart(distEl, {
      type: "doughnut",
      data: {
        labels: d.items.map((i) => i.label_ar),
        datasets: [
          {
            data: d.items.map((i) => i.count),
            backgroundColor: colors.slice(0, d.items.length),
            borderWidth: 0,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "68%",
        plugins: { legend: { display: false } },
      },
    });
  }

  const refresh = document.getElementById("last-refresh");
  if (refresh) {
    setInterval(() => {
      refresh.textContent = new Date().toLocaleTimeString("ar-SA");
    }, 15000);
  }
});
