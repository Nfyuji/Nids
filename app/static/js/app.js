/* أدوات عامة للواجهة */
(function () {
  function tick() {
    const el = document.getElementById("live-clock");
    if (!el) return;
    const now = new Date();
    el.textContent = now.toLocaleString("ar-SA", {
      weekday: "short",
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
  tick();
  setInterval(tick, 1000);

  // إغلاق الشريط الجانبي عند النقر خارجاً على الجوال
  document.addEventListener("click", (e) => {
    const sidebar = document.getElementById("sidebar");
    if (!sidebar || !sidebar.classList.contains("open")) return;
    if (sidebar.contains(e.target) || e.target.closest(".mobile-toggle")) return;
    sidebar.classList.remove("open");
  });
})();

window.NIDS_CHART_DEFAULTS = function () {
  const theme = document.documentElement.getAttribute("data-theme") || "dark";
  const muted = theme === "light" ? "#64748b" : "#94a3b8";
  const grid = theme === "light" ? "rgba(100,116,139,0.15)" : "rgba(148,163,184,0.08)";
  Chart.defaults.color = muted;
  Chart.defaults.borderColor = grid;
  Chart.defaults.font.family = "'IBM Plex Sans Arabic', sans-serif";
};
