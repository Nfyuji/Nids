(function () {
  const tbody = document.querySelector("#traffic-table tbody");
  const ppsPill = document.getElementById("pps-pill");
  const updated = document.getElementById("traffic-updated");
  if (!tbody) return;

  function fmtTime(iso) {
    if (!iso) return "—";
    try {
      return new Date(iso).toLocaleTimeString("ar-SA");
    } catch {
      return iso;
    }
  }

  async function refresh() {
    try {
      const res = await fetch("/api/traffic/live", { credentials: "same-origin" });
      if (!res.ok) return;
      const data = await res.json();
      if (ppsPill) ppsPill.textContent = "PPS: " + (data.pps || 0).toFixed(1);
      if (updated) updated.textContent = "حدّث: " + new Date().toLocaleTimeString("ar-SA");

      if (!data.events || !data.events.length) {
        tbody.innerHTML =
          '<tr id="empty-row"><td colspan="8" class="empty-state">لا توجد حركة مرصودة بعد.</td></tr>';
        return;
      }
      tbody.innerHTML = data.events
        .map(
          (e) => `<tr>
          <td>${fmtTime(e.observed_at)}</td>
          <td>${e.src_ip || "—"}</td>
          <td>${e.dst_ip || "—"}</td>
          <td>${e.src_port || "—"} → ${e.dst_port || "—"}</td>
          <td>${e.protocol || "—"}</td>
          <td>${e.packet_count || 0}</td>
          <td>${e.byte_count || 0}</td>
          <td>${e.flags || "—"}</td>
        </tr>`
        )
        .join("");
    } catch (err) {
      /* تجاهل أخطاء الشبكة المؤقتة */
    }
  }

  setInterval(refresh, 4000);
})();
