/* خريطة شبكة حية — طوبولوجيا Canvas مع حركة حزم */
(function () {
  const canvas = document.getElementById("networkMapCanvas");
  if (!canvas) return;

  const wrap = canvas.parentElement;
  const tooltip = document.getElementById("nmapTooltip");
  const emptyEl = document.getElementById("nmapEmpty");
  const countChip = document.getElementById("nmapNodeCount");
  const linkChip = document.getElementById("nmapLinkCount");
  const ctx = canvas.getContext("2d");

  let nodes = [];
  let links = [];
  let particles = [];
  let hover = null;
  let raf = 0;
  let w = 0;
  let h = 0;
  let dpr = 1;
  let t0 = performance.now();

  const COLORS = {
    gateway: "#0ea5e9",
    sensor: "#22c55e",
    host: "#38bdf8",
    attacker: "#ef4444",
    lan: "rgba(56,189,248,0.35)",
    gatewayLink: "rgba(14,165,233,0.55)",
    traffic: "rgba(34,197,94,0.4)",
    alert: "rgba(239,68,68,0.55)",
    text: "#e2e8f0",
    grid: "rgba(148,163,184,0.08)",
  };

  function isLight() {
    return document.documentElement.getAttribute("data-theme") === "light";
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const rect = wrap.getBoundingClientRect();
    w = rect.width;
    h = rect.height;
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    canvas.style.width = w + "px";
    canvas.style.height = h + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    layout();
  }

  function layout() {
    const cx = w / 2;
    const cy = h / 2 + 6;
    const gateway = nodes.find((n) => n.role === "gateway");
    const sensor = nodes.find((n) => n.role === "sensor");
    const attackers = nodes.filter((n) => n.role === "attacker");
    const hosts = nodes.filter((n) => n.role === "host");

    if (gateway) {
      gateway.x = cx;
      gateway.y = cy;
      gateway.r = 16;
    }
    if (sensor) {
      sensor.x = cx - Math.min(120, w * 0.18);
      sensor.y = cy + Math.min(70, h * 0.16);
      sensor.r = 13;
    }

    const hostR = Math.min(w, h) * 0.28;
    hosts.forEach((n, i) => {
      const a = (i / Math.max(hosts.length, 1)) * Math.PI * 2 - Math.PI / 2;
      n.x = cx + Math.cos(a) * hostR;
      n.y = cy + Math.sin(a) * hostR * 0.72;
      n.r = 8;
      n._orbit = a;
      n._orbitR = hostR;
    });

    const atkR = Math.min(w, h) * 0.42;
    attackers.forEach((n, i) => {
      const a = (i / Math.max(attackers.length, 1)) * Math.PI * 2 + 0.4;
      n.x = cx + Math.cos(a) * atkR;
      n.y = cy + Math.sin(a) * atkR * 0.75;
      n.r = 10;
      n._orbit = a;
      n._orbitR = atkR;
    });

    // أي عقد أخرى
    nodes.forEach((n) => {
      if (n.x == null) {
        n.x = cx + (Math.random() - 0.5) * hostR;
        n.y = cy + (Math.random() - 0.5) * hostR * 0.6;
        n.r = 7;
      }
    });

    rebuildParticles();
  }

  function rebuildParticles() {
    particles = [];
    links.forEach((L, idx) => {
      const count = Math.min(4, 1 + Math.floor((L.weight || 1) / 2));
      for (let i = 0; i < count; i++) {
        particles.push({
          linkIndex: idx,
          t: Math.random(),
          speed: 0.002 + Math.random() * 0.004 + (L.kind === "alert" ? 0.003 : 0),
          kind: L.kind,
          severity: L.severity,
        });
      }
    });
  }

  function nodeById(id) {
    return nodes.find((n) => n.id === id);
  }

  function linkColor(L) {
    if (L.kind === "alert" || L.severity === "critical" || L.severity === "high") return COLORS.alert;
    if (L.kind === "gateway") return COLORS.gatewayLink;
    if (L.kind === "traffic") return COLORS.traffic;
    return COLORS.lan;
  }

  function drawGrid(now) {
    ctx.save();
    ctx.strokeStyle = isLight() ? "rgba(100,116,139,0.12)" : COLORS.grid;
    ctx.lineWidth = 1;
    const step = 36;
    const drift = ((now / 40) % step);
    for (let x = -step + drift; x < w + step; x += step) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, h);
      ctx.stroke();
    }
    for (let y = -step + drift * 0.5; y < h + step; y += step) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }
    // حلقات
    const cx = w / 2;
    const cy = h / 2 + 6;
    ctx.strokeStyle = isLight() ? "rgba(14,165,233,0.12)" : "rgba(56,189,248,0.12)";
    [0.22, 0.34, 0.46].forEach((f, i) => {
      ctx.beginPath();
      ctx.ellipse(cx, cy, Math.min(w, h) * f, Math.min(w, h) * f * 0.72, 0, 0, Math.PI * 2);
      ctx.stroke();
    });
    ctx.restore();
  }

  function drawLinks(now) {
    links.forEach((L) => {
      const a = nodeById(L.source);
      const b = nodeById(L.target);
      if (!a || !b) return;
      const pulse = 0.55 + Math.sin(now / 400 + (a.x + b.x) * 0.01) * 0.25;
      ctx.beginPath();
      ctx.strokeStyle = linkColor(L);
      ctx.globalAlpha = pulse;
      ctx.lineWidth = Math.min(3.5, 0.8 + (L.weight || 1) * 0.25);
      ctx.moveTo(a.x, a.y);
      // منحنى خفيف
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2 - 18;
      ctx.quadraticCurveTo(mx, my, b.x, b.y);
      ctx.stroke();
      ctx.globalAlpha = 1;
    });
  }

  function drawParticles() {
    particles.forEach((p) => {
      const L = links[p.linkIndex];
      if (!L) return;
      const a = nodeById(L.source);
      const b = nodeById(L.target);
      if (!a || !b) return;
      p.t += p.speed;
      if (p.t > 1) p.t = 0;
      const mx = (a.x + b.x) / 2;
      const my = (a.y + b.y) / 2 - 18;
      const t = p.t;
      const x = (1 - t) * (1 - t) * a.x + 2 * (1 - t) * t * mx + t * t * b.x;
      const y = (1 - t) * (1 - t) * a.y + 2 * (1 - t) * t * my + t * t * b.y;
      ctx.beginPath();
      ctx.fillStyle =
        p.kind === "alert" || p.severity === "critical" || p.severity === "high"
          ? "#f87171"
          : p.kind === "traffic"
            ? "#4ade80"
            : "#38bdf8";
      ctx.shadowColor = ctx.fillStyle;
      ctx.shadowBlur = 8;
      ctx.arc(x, y, p.kind === "alert" ? 2.8 : 2.2, 0, Math.PI * 2);
      ctx.fill();
      ctx.shadowBlur = 0;
    });
  }

  function drawNodes(now) {
    nodes.forEach((n) => {
      // حركة مدارية خفيفة
      if (n.role === "host" || n.role === "attacker") {
        const base = n._orbit || 0;
        const rr = n._orbitR || 100;
        const spin = now / (n.role === "attacker" ? 9000 : 14000);
        const cx = w / 2;
        const cy = h / 2 + 6;
        n.x = cx + Math.cos(base + spin) * rr;
        n.y = cy + Math.sin(base + spin) * rr * (n.role === "attacker" ? 0.75 : 0.72);
      }

      const color = COLORS[n.role] || COLORS.host;
      const active = hover && hover.id === n.id;

      // هالة
      ctx.beginPath();
      ctx.fillStyle = color;
      ctx.globalAlpha = n.role === "attacker" ? 0.18 + Math.sin(now / 250) * 0.08 : 0.12;
      ctx.arc(n.x, n.y, n.r + (active ? 14 : 10) + (n.alert_count > 0 ? 4 : 0), 0, Math.PI * 2);
      ctx.fill();
      ctx.globalAlpha = 1;

      // جسم العقدة
      const grd = ctx.createRadialGradient(n.x - 3, n.y - 3, 1, n.x, n.y, n.r + 2);
      grd.addColorStop(0, "#fff");
      grd.addColorStop(0.25, color);
      grd.addColorStop(1, color);
      ctx.beginPath();
      ctx.fillStyle = grd;
      ctx.arc(n.x, n.y, active ? n.r + 2 : n.r, 0, Math.PI * 2);
      ctx.fill();
      ctx.lineWidth = 2;
      ctx.strokeStyle = "rgba(255,255,255,0.35)";
      ctx.stroke();

      // تسمية
      const label = (n.label || n.ip || "").split("\n")[0];
      ctx.font = "600 11px 'IBM Plex Sans Arabic', Tahoma, sans-serif";
      ctx.textAlign = "center";
      ctx.fillStyle = isLight() ? "#0f172a" : "#e2e8f0";
      ctx.globalAlpha = 0.92;
      ctx.fillText(label.length > 18 ? label.slice(0, 16) + "…" : label, n.x, n.y + n.r + 14);
      ctx.globalAlpha = 1;

      if (n.alert_count > 0) {
        ctx.beginPath();
        ctx.fillStyle = "#ef4444";
        ctx.arc(n.x + n.r * 0.7, n.y - n.r * 0.7, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = "#fff";
        ctx.font = "700 8px sans-serif";
        ctx.fillText(String(Math.min(n.alert_count, 9)), n.x + n.r * 0.7, n.y - n.r * 0.7 + 2.5);
      }
    });
  }

  function frame(now) {
    ctx.clearRect(0, 0, w, h);
    drawGrid(now);
    drawLinks(now);
    drawParticles();
    drawNodes(now);
    raf = requestAnimationFrame(frame);
  }

  function hitTest(mx, my) {
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i];
      const dx = mx - n.x;
      const dy = my - n.y;
      if (dx * dx + dy * dy <= (n.r + 8) * (n.r + 8)) return n;
    }
    return null;
  }

  function showTip(n, clientX, clientY) {
    if (!tooltip || !n) {
      if (tooltip) tooltip.classList.remove("visible");
      return;
    }
    const roleAr =
      { gateway: "بوابة الراوتر", sensor: "مستشعر NIDS", host: "جهاز", attacker: "مصدر مشبوه" }[
        n.role
      ] || n.role;
    tooltip.innerHTML = `<strong>${n.ip}</strong>
      <div class="row"><span>الدور</span><span>${roleAr}</span></div>
      <div class="row"><span>التنبيهات</span><span>${n.alert_count || 0}</span></div>
      <div class="row"><span>الحزم</span><span>${n.packet_count || 0}</span></div>
      <div class="row"><span>الخطورة</span><span>${n.severity || "info"}</span></div>
      ${n.mac ? `<div class="row"><span>MAC</span><span>${n.mac}</span></div>` : ""}
      ${n.is_simulated ? `<div class="row"><span>مصدر</span><span>تجريبي</span></div>` : ""}`;
    const rect = wrap.getBoundingClientRect();
    let left = clientX - rect.left + 14;
    let top = clientY - rect.top + 14;
    if (left + 200 > rect.width) left = clientX - rect.left - 210;
    if (top + 120 > rect.height) top = clientY - rect.top - 100;
    tooltip.style.left = left + "px";
    tooltip.style.top = top + "px";
    tooltip.classList.add("visible");
  }

  canvas.addEventListener("mousemove", (e) => {
    const rect = canvas.getBoundingClientRect();
    const n = hitTest(e.clientX - rect.left, e.clientY - rect.top);
    hover = n;
    canvas.style.cursor = n ? "pointer" : "grab";
    showTip(n, e.clientX, e.clientY);
  });
  canvas.addEventListener("mouseleave", () => {
    hover = null;
    if (tooltip) tooltip.classList.remove("visible");
  });
  canvas.addEventListener("click", () => {
    if (hover && hover.ip) {
      window.location.href = "/ip-investigation?ip=" + encodeURIComponent(hover.ip);
    }
  });

  async function loadMap() {
    try {
      const res = await fetch("/api/network-map", { credentials: "same-origin" });
      if (!res.ok) return;
      const data = await res.json();
      nodes = data.nodes || [];
      links = data.links || [];
      if (countChip) countChip.textContent = String(data.node_count || nodes.length);
      if (linkChip) linkChip.textContent = String(data.link_count || links.length);
      if (emptyEl) {
        emptyEl.style.display = nodes.length ? "none" : "grid";
      }
      layout();
    } catch (e) {
      /* تجاهل */
    }
  }

  window.addEventListener("resize", () => {
    resize();
  });

  resize();
  loadMap();
  raf = requestAnimationFrame(frame);
  setInterval(loadMap, 8000);

  // بيانات أولية من الصفحة إن وُجدت
  if (window.NIDS_MAP && window.NIDS_MAP.nodes) {
    nodes = window.NIDS_MAP.nodes;
    links = window.NIDS_MAP.links || [];
    if (countChip) countChip.textContent = String(nodes.length);
    if (linkChip) linkChip.textContent = String(links.length);
    if (emptyEl) emptyEl.style.display = nodes.length ? "none" : "grid";
    layout();
  }
})();
