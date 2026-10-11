// Prosvet public map. Vanilla JS, no dependencies, no network access except data/map.json.
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  };
  const store = {
    get(k) { try { return localStorage.getItem(k); } catch (_) { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch (_) { /* private mode */ } },
  };

  let data = null;
  let lang = store.get("prosvet.lang") || ((navigator.language || "").toLowerCase().startsWith("ru") ? "ru" : "en");
  const filters = { cat: "", region: "", conn: "", q: "" };

  const t = (key, args) => {
    let s = (data && data.i18n[lang] && data.i18n[lang][key]) || (data && data.i18n.en && data.i18n.en[key]) || key;
    if (args) for (const [k, v] of Object.entries(args)) s = s.split("{" + k + "}").join(v);
    return s;
  };
  const statusText = (s) => t("status." + s);
  const kindText = (k) => t("kind." + k + ".title");
  const regionName = (code) => {
    const r = data.regions.find((x) => x.code === code);
    return r ? r[lang] || r.en : code;
  };
  const rowLabel = (r) => r.isp + " · AS" + r.asn;
  const rowSub = (r) => [r.region ? regionName(r.region) : "", t("conn." + r.conn)].filter(Boolean).join(" · ");
  const daysAgo = (d) => (Date.now() - Date.parse(d + "T00:00:00Z")) / 86400000;

  function applyI18n() {
    document.documentElement.lang = lang;
    document.querySelectorAll("[data-i18n]").forEach((n) => { n.textContent = t(n.dataset.i18n); });
    $("lang").textContent = lang === "ru" ? "EN" : "RU";
    $("f-search").placeholder = "Rostelecom, 12389…";
  }

  function option(sel, value, label, selected) {
    const o = el("option", "", label);
    o.value = value;
    if (selected) o.selected = true;
    sel.append(o);
  }

  function renderFilters() {
    const cat = $("f-cat"), region = $("f-region"), conn = $("f-conn");
    [cat, region, conn].forEach((s) => s.replaceChildren());
    option(cat, "", t("map.all"), !filters.cat);
    data.categories.forEach((c) => option(cat, c.id, c.title[lang] || c.title.en, filters.cat === c.id));
    option(region, "", t("map.all"), !filters.region);
    data.regions.forEach((r) => option(region, r.code, r[lang] || r.en, filters.region === r.code));
    option(conn, "", t("map.all"), !filters.conn);
    ["fixed", "mobile", "unknown"].forEach((c) => option(conn, c, t("conn." + c), filters.conn === c));
  }

  function renderStats() {
    const s = $("stats");
    s.replaceChildren();
    const pill = (n, label) => {
      const p = el("span", "pill");
      p.append(el("b", "", String(n)), document.createTextNode(" " + label));
      s.append(p);
    };
    pill(data.submissions, t("map.reports"));
    pill(data.rows.length, t("map.networks"));
    pill(data.targets.length, t("map.services"));
    if (data.updated) {
      const p = el("span", "pill");
      p.append(document.createTextNode(t("map.updated") + " "), el("b", "", data.updated));
      s.append(p);
    }
  }

  function renderLegend() {
    const l = $("legend");
    l.replaceChildren();
    ["ok", "throttled", "partial", "blocked"].forEach((st) => {
      const span = el("span");
      span.append(el("i", "sq s-" + st), document.createTextNode(statusText(st)));
      l.append(span);
    });
    const none = el("span");
    none.append(el("i", "sq"), document.createTextNode("—"));
    l.append(none);
  }

  function visibleRows() {
    const q = filters.q.trim().toLowerCase();
    return data.rows.filter((r) =>
      (!filters.region || r.region === filters.region) &&
      (!filters.conn || r.conn === filters.conn) &&
      (!q || r.isp.toLowerCase().includes(q) || String(r.asn).includes(q.replace(/^as/, ""))));
  }

  function visibleTargets() {
    return data.targets.filter((x) => !filters.cat || x.category === filters.cat);
  }

  function renderHeat() {
    const rows = visibleRows(), targets = visibleTargets();
    const table = $("heat");
    table.replaceChildren();
    const empty = rows.length === 0 || targets.length === 0;
    $("heat-wrap").hidden = empty;
    $("empty").hidden = !empty;
    $("empty").textContent = t("map.empty");
    if (empty) return;

    const thead = el("thead");
    const cats = el("tr", "cats");
    cats.append(el("th", "net"));
    let i = 0;
    while (i < targets.length) {
      const c = targets[i].category;
      let span = 0;
      while (i + span < targets.length && targets[i + span].category === c) span++;
      const meta = data.categories.find((x) => x.id === c);
      const th = el("th", "", meta ? meta.title[lang] || meta.title.en : c);
      th.colSpan = span;
      cats.append(th);
      i += span;
    }
    const names = el("tr", "names");
    names.append(el("th", "net", t("map.network")));
    targets.forEach((x) => {
      const th = el("th");
      const b = el("button", "", x.name);
      b.type = "button";
      b.addEventListener("click", () => openPanel(x.id, null));
      th.append(b);
      names.append(th);
    });
    thead.append(cats, names);

    const tbody = el("tbody");
    rows.forEach((r) => {
      const tr = el("tr");
      const net = el("td", "net");
      net.title = rowLabel(r) + " — " + rowSub(r);
      net.append(document.createTextNode(rowLabel(r)), el("br"), el("small", "", rowSub(r)));
      tr.append(net);
      const cells = data.cells[r.key] || {};
      targets.forEach((x) => {
        const c = cells[x.id];
        const td = el("td", "c" + (c ? " s-" + c.s : "") + (c && daysAgo(c.d) > 30 ? " old" : ""));
        const b = el("button");
        b.type = "button";
        if (c) {
          const tip = t("map.cell_tip", { status: statusText(c.s), kind: kindText(c.k), date: c.d, n: String(c.n) });
          b.title = x.name + " — " + tip;
          b.setAttribute("aria-label", b.title);
          b.addEventListener("click", () => openPanel(x.id, r));
        } else {
          b.disabled = true;
          b.setAttribute("aria-label", x.name + " — —");
        }
        td.append(b);
        tr.append(td);
      });
      tbody.append(tr);
    });
    table.append(thead, tbody);
  }

  function chart(days) {
    const NS = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(NS, "svg");
    const w = 640, h = 140, pad = 18;
    svg.setAttribute("viewBox", `0 0 ${w} ${h + pad}`);
    svg.setAttribute("role", "img");
    if (!days || days.length === 0) return svg;
    const bw = Math.max(2, Math.min(40, (w - 4) / days.length - 2));
    days.forEach((d, i) => {
      const counts = d.slice(1);
      const total = counts.reduce((a, b) => a + b, 0) || 1;
      let y = h;
      ["ok", "throttled", "partial", "blocked"].forEach((st, k) => {
        const hh = (counts[k] / total) * h;
        if (hh <= 0) return;
        y -= hh;
        const rect = document.createElementNS(NS, "rect");
        rect.setAttribute("x", String(2 + i * (bw + 2)));
        rect.setAttribute("y", String(y));
        rect.setAttribute("width", String(bw));
        rect.setAttribute("height", String(hh));
        rect.setAttribute("class", "bar-" + st);
        const title = document.createElementNS(NS, "title");
        title.textContent = `${d[0]}: ${statusText(st)} ${counts[k]}`;
        rect.append(title);
        svg.append(rect);
      });
    });
    const label = (x, text, anchor) => {
      const tx = document.createElementNS(NS, "text");
      tx.setAttribute("x", String(x));
      tx.setAttribute("y", String(h + 13));
      tx.setAttribute("class", "axis");
      tx.setAttribute("text-anchor", anchor);
      tx.textContent = text;
      svg.append(tx);
    };
    label(2, days[0][0], "start");
    if (days.length > 1) label(w - 2, days[days.length - 1][0], "end");
    return svg;
  }

  function openPanel(targetId, row) {
    const target = data.targets.find((x) => x.id === targetId);
    $("panel-title").textContent = target ? target.name : targetId;
    const cellInfo = $("panel-cell");
    cellInfo.replaceChildren();
    if (row) {
      const c = (data.cells[row.key] || {})[targetId];
      cellInfo.textContent = rowLabel(row) + " · " + rowSub(row) + " — " +
        (c ? t("map.cell_tip", { status: statusText(c.s), kind: kindText(c.k), date: c.d, n: String(c.n) }) : "—");
    }
    $("panel-chart").replaceChildren(chart(data.timeline[targetId]));
    const list = $("panel-events");
    list.replaceChildren();
    const events = (data.events[targetId] || []).filter((e) => !row || e.row === row.key);
    if (events.length === 0) list.append(el("li", "muted", t("map.no_history")));
    events.slice(0, 50).forEach((e) => {
      const r = data.rows.find((x) => x.key === e.row);
      const li = el("li");
      li.append(el("time", "", e.d), el("span", "", r ? rowLabel(r) : e.row),
        el("i", "sq s-" + e.from), el("span", "arrow", "→"), el("i", "sq s-" + e.to),
        el("span", "muted", statusText(e.to) + (e.to !== "ok" ? " · " + kindText(e.k) : "")));
      list.append(li);
    });
    const dlg = $("panel");
    if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
  }

  function render() {
    applyI18n();
    renderStats();
    renderFilters();
    renderLegend();
    renderHeat();
    const sample = $("sample");
    sample.hidden = !data.sample;
    sample.textContent = "⚠ " + t("map.sample");
    $("generated").textContent = data.generated;
    $("repo-link").href = "https://github.com/" + data.repo;
  }

  function bind() {
    $("lang").addEventListener("click", () => {
      lang = lang === "ru" ? "en" : "ru";
      store.set("prosvet.lang", lang);
      render();
    });
    $("f-cat").addEventListener("change", (e) => { filters.cat = e.target.value; renderHeat(); });
    $("f-region").addEventListener("change", (e) => { filters.region = e.target.value; renderHeat(); });
    $("f-conn").addEventListener("change", (e) => { filters.conn = e.target.value; renderHeat(); });
    $("f-search").addEventListener("input", (e) => { filters.q = e.target.value; renderHeat(); });
  }

  fetch("data/map.json", { cache: "no-cache" })
    .then((r) => r.json())
    .then((d) => { data = d; bind(); render(); })
    .catch(() => { $("empty").hidden = false; $("empty").textContent = "data/map.json could not be loaded"; });
})();
