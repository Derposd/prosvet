// Prosvet local dashboard. No third-party code, no network access beyond 127.0.0.1.
(() => {
  "use strict";
  const token = document.querySelector('meta[name="prosvet-token"]').content;
  const $ = (id) => document.getElementById(id);
  const run = $("run"), wl = $("wl"), cancel = $("cancel");
  const progress = $("progress"), bar = $("bar"), phase = $("phase"), live = $("live");

  const post = (path, body) =>
    fetch(path, {
      method: "POST",
      headers: { "X-Prosvet-Token": token, "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });

  const busy = (on) => {
    run.disabled = wl.disabled = on;
    cancel.hidden = !on;
    progress.hidden = !on;
  };

  const row = (t) => {
    const div = document.createElement("div");
    div.className = "s-" + t.status;
    const dot = document.createElement("span");
    dot.className = "dot";
    const text = document.createElement("span");
    text.textContent = " " + t.name + " — " + t.status_text + (t.kind_title ? " · " + t.kind_title : "");
    div.append(dot, text);
    return div;
  };

  const listen = () => {
    busy(true);
    const es = new EventSource("/api/events");
    es.onmessage = (e) => {
      const ev = JSON.parse(e.data);
      if (ev.total > 0) bar.style.width = Math.round((100 * ev.done) / ev.total) + "%";
      if (ev.phase_text) phase.textContent = ev.phase_text;
      if (ev.target) live.prepend(row(ev.target));
      if (ev.kind === "finished") {
        es.close();
        location.reload();
      }
    };
    es.onerror = () => {
      es.close();
      setTimeout(() => location.reload(), 1500);
    };
  };

  run.addEventListener("click", async () => {
    const cats = [...document.querySelectorAll('input[name="cat"]:checked')].map((i) => i.value);
    const r = await post("/api/scan", { categories: cats });
    if (r.ok || r.status === 409) listen();
  });
  wl.addEventListener("click", async () => {
    const r = await post("/api/whitelist");
    if (r.ok || r.status === 409) listen();
  });
  cancel.addEventListener("click", () => post("/api/cancel"));

  if (document.body.dataset.running) listen();
})();
