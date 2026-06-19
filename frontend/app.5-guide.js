// ===== In-app user guide =====
// A self-contained, paginated help manual rendered from static markup. The
// contract is data-* attributes so the content (in index.html) stays portable
// and this controller never needs per-page edits:
//
//   [data-guide]            container holding the pages
//   [data-page] [data-title]  one guide page + its TOC/label title
//   [data-group]            (optional) groups pages under a TOC heading
//   [data-guide-toc]        element the table of contents is rendered into
//   [data-guide-prev/next]  previous / next buttons
//   [data-guide-pglabel]    "<n> / <total> · <title>" position label
//
// Opened from the header "Guide" button, context-aware: it lands on the page
// matching wherever you are (current dashboard or admin panel). Other code can
// call window.openGuide("<data-page>") to deep-link a specific page.
(function () {
  const root = document.querySelector("[data-guide]");
  const overlay = document.getElementById("guide-overlay");
  if (!root || !overlay) return;

  const pages = Array.from(root.querySelectorAll("[data-page]"));
  const tocEl = document.querySelector("[data-guide-toc]");
  const pglabel = document.querySelector("[data-guide-pglabel]");
  const prevBtn = document.querySelector("[data-guide-prev]");
  const nextBtn = document.querySelector("[data-guide-next]");
  const content = root.parentElement; // scroll container
  let idx = 0;

  function buildToc() {
    if (!tocEl) return;
    tocEl.innerHTML = "";
    let lastGroup = null;
    pages.forEach((pg, i) => {
      const grp = pg.getAttribute("data-group") || "";
      if (grp && grp !== lastGroup) {
        const h = document.createElement("div");
        h.className = "guide-toc-group";
        h.textContent = grp;
        tocEl.appendChild(h);
        lastGroup = grp;
      }
      const b = document.createElement("button");
      b.type = "button";
      b.className = "guide-toc-item";
      b.textContent = pg.getAttribute("data-title") || pg.getAttribute("data-page");
      b.dataset.idx = String(i);
      b.addEventListener("click", () => show(i));
      tocEl.appendChild(b);
    });
  }

  function show(i) {
    idx = Math.max(0, Math.min(pages.length - 1, i));
    pages.forEach((pg, j) => { pg.hidden = j !== idx; });
    if (tocEl) {
      tocEl.querySelectorAll(".guide-toc-item").forEach((it) => {
        const on = Number(it.dataset.idx) === idx;
        it.classList.toggle("active", on);
        if (on) it.scrollIntoView({ block: "nearest" });
      });
    }
    if (pglabel) {
      pglabel.textContent =
        `${idx + 1} / ${pages.length} · ${pages[idx].getAttribute("data-title") || ""}`;
    }
    if (prevBtn) prevBtn.disabled = idx === 0;
    if (nextBtn) nextBtn.disabled = idx === pages.length - 1;
    if (content) content.scrollTop = 0;
  }

  function indexOfPage(id) {
    const n = pages.findIndex((p) => p.getAttribute("data-page") === id);
    return n < 0 ? 0 : n;
  }

  function open(pageId) {
    if (pageId) show(indexOfPage(pageId));
    overlay.hidden = false;
    document.body.classList.add("guide-open");
  }
  function close() {
    overlay.hidden = true;
    document.body.classList.remove("guide-open");
  }

  // Which guide page matches the part of the app you're currently looking at.
  function contextPage() {
    const adminView = document.getElementById("admin-view");
    if (adminView && !adminView.hidden) {
      const ap = document.querySelector("#admin-nav button.active");
      return ap ? "admin-" + ap.dataset.panel : "admin-overview";
    }
    const mp = document.querySelector("#main-nav button.active");
    return mp ? mp.dataset.panel : "welcome";
  }

  buildToc();
  show(0);

  if (prevBtn) prevBtn.addEventListener("click", () => show(idx - 1));
  if (nextBtn) nextBtn.addEventListener("click", () => show(idx + 1));
  const closeBtn = document.getElementById("guide-close");
  if (closeBtn) closeBtn.addEventListener("click", close);
  overlay.addEventListener("click", (e) => { if (e.target === overlay) close(); });
  document.addEventListener("keydown", (e) => {
    if (overlay.hidden) return;
    if (e.key === "Escape") close();
    else if (e.key === "ArrowLeft") show(idx - 1);
    else if (e.key === "ArrowRight") show(idx + 1);
  });
  const navGuide = document.getElementById("nav-guide");
  if (navGuide) navGuide.addEventListener("click", () => open(contextPage()));

  // Deep-link hook for any per-panel "?" affordance.
  window.openGuide = open;
})();
