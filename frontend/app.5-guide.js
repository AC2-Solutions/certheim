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

  const allPages = Array.from(root.querySelectorAll("[data-page]"));
  let pages = allPages;   // active subset; Administration pages hidden for non-admins
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

  // Per-page content filters: a <select data-guide-filter> inside a guide page
  // narrows that page to the [data-filter-tag] blocks matching the selection,
  // so long reference pages (e.g. Signing/CA backend setup) don't force a
  // scroll-through. "all" — the default — shows every block.
  root.addEventListener("change", (e) => {
    const sel = e.target.closest("select[data-guide-filter]");
    if (!sel) return;
    const page = sel.closest("[data-page]");
    if (!page) return;
    page.querySelectorAll("[data-filter-tag]").forEach((el) => {
      el.hidden = sel.value !== "all"
        && el.getAttribute("data-filter-tag") !== sel.value;
    });
    if (content) content.scrollTop = 0;
  });

  // Regular users only get the Getting-started + Dashboard guides; the
  // Administration pages are admin-only (they can't reach those screens anyway).
  // Recomputed on each open so it tracks the logged-in user.
  function refreshPages() {
    const isAdmin = !!(typeof currentUser !== "undefined" && currentUser && currentUser.is_admin);
    pages = allPages.filter((p) =>
      isAdmin || (p.getAttribute("data-group") || "") !== "Administration");
    allPages.forEach((p) => { if (pages.indexOf(p) < 0) p.hidden = true; });
    buildToc();
  }

  function open(pageId) {
    refreshPages();
    show(pageId ? indexOfPage(pageId) : Math.min(idx, pages.length - 1));
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

  // Drop a small "?" next to each panel's title that deep-links the guide to
  // that page. Injected (not hand-placed in markup) so it stays in sync with
  // the pages above and never collides with a card-header's right-side controls.
  function injectPanelHelp() {
    const ids = new Set(allPages.map((p) => p.getAttribute("data-page")));
    [["#main-panels", (dp) => dp], ["#admin-panels", (dp) => "admin-" + dp]]
      .forEach(([container, toId]) => {
        const host = document.querySelector(container);
        if (!host) return;
        host.querySelectorAll(":scope > [data-panel]").forEach((panel) => {
          const pid = toId(panel.getAttribute("data-panel"));
          if (!ids.has(pid)) return;
          const head = panel.querySelector("h2, h3");
          if (!head || head.querySelector(".panel-help-btn")) return;
          const b = document.createElement("button");
          b.type = "button";
          b.className = "panel-help-btn";
          b.textContent = "?";
          b.title = "Open the guide for this page";
          b.setAttribute("aria-label", "Open the guide for this page");
          b.addEventListener("click", (e) => {
            e.preventDefault(); e.stopPropagation(); open(pid);
          });
          head.appendChild(b);
        });
      });
  }

  refreshPages();   // build the (filtered) TOC for the current user
  injectPanelHelp();
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

// ===== Connection setup wizard (OpenBao / CyberArk) =====
// Self-contained: injects its own launcher button, modal, and scoped styles -
// no markup edits in index.html, so it never collides with in-flight changes.
// An admin picks an integration and fills in THEIR values; the wizard generates
// tailored, copy-pasteable setup steps (external system + Certinel config), so
// nobody has to reverse-engineer which knobs a given connection needs.
// All defaults below are generic placeholders - no environment specifics.
(function () {
  // ---- helpers -----------------------------------------------------------
  const esc = (s) => String(s == null ? "" : s);
  function el(tag, attrs, kids) {
    const n = document.createElement(tag);
    if (attrs) for (const k in attrs) {
      if (k === "class") n.className = attrs[k];
      else if (k === "text") n.textContent = attrs[k];
      else n.setAttribute(k, attrs[k]);
    }
    (kids || []).forEach((c) => n.appendChild(typeof c === "string" ? document.createTextNode(c) : c));
    return n;
  }
  // a value, falling back to its placeholder so the output is always complete
  const V = (vals, f) => (vals[f.key] && String(vals[f.key]).trim()) || f.ph || "";

  // ---- integration specs -------------------------------------------------
  // fields: {key,label,ph(placeholder/default),hint?,type?('checkbox')}
  // gen(v): returns blocks [{h:..}|{p:..}|{code:..,lang?}|{note:..}]
  const SPECS = [
    {
      id: "openbao_sign",
      group: "OpenBao / HashiCorp Vault",
      label: "Signing (PKI)",
      blurb: "Certinel signs approved CSRs by calling an OpenBao/Vault PKI role. Uses an AppRole scoped to only that one sign path.",
      fields: [
        { key: "addr", label: "OpenBao address", ph: "https://openbao.example.com" },
        { key: "pki", label: "PKI mount", ph: "pki_csr" },
        { key: "role", label: "Signing role", ph: "certinel" },
        { key: "approle", label: "AppRole name", ph: "certinel-signer" },
        { key: "policy", label: "Policy name", ph: "certinel-sign" },
        { key: "ttl", label: "Max cert TTL (hours)", ph: "8760" },
        { key: "cafile", label: "OpenBao CA file path (optional, TLS pin)", ph: "" },
        { key: "revoke", label: "Also allow in-UI revoke", ph: "", type: "checkbox" },
      ],
      gen(v) {
        const pki = V(v, this.fields[1]), role = V(v, this.fields[2]),
          ar = V(v, this.fields[3]), pol = V(v, this.fields[4]),
          ttl = V(v, this.fields[5]), addr = V(v, this.fields[0]),
          ca = (v.cafile || "").trim(), rev = !!v.revoke;
        const revLine = rev ? `\npath "${pki}/revoke" { capabilities = ["update"] }` : "";
        return [
          { h: "1 - In OpenBao / Vault (run once with an admin token)" },
          { p: "Enable a PKI engine and load your issuing CA (skip if you already have one), then create the role Certinel calls:" },
          { code:
`# PKI engine + your issuing CA (generate or import your CA into this mount)
bao secrets enable -path=${pki} pki
bao secrets tune -max-lease-ttl=${ttl}h ${pki}

# Signing role Certinel will use (tune the constraints to your policy)
bao write ${pki}/roles/${role} allow_any_name=true allow_subdomains=true max_ttl=${ttl}h` },
          { p: "Create a least-privilege policy - Certinel needs nothing but the sign path" + (rev ? " (and revoke)" : "") + ":" },
          { code:
`bao policy write ${pol} - <<'EOF'
path "${pki}/sign/${role}" { capabilities = ["update"] }${revLine}
EOF` },
          { p: "Create an AppRole bound to that policy. The role_id + secret_id it prints are Certinel's credentials:" },
          { code:
`bao auth enable approle    # skip if already enabled
bao write auth/approle/role/${ar} \\
    token_policies=${pol} token_ttl=20m token_max_ttl=30m \\
    secret_id_ttl=0 secret_id_num_uses=0
bao read  -field=role_id      auth/approle/role/${ar}/role-id
bao write -f -field=secret_id auth/approle/role/${ar}/secret-id` },
          { h: "2 - In Certinel: /etc/certinel/certinel.env" },
          { p: "The AppRole credentials live ONLY in the env file (never in the app database). Paste the role_id/secret_id from step 1, then restart:" },
          { code:
`CSR_CAP_OPENBAO=1
CSR_OPENBAO_ADDR=${addr}
CSR_OPENBAO_ROLE_ID=<role_id from step 1>
CSR_OPENBAO_SECRET_ID=<secret_id from step 1>${ca ? `\nCSR_OPENBAO_CA_FILE=${ca}` : ""}

# then:
sudo systemctl restart certinel-api` },
          { h: "3 - In Certinel: Administration -> Signing / CA" },
          { p: "Set the non-secret connection fields and test:" },
          { code:
`Signing provider : OpenBao
OpenBao address  : ${addr}
PKI mount        : ${pki}
Default role     : ${role}` },
          { p: "Click “Test connection”, then Save. (Per-template role/TTL overrides are available on each template.)" },
          { note: "The AppRole can only call " + pki + "/sign/" + role + (rev ? " and " + pki + "/revoke" : "") + " - it cannot read private keys or mint CAs." },
        ];
      },
    },
    {
      id: "openbao_deliver",
      group: "OpenBao / HashiCorp Vault",
      label: "Cert delivery (KV v2)",
      blurb: "After issuance, Certinel writes the cert (and optionally the key) into an OpenBao KV-v2 path. Reuses the signing AppRole.",
      fields: [
        { key: "kv", label: "KV v2 mount", ph: "secret" },
        { key: "base", label: "Base path for certs", ph: "csr-certs" },
        { key: "policy", label: "Policy to extend", ph: "certinel-sign" },
      ],
      gen(v) {
        const kv = V(v, this.fields[0]), base = V(v, this.fields[1]), pol = V(v, this.fields[2]);
        return [
          { h: "1 - In OpenBao: extend the AppRole policy" },
          { p: "Add KV-v2 write access for the delivery base path to your existing signing policy (KV v2 uses /data/ and /metadata/ prefixes):" },
          { code:
`# append to ${pol}, then re-run: bao policy write ${pol} <file>
path "${kv}/data/${base}/*"     { capabilities = ["create","update"] }
path "${kv}/metadata/${base}/*" { capabilities = ["read","delete"] }` },
          { note: "No new credentials - delivery reuses the same OpenBao AppRole/env from the signing setup." },
          { h: "2 - In Certinel: Administration -> Templates -> (edit a template) -> Delivery" },
          { code:
`Delivery backend : OpenBao
Key handling     : destination (cert only) | ship (cert + key) | vault (store key in OpenBao)
Destination path : ${base}/<host>      (leave blank to use the base path)` },
          { p: "On issuance the cert is written to:" },
          { code: `${kv}/data/${base}/<target_host>` },
        ];
      },
    },
    {
      id: "openbao_keys",
      group: "OpenBao / HashiCorp Vault",
      label: "Private-key storage",
      blurb: "Generated private keys are stored in OpenBao instead of on the host disk; the host copy is shredded immediately.",
      fields: [
        { key: "kv", label: "KV v2 mount", ph: "secret" },
        { key: "policy", label: "Policy to extend", ph: "certinel-sign" },
        { key: "mode", label: "Policy: vault (keep) or return_once (destroy after first fetch)", ph: "vault" },
      ],
      gen(v) {
        const kv = V(v, this.fields[0]), pol = V(v, this.fields[1]), mode = V(v, this.fields[2]);
        return [
          { h: "1 - In OpenBao: extend the AppRole policy" },
          { p: "Certinel stores keys under a dedicated path; grant the AppRole full lifecycle there:" },
          { code:
`# append to ${pol}, then re-run: bao policy write ${pol} <file>
path "${kv}/data/certinel-keys/*"     { capabilities = ["create","read","update","delete"] }
path "${kv}/metadata/certinel-keys/*" { capabilities = ["delete"] }` },
          { h: "2 - In Certinel: Administration -> Signing / CA -> Key storage" },
          { code: `Key storage policy : ${mode}` },
          { p: mode === "return_once"
              ? "return_once: the key is stored in OpenBao, fetched exactly once at delivery, then destroyed."
              : "vault: keys are generated on the host, immediately uploaded to OpenBao, and the host copy is shredded." },
          { note: "Reuses the same OpenBao AppRole/env - no extra credentials." },
        ];
      },
    },
    {
      id: "cyberark",
      group: "CyberArk",
      label: "Cert delivery (Conjur)",
      blurb: "Certinel pushes the issued cert (and optionally key) into CyberArk Conjur variables via the Conjur REST API.",
      fields: [
        { key: "url", label: "Conjur base URL", ph: "https://conjur.example.com" },
        { key: "account", label: "Conjur account", ph: "my-account" },
        { key: "login", label: "Service login (host id)", ph: "host/certinel" },
        { key: "variable", label: "Target variable id", ph: "apps/myapp/certificate" },
        { key: "shipkey", label: "Also store the private key (at <variable>/key)", ph: "", type: "checkbox" },
        { key: "cafile", label: "Conjur CA cert PEM path (optional)", ph: "" },
      ],
      gen(v) {
        const url = V(v, this.fields[0]), acct = V(v, this.fields[1]),
          login = V(v, this.fields[2]), variable = V(v, this.fields[3]),
          ship = !!v.shipkey, ca = (v.cafile || "").trim();
        const hostId = login.replace(/^host\//, "");
        const keyVar = ship ? `\n- !variable ${variable}/key` : "";
        const keyPerm = ship ? `\n    - !variable ${variable}/key` : "";
        return [
          { h: "1 - In CyberArk Conjur (load a policy as an admin)" },
          { p: "Create the service host, the cert variable(s), and grant the host update access. Save as certinel.yml and load it:" },
          { code:
`# certinel.yml  ->  conjur policy load -b root -f certinel.yml
- !host ${hostId}
- !variable ${variable}${keyVar}
- !permit
    role: !host ${hostId}
    privileges: [ read, update ]
    resources:
    - !variable ${variable}${keyPerm}` },
          { p: "Then mint the API key Certinel will authenticate with:" },
          { code: `conjur host rotate-api-key -i ${hostId}` },
          { h: "2 - In Certinel: /etc/certinel/certinel.env (secrets only here)" },
          { code:
`CSR_CYBERARK_API_KEY=<api key from step 1>${ca ? `\nCSR_CYBERARK_CA_CERT=${ca}` : ""}

# then:
sudo systemctl restart certinel-api` },
          { h: "3 - In Certinel: Administration -> Signing / CA (CyberArk connection)" },
          { code:
`CyberArk base URL : ${url}
Conjur account    : ${acct}
Service login     : ${login}` },
          { h: "4 - In Certinel: Templates -> (edit a template) -> Delivery" },
          { code:
`Delivery backend : CyberArk
Destination      : ${variable}${ship ? `\nKey handling     : ship  (key written to ${variable}/key)` : ""}` },
          { note: "CyberArk is supported for DELIVERY (storing the issued cert/key in Conjur). CyberArk as a signing CA is not available in this release." },
        ];
      },
    },
  ];

  // ---- one-time scoped styles -------------------------------------------
  function injectStyles() {
    if (document.getElementById("iwz-styles")) return;
    const s = document.createElement("style");
    s.id = "iwz-styles";
    s.textContent = `
.iwz-overlay{position:fixed;inset:0;background:var(--modal-overlay,rgba(0,0,0,.85));display:flex;
  align-items:flex-start;justify-content:center;z-index:9000;padding:4vh 16px;overflow:auto}
.iwz-modal{background:var(--modal-bg,#1a1f26);color:var(--fg,#e7eaee);width:min(880px,100%);
  border-radius:10px;box-shadow:0 12px 40px rgba(0,0,0,.5);border:1px solid var(--border,#2d343d)}
.iwz-head{display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:14px 18px;border-bottom:1px solid var(--border,#2d343d)}
.iwz-head h2{margin:0;font-size:1.15rem;color:var(--fg,#e7eaee)}
.iwz-x{background:none;border:none;font-size:1.5rem;line-height:1;cursor:pointer;color:var(--fg-muted,#8a93a0)}
.iwz-x:hover{color:var(--fg,#e7eaee)}
.iwz-body{padding:16px 18px}
.iwz-pills{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:6px}
.iwz-pill{padding:6px 11px;border:1px solid var(--border,#2d343d);border-radius:999px;
  background:transparent;color:var(--fg,#e7eaee);cursor:pointer;font-size:.86rem}
.iwz-pill:hover{border-color:var(--accent,#4a90c7)}
.iwz-pill.on{background:var(--accent,#4a90c7);color:var(--accent-fg,#0e1116);border-color:var(--accent,#4a90c7)}
.iwz-blurb{color:var(--fg-muted,#8a93a0);font-size:.9rem;margin:.5rem 0 1.1rem}
.iwz-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px 14px;margin-bottom:14px}
.iwz-f label{display:block;font-size:.8rem;color:var(--fg-muted,#8a93a0);margin-bottom:4px}
.iwz-f input[type=text]{width:100%;box-sizing:border-box;padding:8px 9px;border-radius:6px;
  border:1px solid var(--border-input,#3a424d);background:var(--bg-input,#11161c);color:var(--fg,#e7eaee);font-family:inherit;font-size:.9rem}
.iwz-f input[type=text]:focus{outline:none;border-color:var(--accent,#4a90c7)}
.iwz-f input::placeholder{color:var(--fg-muted,#8a93a0);opacity:.7}
.iwz-f.chk{display:flex;align-items:center;gap:8px;align-self:end}
.iwz-f.chk label{margin:0;color:var(--fg,#e7eaee)}
.iwz-out h4{margin:20px 0 6px;font-size:.95rem;color:var(--fg,#e7eaee);
  padding-top:12px;border-top:1px solid var(--border,#2d343d)}
.iwz-out h4:first-child{border-top:0;padding-top:0;margin-top:4px}
.iwz-out p{margin:.35rem 0 .55rem;font-size:.9rem;color:var(--fg,#e7eaee)}
.iwz-note{font-size:.85rem;color:var(--fg,#e7eaee);border-left:3px solid var(--accent,#4a90c7);
  padding:7px 11px;margin:.6rem 0;background:var(--code-bg,rgba(255,255,255,.06));border-radius:0 4px 4px 0}
.iwz-code{position:relative;margin:.45rem 0}
.iwz-code pre{margin:0;padding:11px 12px;background:var(--log-bg,#050709);color:var(--log-fg,#c4cad2);
  border:1px solid var(--border,#2d343d);border-radius:7px;
  overflow:auto;font:12.5px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.iwz-copy{position:absolute;top:7px;right:7px;font-size:.72rem;padding:4px 9px;border-radius:5px;
  border:1px solid var(--border-input,#3a424d);background:var(--bg-elevated,#1a1f26);color:var(--fg,#e7eaee);cursor:pointer}
.iwz-copy:hover{border-color:var(--accent,#4a90c7)}
.iwz-copy.ok{background:var(--ok,#5fdc7a);color:var(--accent-fg,#0e1116);border-color:var(--ok,#5fdc7a)}
.iwz-launch{font:inherit;font-size:.82rem;padding:6px 12px;border-radius:6px;cursor:pointer;
  border:1px solid var(--accent,#4a90c7);background:var(--accent,#4a90c7);color:var(--accent-fg,#0e1116);margin-left:8px}
.iwz-launch:hover{filter:brightness(1.08)}
`;
    document.head.appendChild(s);
  }

  // ---- render ------------------------------------------------------------
  let overlay, outEl, current = SPECS[0];
  const values = {}; // per-spec value cache: values[specId][fieldKey]

  function codeBlock(text) {
    const wrap = el("div", { class: "iwz-code" });
    const pre = el("pre"); pre.appendChild(el("code", { text }));
    const btn = el("button", { class: "iwz-copy", type: "button", text: "Copy" });
    btn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(text); }
      catch (_) { const r = document.createRange(); r.selectNodeContents(pre);
        const sel = getSelection(); sel.removeAllRanges(); sel.addRange(r);
        try { document.execCommand("copy"); } catch (e) {} sel.removeAllRanges(); }
      btn.textContent = "Copied"; btn.classList.add("ok");
      setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("ok"); }, 1400);
    });
    wrap.appendChild(pre); wrap.appendChild(btn);
    return wrap;
  }

  function regen() {
    const v = values[current.id] || (values[current.id] = {});
    outEl.innerHTML = "";
    current.gen(v).forEach((b) => {
      if (b.h) outEl.appendChild(el("h4", { text: b.h }));
      else if (b.p) outEl.appendChild(el("p", { text: b.p }));
      else if (b.note) outEl.appendChild(el("div", { class: "iwz-note", text: b.note }));
      else if (b.code) outEl.appendChild(codeBlock(b.code));
    });
  }

  function renderFields(body) {
    const v = values[current.id] || (values[current.id] = {});
    const grid = el("div", { class: "iwz-grid" });
    current.fields.forEach((f) => {
      const cell = el("div", { class: "iwz-f" + (f.type === "checkbox" ? " chk" : "") });
      if (f.type === "checkbox") {
        const cb = el("input", { type: "checkbox", id: "iwz-" + f.key });
        cb.checked = !!v[f.key];
        cb.addEventListener("change", () => { v[f.key] = cb.checked; regen(); });
        cell.appendChild(cb);
        cell.appendChild(el("label", { for: "iwz-" + f.key, text: f.label }));
      } else {
        cell.appendChild(el("label", { for: "iwz-" + f.key, text: f.label }));
        const inp = el("input", { type: "text", id: "iwz-" + f.key, placeholder: f.ph || "" });
        inp.value = v[f.key] || "";
        inp.addEventListener("input", () => { v[f.key] = inp.value; regen(); });
        cell.appendChild(inp);
      }
      grid.appendChild(cell);
    });
    body.appendChild(grid);
  }

  function build() {
    injectStyles();
    overlay = el("div", { class: "iwz-overlay", role: "dialog", "aria-modal": "true" });
    overlay.hidden = true;
    const modal = el("div", { class: "iwz-modal" });
    const head = el("div", { class: "iwz-head" }, [el("h2", { text: "Connection setup wizard" })]);
    const x = el("button", { class: "iwz-x", type: "button", "aria-label": "Close", text: "×" });
    x.addEventListener("click", closeWiz); head.appendChild(x);
    const body = el("div", { class: "iwz-body" });

    const pills = el("div", { class: "iwz-pills" });
    SPECS.forEach((sp) => {
      const p = el("button", { class: "iwz-pill", type: "button", text: sp.group + " · " + sp.label });
      p.addEventListener("click", () => { current = sp; draw(body, pills); });
      pills.appendChild(p);
    });

    modal.appendChild(head); modal.appendChild(body);
    overlay.appendChild(modal);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) closeWiz(); });
    document.addEventListener("keydown", (e) => { if (!overlay.hidden && e.key === "Escape") closeWiz(); });
    document.body.appendChild(overlay);
    draw(body, pills);
  }

  function draw(body, pills) {
    body.innerHTML = "";
    pills.querySelectorAll(".iwz-pill").forEach((p, i) =>
      p.classList.toggle("on", SPECS[i].id === current.id));
    body.appendChild(pills);
    body.appendChild(el("div", { class: "iwz-blurb", text: current.blurb }));
    renderFields(body);
    outEl = el("div", { class: "iwz-out" });
    body.appendChild(outEl);
    regen();
  }

  function openWiz(specId) {
    if (!overlay) build();
    if (specId) { const s = SPECS.find((x) => x.id === specId); if (s) current = s; }
    const body = overlay.querySelector(".iwz-body");
    const pills = body.querySelector(".iwz-pills") || overlay.querySelector(".iwz-pills");
    draw(body, pills);
    overlay.hidden = false;
  }
  function closeWiz() { if (overlay) overlay.hidden = true; }

  // ---- launcher injection (admin panels; no markup edits) ----------------
  function addLauncher(panelId, specId) {
    const panel = document.querySelector(`#admin-panels > [data-panel="${panelId}"]`);
    if (!panel) return;
    const head = panel.querySelector("h2");
    if (!head || head.querySelector(".iwz-launch")) return;
    const b = el("button", { class: "iwz-launch", type: "button", text: "🔌 Connection setup wizard" });
    b.addEventListener("click", (e) => { e.preventDefault(); e.stopPropagation(); openWiz(specId); });
    head.appendChild(b);
  }
  function placeLaunchers() {
    addLauncher("signingca", "openbao_sign");
    addLauncher("templates", "openbao_deliver");
  }
  // admin panels may render after auth; try now + observe.
  placeLaunchers();
  const ob = new MutationObserver(placeLaunchers);
  const host = document.getElementById("admin-panels") || document.body;
  ob.observe(host, { childList: true, subtree: true });

  // expose for deep-linking
  window.openConnectionWizard = openWiz;
})();
