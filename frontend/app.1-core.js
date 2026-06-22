// Certinel frontend - Linux-only flow with jobs DB
const API = "/csr/api";
const CSRF = { "X-Requested-With": "certinel", "Content-Type": "application/json" };
const PAGE_SIZE = 50;

// ===== Login banner (configurable; a modal opened from a link on the gate) =====
const banner = document.getElementById("consent-banner");
document.getElementById("consent-close").addEventListener("click", () => {
  banner.hidden = true;
});
document.getElementById("login-show-banner").addEventListener("click", () => {
  banner.hidden = false;
});
document.getElementById("login-show-banner-2")?.addEventListener("click", () => {
  banner.hidden = false;
});

// Populate the banner modal + the agreement link text from /auth/info's banner
// object ({title, link, paragraphs[], items[]}). Built with textContent so any
// custom admin text is inert (no HTML injection).
function renderBanner(b) {
  const title = document.getElementById("consent-title");
  const body = document.getElementById("consent-body");
  if (!b) { body.replaceChildren(); return; }
  title.textContent = b.title || "Notice and Consent";
  const frag = document.createDocumentFragment();
  (b.paragraphs || []).forEach(p => {
    const el = document.createElement("p"); el.textContent = p; frag.appendChild(el);
  });
  if ((b.items || []).length) {
    const ul = document.createElement("ul");
    b.items.forEach(it => {
      const li = document.createElement("li"); li.textContent = it; ul.appendChild(li);
    });
    frag.appendChild(ul);
  }
  body.replaceChildren(frag);
  const link = b.link || "User Access Agreement";
  ["login-show-banner", "login-show-banner-2"].forEach(id => {
    const el = document.getElementById(id); if (el) el.textContent = link;
  });
}

// ===== Login gate =====
// The app always shows a login gate first. What it offers depends on the
// server's auth mode (GET /api/auth/info): CAC "Continue" when mTLS is on,
// username/password when local auth is on (both can show together - CAC stays
// primary with password as a fallback). On success we reveal the app + run
// init(). A logout returns here.
let authInfo = null;

function showLoginView() {
  document.getElementById("login-view").hidden = false;
  document.querySelector("header").style.display = "none";
  document.querySelector("main").style.display = "none";
}
function hideLoginView() {
  document.getElementById("login-view").hidden = true;
  document.querySelector("header").style.display = "";
  document.querySelector("main").style.display = "";
}

async function startApp() {
  // Mark the gate as passed for this browser session, so subsequent refreshes
  // skip straight in instead of re-showing the gate. Cleared on sign-out and
  // when the browser session ends (sessionStorage).
  sessionStorage.setItem("csr-gate-passed", "1");
  hideLoginView();
  await init();
}

async function bootstrapAuth() {
  // Ask the server which single auth mode this box uses. A box is EITHER
  // mTLS (CAC only) OR local (username/password only) - set at install time.
  // No mixing, which avoids the CAC-vs-password conflict entirely.
  const r = await jsonReq("/auth/info");
  authInfo = r.ok ? r.body : { auth_mode: "mtls", local_enabled: false,
                               registration_open: false };
  const mtlsOnly = authInfo.auth_mode === "mtls";

  // Gate is passed explicitly once per browser session; afterward a refresh
  // skips straight in (so reloads don't kick you out).
  const gatePassed = sessionStorage.getItem("csr-gate-passed") === "1";
  if (gatePassed) {
    const me = await jsonReq("/me");
    if (me.ok && me.body && me.body.dn && !String(me.body.dn).startsWith("ip:")) {
      return startApp();
    }
  }

  if (mtlsOnly) {
    // CAC-only box: show ONLY the CAC continue button + agreement. No password
    // fields, no Smartcard checkbox (there's nothing to choose).
    document.getElementById("login-local").hidden = true;
    document.getElementById("login-local-btn").hidden = true;
    document.getElementById("login-cac-row").hidden = true;
    document.getElementById("login-cac").hidden = false;
    document.getElementById("login-register-link-wrap").hidden = true;
    document.getElementById("login-sub").textContent =
      "Authenticate with your CAC to continue";
  } else {
    // Password-only box: show ONLY username/password (+ registration if open).
    // No CAC anywhere.
    document.getElementById("login-local").hidden = false;
    document.getElementById("login-local-btn").hidden = false;
    document.getElementById("login-cac-row").hidden = true;
    document.getElementById("login-cac").hidden = true;
    document.getElementById("login-register-link-wrap").hidden = !authInfo.registration_open;
    document.getElementById("login-sub").textContent =
      "Sign in with your username and password";
  }

  // Login banner + agreement gate. Configurable per install; when the banner
  // is "none" there is nothing to agree to, so the gate is skipped entirely.
  _agreementRequired = !!authInfo.require_agreement;
  renderBanner(authInfo.banner || null);
  document.getElementById("login-agree-row").hidden = !_agreementRequired;
  if (!_agreementRequired) banner.hidden = true;

  _agreeInteracted = false;  // reset so the warning is silent on (re)render
  _applyAgreementGate();
  showLoginView();
}

// Agreement checkbox gates the action buttons. The warning box stays hidden
// on load (silent) and appears only AFTER the user actively unchecks the box.
let _agreeInteracted = false;
let _agreementRequired = true;   // set from /auth/info (false when banner=none)
function _applyAgreementGate() {
  // No banner configured -> nothing to agree to: enable the buttons, no warning.
  if (!_agreementRequired) {
    ["login-submit", "login-cac-btn"].forEach(id => {
      const b = document.getElementById(id); if (b) b.disabled = false;
    });
    document.getElementById("login-agree-warn").hidden = true;
    return;
  }
  const agreed = document.getElementById("login-agree-check").checked;
  ["login-submit", "login-cac-btn"].forEach(id => {
    const b = document.getElementById(id);
    if (b) b.disabled = !agreed;
  });
  // Silent until the user has actually toggled the box at least once and
  // left it unchecked. Never shown on initial load.
  document.getElementById("login-agree-warn").hidden = !( _agreeInteracted && !agreed );
}
document.getElementById("login-agree-check").addEventListener("change", () => {
  _agreeInteracted = true;
  _applyAgreementGate();
});

// Smartcard checkbox switches between password (default) and CAC. Password
// fields are the default; checking "Use Smartcard" reveals the CAC button and
// hides the password fields. Unchecking returns to password.
function _applyCacToggle() {
  const mtlsOn = authInfo && authInfo.auth_mode === "mtls";
  const useCac = mtlsOn && document.getElementById("login-cac-check")?.checked;
  // CAC button visible only when the box is checked
  document.getElementById("login-cac").hidden = !useCac;
  // password fields + button hidden when using CAC, shown otherwise
  document.getElementById("login-local").hidden = !!useCac;
  document.getElementById("login-local-btn").hidden = !!useCac;
}
document.getElementById("login-cac-check")?.addEventListener("change", _applyCacToggle);

// CAC: the cert is presented at TLS handshake; "Continue" just proceeds.
document.getElementById("login-cac-btn").addEventListener("click", async () => {
  const status = document.getElementById("login-status");
  if (_agreementRequired && !document.getElementById("login-agree-check").checked) {
    _agreeInteracted = true; _applyAgreementGate();
    setStatus(status, "You must agree to the User Access Agreement first.", "err");
    return;
  }
  setStatus(status, "Verifying CAC…");
  const me = await jsonReq("/me");
  if (me.ok && me.body && me.body.dn && !String(me.body.dn).startsWith("ip:")) {
    startApp();
  } else {
    setStatus(status, "No valid CAC detected. Ensure your card is inserted "
                    + "and you selected your certificate.", "err");
  }
});

// Username / password login.
document.getElementById("login-submit").addEventListener("click", doLogin);
document.getElementById("login-password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") doLogin();
});
async function doLogin() {
  const status = document.getElementById("login-status");
  if (_agreementRequired && !document.getElementById("login-agree-check").checked) {
    _agreeInteracted = true; _applyAgreementGate();
    setStatus(status, "You must agree to the User Access Agreement first.", "err");
    return;
  }
  const username = document.getElementById("login-username").value.trim();
  const password = document.getElementById("login-password").value;
  if (!username || !password) {
    setStatus(status, "Enter your username and password.", "err");
    return;
  }
  setStatus(status, "Signing in…");
  const r = await jsonReq("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  if (r.ok) {
    startApp();
  } else {
    const msg = (r.body && r.body.error) || "Sign-in failed";
    setStatus(status, msg, "err");
  }
}

// Toggle register / login.
document.getElementById("login-show-register")?.addEventListener("click", () => {
  document.getElementById("login-local").hidden = true;
  document.getElementById("login-local-btn").hidden = true;
  document.getElementById("login-cac").hidden = true;
  document.getElementById("login-cac-row").hidden = true;
  document.getElementById("login-agree-row").hidden = true;
  document.getElementById("login-agree-warn").hidden = true;
  document.getElementById("register-block").hidden = false;
  setStatus(document.getElementById("login-status"), "");
});
document.getElementById("register-show-login")?.addEventListener("click", () => {
  document.getElementById("register-block").hidden = true;
  // Don't force the agreement visible - bootstrapAuth() re-renders the login
  // side and shows it only if a banner is configured (else it stays hidden).
  bootstrapAuth();
});

// Live password-policy hints during registration.
document.getElementById("reg-password")?.addEventListener("input", (e) => {
  const pw = e.target.value;
  const rules = {
    len: pw.length >= 15,
    upper: /[A-Z]/.test(pw),
    lower: /[a-z]/.test(pw),
    digit: /[0-9]/.test(pw),
    special: /[^A-Za-z0-9]/.test(pw),
  };
  document.querySelectorAll("#reg-pw-hints li").forEach(li => {
    li.classList.toggle("met", !!rules[li.dataset.rule]);
  });
});

document.getElementById("register-submit")?.addEventListener("click", async () => {
  const status = document.getElementById("login-status");
  const first = document.getElementById("reg-first").value.trim();
  const last = document.getElementById("reg-last").value.trim();
  const email = document.getElementById("reg-email").value.trim();
  const password = document.getElementById("reg-password").value;
  if (!first || !last || !email || !password) {
    setStatus(status, "Fill in every field.", "err");
    return;
  }
  setStatus(status, "Creating account…");
  const r = await jsonReq("/auth/register", {
    method: "POST",
    body: JSON.stringify({ first_name: first, last_name: last,
                           email, password }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Registration failed", "err");
    return;
  }
  if (r.body.status === "pending") {
    setStatus(status, `Account created as "${r.body.username}". It is awaiting `
                    + "administrator approval - you'll be able to sign in once "
                    + "approved.", "ok");
    document.getElementById("register-block").hidden = true;
  } else {
    // active + logged in (cookie set) - show the assigned username, then enter
    alert(`Your username is "${r.body.username}". Please remember it for `
        + "future sign-ins.");
    startApp();
  }
});

// Logout (local sessions). Hidden for CAC since the cert is the identity.
document.getElementById("nav-logout")?.addEventListener("click", async () => {
  sessionStorage.removeItem("csr-gate-passed");  // force the gate on next load
  try {
    await jsonReq("/auth/logout", { method: "POST" });
  } catch (e) { /* ignore - we reload regardless */ }
  // After clearing the local session, re-probe. If a CAC cert is still being
  // presented, the server will re-authenticate us on reload (you can't "log
  // out" of a presented certificate without removing the card / closing the
  // browser). Tell the user that rather than silently bouncing back in.
  const me = await jsonReq("/me");
  if (me.ok && me.body && me.body.via === "cac") {
    alert("Your CAC is still presented, so you remain signed in via "
        + "certificate. To fully sign out, remove your card or close the "
        + "browser.");
    return;
  }
  location.reload();  // password session cleared -> gate shows
});

// ===== Theme =====
const themeBtn = document.getElementById("theme-toggle");
const themeIcon = document.getElementById("theme-toggle-icon");
const themeLabel = document.getElementById("theme-toggle-label");
function applyTheme(theme) {
  if (theme === "light") {
    document.documentElement.setAttribute("data-theme", "light");
    themeIcon.textContent = "☾";
    themeLabel.textContent = "Dark";
  } else {
    document.documentElement.removeAttribute("data-theme");
    themeIcon.textContent = "☀";
    themeLabel.textContent = "Light";
  }
}
applyTheme(localStorage.getItem("csr-theme") || "dark");
themeBtn.addEventListener("click", () => {
  const next = document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light";
  localStorage.setItem("csr-theme", next);
  applyTheme(next);
});

// ===== Helpers =====
async function jsonReq(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (opts.method && opts.method !== "GET") Object.assign(headers, CSRF);
  const r = await fetch(API + path, { credentials: "same-origin", ...opts, headers });
  let body = null;
  try { body = await r.json(); } catch (_) {}
  return { ok: r.ok, status: r.status, body };
}

function setStatus(el, msg, kind = "") {
  if (!el) return;
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

function fmtBytes(n) {
  if (n < 1024) return n + " B";
  if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
  return (n / 1024 / 1024).toFixed(2) + " MB";
}

function fmtTime(epoch) {
  if (!epoch) return "—";
  return new Date(epoch * 1000).toLocaleString();
}

function fmtRelTime(epoch) {
  if (!epoch) return "—";
  const seconds = Math.floor(Date.now() / 1000 - epoch);
  if (seconds < 60) return seconds + "s ago";
  if (seconds < 3600) return Math.floor(seconds / 60) + "m ago";
  if (seconds < 86400) return Math.floor(seconds / 3600) + "h ago";
  return Math.floor(seconds / 86400) + "d ago";
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  })[c]);
}

function shortDN(dn) {
  const m = String(dn).match(/CN=([^,]+)/);
  return m ? m[1] : dn;
}

function statusPill(status) {
  const map = { pending: "pill-pending", issued: "pill-ok",
                failed: "pill-err", cancelled: "pill-mute",
                expired: "pill-warn" };
  return `<span class="pill ${map[status] || ''}">${status}</span>`;
}

function sourcePill(source) {
  const map = { rhel: "pill-blue", external: "pill-purple" };
  const label = source === "rhel" ? "Linux" : "External";
  return `<span class="pill ${map[source] || ''}">${label}</span>`;
}

const CERT_TYPE_LABELS = {
  "web": "Web",
  "server-client": "Srv+Cli",   // legacy rows in the DB
  "client": "Client",
  "email": "Email",
  "codesign": "CodeSign",
  "ipsec": "IPSec",
  "ocsp": "OCSP",
  "timestamp": "TSA",
  "8021x": "802.1X",
};

function certTypePill(t) {
  if (!t) return '<span class="status">&mdash;</span>';
  return t.split(",").map(x => {
    const label = CERT_TYPE_LABELS[x] || x;
    return `<span class="pill" style="background:#0ea5e9;color:white" title="${escapeHtml(x)}">${escapeHtml(label)}</span>`;
  }).join(" ");
}

// ===== Cert type checkbox groups (compatibility greying) =====
const CERT_TYPE_EXCLUSIVE = ["codesign", "ocsp", "timestamp"];

function applyCertTypeRules(container) {
  const cbs = Array.from(container.querySelectorAll(".cert-type-cb"));
  const checked = cbs.filter(c => c.checked).map(c => c.value);
  const anyExclusive = checked.some(v => CERT_TYPE_EXCLUSIVE.includes(v));
  const anyCombinable = checked.some(v => !CERT_TYPE_EXCLUSIVE.includes(v));

  cbs.forEach(cb => {
    let disabled = false;
    if (!cb.checked) {
      if (anyExclusive) {
        // An exclusive type is selected: everything else greys out
        disabled = true;
      } else if (CERT_TYPE_EXCLUSIVE.includes(cb.value) && anyCombinable) {
        // Combinables selected: exclusives grey out
        disabled = true;
      } else if (cb.value === "client" && checked.includes("8021x")) {
        // 802.1X already implies clientAuth
        disabled = true;
      } else if (cb.value === "8021x" && checked.includes("client")) {
        disabled = true;
      }
    }
    cb.disabled = disabled;
    const lbl = cb.closest("label");
    if (lbl) lbl.classList.toggle("disabled", disabled);
  });
}

function setupCertTypeGroup(id) {
  const c = document.getElementById(id);
  if (!c) return;
  c.addEventListener("change", () => applyCertTypeRules(c));
  applyCertTypeRules(c);
}

function getCertTypes(id) {
  return Array.from(document.querySelectorAll(`#${id} .cert-type-cb:checked`))
    .map(cb => cb.value);
}

function resetCertTypes(id, defaults) {
  document.querySelectorAll(`#${id} .cert-type-cb`).forEach(cb => {
    cb.checked = defaults.includes(cb.value);
  });
  const c = document.getElementById(id);
  if (c) applyCertTypeRules(c);
}

setupCertTypeGroup("external-cert-types");
setupCertTypeGroup("admin-template-cert-types");
setupCertTypeGroup("user-template-cert-types");


function debounce(fn, ms) {
  let t;
  return (...args) => { clearTimeout(t); t = setTimeout(() => fn(...args), ms); };
}

function expiryCountdown(epoch) {
  const days = Math.floor((epoch * 1000 - Date.now()) / 86400000);
  if (days < 0) return `expired ${-days} day${-days === 1 ? "" : "s"} ago`;
  if (days === 0) return "expires today";
  return `in ${days} day${days === 1 ? "" : "s"}`;
}

// ===== Side-nav panel switching (admin + dashboard) =====
function _switchPanel(navId, panelsId, name) {
  document.querySelectorAll(`#${panelsId} > [data-panel]`).forEach(s => {
    s.hidden = (s.dataset.panel !== name);
  });
  document.querySelectorAll(`#${navId} button`).forEach(b => {
    b.classList.toggle("active", b.dataset.panel === name);
  });
}
function showAdminPanel(name) { _switchPanel("admin-nav", "admin-panels", name); }
function showMainPanel(name)  { _switchPanel("main-nav", "main-panels", name); }

// Nav clicks set the hash; applyRoute() does the actual switching, so each
// section has its own URL and a refresh restores it.
document.querySelectorAll("#admin-nav button").forEach(b => {
  b.addEventListener("click", () => { location.hash = "#admin/" + b.dataset.panel; });
});
document.querySelectorAll("#main-nav button").forEach(b => {
  b.addEventListener("click", () => { location.hash = "#" + b.dataset.panel; });
});
showAdminPanel("overview");
showMainPanel("create");

async function renewJob(id, host, btn) {
  if (!confirm(`Renew the certificate for ${host}?\n\nA new key and CSR are generated ` +
               "with the same names, types, and key algorithm, and a new pending job " +
               "is created for signing.")) return;
  if (btn) { btn.disabled = true; btn.textContent = "Renewing…"; }
  const r = await jsonReq(`/jobs/${id}/renew`, { method: "POST", body: "{}" });
  if (!r.ok) {
    alert("Renew failed: " + ((r.body && r.body.error) || "unknown"));
    if (btn) { btn.disabled = false; btn.textContent = "Renew"; }
    return;
  }
  await refreshJobs();
  await refreshKeys();
  openDetailModal(r.body.new_job_id);
}

// ===== Signing queue =====
async function refreshSigningQueue() {
  const tbody = document.getElementById("signing-tbody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="5" class="status">Loading…</td></tr>';
  const r = await jsonReq("/jobs?status=pending&limit=500&sort=asc");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="5" class="status err">Failed to load</td></tr>';
    return;
  }
  const jobs = (r.body.jobs || []).slice().sort((a, b) => a.created_at - b.created_at);
  if (!jobs.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="status">Nothing awaiting signature. 🎉</td></tr>';
    return;
  }
  tbody.innerHTML = jobs.map(j => `
    <tr>
      <td title="${fmtTime(j.created_at)}">${fmtRelTime(j.created_at)}</td>
      <td><code>${escapeHtml(j.target_host)}</code></td>
      <td>${certTypePill(j.cert_type)}</td>
      <td title="${escapeHtml(j.requester_dn)}">${escapeHtml(j.requester_display || shortDN(j.requester_dn))}</td>
      <td><button class="link-btn sq-detail" data-id="${j.id}">Details / Upload</button></td>
    </tr>`).join("");
  tbody.querySelectorAll(".sq-detail").forEach(b => {
    b.addEventListener("click", () => openDetailModal(b.dataset.id));
  });
}

document.getElementById("signing-refresh-btn")?.addEventListener("click", refreshSigningQueue);
document.getElementById("signing-zip-btn")?.addEventListener("click", () => {
  window.location = API + "/signing-queue/csrs.zip";
});
document.querySelector('#main-nav button[data-panel="signing"]')
  ?.addEventListener("click", refreshSigningQueue);

// ===== Fleet certificates =====
let fleetExpiringActive = false;

async function refreshFleetCerts() {
  const tbody = document.getElementById("fleet-tbody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" class="status">Loading…</td></tr>';
  const params = new URLSearchParams({ limit: 500 });
  const q = document.getElementById("fleet-search").value.trim();
  if (q) params.set("q", q);
  if (fleetExpiringActive) params.set("expiring_within", "60");
  if (document.getElementById("fleet-dedupe-cb")?.checked) params.set("dedupe", "1");
  const r = await jsonReq("/fleet-certs?" + params.toString());
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="7" class="status err">Failed to load</td></tr>';
    return;
  }
  const certs = r.body.certs || [];
  setStatus(document.getElementById("fleet-status"),
    `${r.body.total} certificate(s) tracked`, "");
  if (!certs.length) {
    tbody.innerHTML = '<tr><td colspan="7" class="status">No fleet certificates yet. Run the fleet-cert-scan playbook to populate this view.</td></tr>';
    return;
  }
  tbody.innerHTML = certs.map(c => {
    const expPill = !c.expires_at ? '<span class="status">—</span>'
      : c.expired ? '<span class="pill pill-warn">expired</span>'
      : `<span title="${fmtTime(c.expires_at)}">${expiryCountdown(c.expires_at)}</span>`;
    return `
    <tr>
      <td><code>${escapeHtml(c.host.split(".")[0])}</code>${
        c.location_count > 1
          ? ` <span class="pill pill-blue" title="${escapeHtml(c.locations || "")}">+${c.location_count - 1} more</span>`
          : ""}</td>
      <td title="${escapeHtml(c.path)}">${escapeHtml(c.cn || "(no CN)")}</td>
      <td>${certTypePill(c.cert_types)}</td>
      <td class="status">${escapeHtml(c.issuer || "—")}</td>
      <td>${expPill}</td>
      <td title="${fmtTime(c.last_seen)}">${fmtRelTime(c.last_seen)}</td>
      <td>
        <button class="link-btn fleet-renew" data-cn="${escapeHtml(c.cn || "")}"
                data-sans="${escapeHtml((c.sans || []).join(", "))}"
                data-types="${escapeHtml(c.cert_types || "")}">Renew here</button>
        ${currentUser?.is_admin
          ? `<button class="link-btn fleet-del" data-id="${c.id}" style="color:var(--danger)">Remove</button>`
          : ""}
      </td>
    </tr>`;
  }).join("");

  tbody.querySelectorAll(".fleet-renew").forEach(b => {
    b.addEventListener("click", () => {
      // Pre-fill the Create panel with this cert's identity + usages
      showMainPanel("create");
      const det = document.getElementById("certlist-section");
      if (det) det.open = true;
      requestRows.innerHTML = "";
      const cn = b.dataset.cn;
      const sans = (b.dataset.sans || "").split(",").map(s => s.trim())
        .filter(s => s && s !== cn).join(", ");
      addRequestRow(cn, sans);
      const typesCsv = (b.dataset.types || "web");
      setGenTypesCustom(`From fleet cert: ${b.dataset.cn || "imported"} (${typesCsv})`, typesCsv);
      setStatus(saveStatus, `Pre-filled from fleet cert — review, then Generate.`, "ok");
      det?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
  tbody.querySelectorAll(".fleet-del").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm("Remove this record from fleet tracking? (The cert on the host is untouched; the next scan re-adds it unless the file is gone.)")) return;
      const r2 = await jsonReq("/fleet-certs/" + b.dataset.id, { method: "DELETE" });
      if (r2.ok) refreshFleetCerts();
    });
  });
}

document.getElementById("fleet-refresh-btn")?.addEventListener("click", refreshFleetCerts);
document.getElementById("fleet-search")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") refreshFleetCerts();
});
document.getElementById("fleet-dedupe-cb")?.addEventListener("change", refreshFleetCerts);
document.getElementById("fleet-expiring-btn")?.addEventListener("click", (e) => {
  fleetExpiringActive = !fleetExpiringActive;
  e.target.style.borderColor = fleetExpiringActive ? "var(--warning)" : "";
  e.target.style.color = fleetExpiringActive ? "var(--warning)" : "";
  refreshFleetCerts();
});
document.querySelector('#main-nav button[data-panel="fleet"]')
  ?.addEventListener("click", refreshFleetCerts);

// ===== My groups =====
async function refreshMyGroups() {
  const list = document.getElementById("mygroups-list");
  if (!list) return;
  list.innerHTML = '<p class="status">Loading…</p>';
  const r = await jsonReq("/my-groups");
  if (!r.ok) { list.innerHTML = '<p class="status err">Failed to load</p>'; return; }
  const groups = r.body.groups || [];
  if (!groups.length) {
    list.innerHTML = '<p class="status">You are not a member of any group. Ask an admin (or a group owner) to add you.</p>';
    return;
  }
  list.innerHTML = groups.map(grp => `
    <div class="card" style="margin-bottom:12px; padding:12px">
      <div class="row" style="justify-content:space-between">
        <div>
          <b>${escapeHtml(grp.name)}</b>
          ${grp.role === "owner"
            ? '<span class="pill" style="background:#10b981;color:white">owner</span>'
            : '<span class="pill" style="background:#6b7280;color:white">member</span>'}
          ${grp.notify_on_new ? '<span class="pill pill-warn">signers</span>' : ""}
          <span class="status">· ${grp.member_count} member(s)${grp.email ? " · " + escapeHtml(grp.email) : ""}</span>
        </div>
      </div>
      ${grp.description ? `<p class="hint" style="margin:4px 0">${escapeHtml(grp.description)}</p>` : ""}
      ${grp.role === "owner" ? `
        <table style="margin-top:8px">
          <thead><tr><th>Member</th><th>Email</th><th>Role</th><th></th></tr></thead>
          <tbody>
            ${(grp.members || []).map(m => `
              <tr>
                <td title="${escapeHtml(m.dn)}"><code>${escapeHtml(m.cn || shortDN(m.dn))}</code></td>
                <td>${m.email ? escapeHtml(m.email) : "<em>—</em>"}</td>
                <td>${m.role === "owner" ? '<span class="pill" style="background:#10b981;color:white">owner</span>' : "member"}</td>
                <td>
                  ${m.role !== "owner"
                    ? `<button class="link-btn mygroup-promote" data-gid="${grp.id}" data-dn="${escapeHtml(m.dn)}">Make owner</button>
                       &nbsp;|&nbsp;
                       <button class="link-btn mygroup-remove" data-gid="${grp.id}" data-dn="${escapeHtml(m.dn)}" style="color:var(--danger)">Remove</button>`
                    : `<button class="link-btn mygroup-demote" data-gid="${grp.id}" data-dn="${escapeHtml(m.dn)}">Make member</button>`}
                </td>
              </tr>`).join("")}
          </tbody>
        </table>
        <div class="row" style="margin-top:8px; gap:6px">
          <input type="email" class="form-input mygroup-add-email" data-gid="${grp.id}"
                 placeholder="member's dashboard email" style="width:260px">
          <button class="mygroup-add-btn" data-gid="${grp.id}" type="button">Add member</button>
          <span class="status mygroup-status" data-gid="${grp.id}"></span>
        </div>` : ""}
      <div class="row" style="margin-top:8px">
        <button class="link-btn mygroup-leave" data-gid="${grp.id}" data-name="${escapeHtml(grp.name)}"
                data-isowner="${grp.role === "owner" ? 1 : 0}" style="color:var(--danger)">Leave group</button>
      </div>
    </div>`).join("");

  list.querySelectorAll(".mygroup-leave").forEach(b => {
    b.addEventListener("click", async () => {
      const name = b.dataset.name;
      if (!confirm(`Leave the group "${name}"? You'll lose access to its shared `
                 + `templates and jobs.`)) return;
      const r2 = await jsonReq(`/groups/${b.dataset.gid}/members`, {
        method: "DELETE", body: JSON.stringify({ dn: currentUser.dn }),
      });
      if (r2.ok) { refreshMyGroups(); return; }
      // Most likely failure: you're the only owner and must hand off first.
      alert("Couldn't leave: " + ((r2.body && r2.body.error) || "unknown"));
    });
  });

  list.querySelectorAll(".mygroup-add-btn").forEach(b => {
    b.addEventListener("click", async () => {
      const gid = b.dataset.gid;
      const input = list.querySelector(`.mygroup-add-email[data-gid="${gid}"]`);
      const status = list.querySelector(`.mygroup-status[data-gid="${gid}"]`);
      const email = input.value.trim();
      if (!email) { setStatus(status, "Email required", "err"); return; }
      const r2 = await jsonReq(`/groups/${gid}/members`, {
        method: "POST", body: JSON.stringify({ email }),
      });
      if (!r2.ok) { setStatus(status, (r2.body && r2.body.error) || "Add failed", "err"); return; }
      refreshMyGroups();
    });
  });
  list.querySelectorAll(".mygroup-remove").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm("Remove this member from the group?")) return;
      const r2 = await jsonReq(`/groups/${b.dataset.gid}/members`, {
        method: "DELETE", body: JSON.stringify({ dn: b.dataset.dn }),
      });
      if (r2.ok) refreshMyGroups();
      else alert("Remove failed: " + ((r2.body && r2.body.error) || "unknown"));
    });
  });
  const setRole = async (gid, dn, role) => {
    const r2 = await jsonReq(`/groups/${gid}/members/role`, {
      method: "PUT", body: JSON.stringify({ dn, role }),
    });
    if (r2.ok) refreshMyGroups();
    else alert("Role change failed: " + ((r2.body && r2.body.error) || "unknown"));
  };
  list.querySelectorAll(".mygroup-promote").forEach(b => {
    b.addEventListener("click", () => {
      if (!confirm("Make this member an owner? They'll be able to manage the group.")) return;
      setRole(b.dataset.gid, b.dataset.dn, "owner");
    });
  });
  list.querySelectorAll(".mygroup-demote").forEach(b => {
    b.addEventListener("click", () => {
      if (!confirm("Demote this owner to a regular member?")) return;
      setRole(b.dataset.gid, b.dataset.dn, "member");
    });
  });
}

document.getElementById("mygroups-refresh-btn")?.addEventListener("click", refreshMyGroups);
document.querySelector('#main-nav button[data-panel="mygroups"]')
  ?.addEventListener("click", refreshMyGroups);

// ===== Bulk cancel =====
function selectedJobIds() {
  return Array.from(document.querySelectorAll(".job-select-cb:checked"))
    .map(cb => cb.value);
}

function updateBulkCancelState() {
  const btn = document.getElementById("bulk-cancel-btn");
  if (!btn) return;
  const n = selectedJobIds().length;
  btn.disabled = (n === 0);
  btn.textContent = n > 0 ? `Cancel selected (${n})` : "Cancel selected";
}

document.getElementById("jobs-select-all")?.addEventListener("change", (e) => {
  document.querySelectorAll(".job-select-cb").forEach(cb => {
    cb.checked = e.target.checked;
  });
  updateBulkCancelState();
});

document.getElementById("bulk-cancel-btn")?.addEventListener("click", async () => {
  const ids = selectedJobIds();
  if (!ids.length) return;
  const status = document.getElementById("bulk-cancel-status");
  const reason = prompt(
    `Cancel ${ids.length} pending request${ids.length > 1 ? "s" : ""}?\n\n` +
    `Optional reason (applied to all):`, ""
  );
  if (reason === null) return;  // user hit Cancel in the prompt
  setStatus(status, "Cancelling…");
  const r = await jsonReq("/jobs/bulk-cancel", {
    method: "POST",
    body: JSON.stringify({ job_ids: ids, reason: reason.trim() }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Bulk cancel failed", "err");
    return;
  }
  const c = (r.body.cancelled || []).length;
  const s = (r.body.skipped || []).length;
  const d = (r.body.denied || []).length;
  let msg = `Cancelled ${c}`;
  if (s) msg += `, skipped ${s} (no longer pending)`;
  if (d) msg += `, denied ${d} (not your requests)`;
  setStatus(status, msg, d ? "err" : "ok");
  refreshJobs();
});

// ===== Certlist editor (form + raw modes) =====
const saveStatus = document.getElementById("save-status");

// ===== Multi-request rows editor =====
const requestRows = document.getElementById("request-rows");
// Charset matches the server-side CERTLIST_LINE_RE (sans comma, which is
// the field separator): letters, digits, . _ @ + : -
const ENTRY_RE = /^[A-Za-z0-9._@+:-]+$/;

// Make the request form reflect the admin-configured CSR subject domain instead
// of a hardcoded "example.com": fills the help-text spans + (re)sets input
// placeholders. Called once /api/me resolves. Falls back to example.com when no
// domain is configured yet.
function applyConfiguredDomain(suffix) {
  const dom = (suffix || "").trim().replace(/^\.+/, "");
  window.CSR_DOMAIN = dom;                       // "" until an admin configures it
  const shown = dom || "example.com";
  const dEl = document.getElementById("hint-domain");
  const eEl = document.getElementById("hint-example");
  if (dEl) dEl.textContent = "." + shown;
  if (eEl) eEl.textContent = "myserver." + shown;
  document.querySelectorAll(".req-cn").forEach(i => {
    i.placeholder = "myserver  or  myserver." + shown;
  });
  document.querySelectorAll(".req-sans").forEach(i => {
    i.placeholder = "alt." + shown + ", 10.1.2.3";
  });
}

function addRequestRow(cn = "", sans = "") {
  const row = document.createElement("div");
  row.className = "request-row";

  const _dom = (window.CSR_DOMAIN || "example.com");
  const cnInput = document.createElement("input");
  cnInput.type = "text";
  cnInput.className = "form-input req-cn";
  cnInput.placeholder = "myserver  or  myserver." + _dom;
  cnInput.autocomplete = "off";
  cnInput.value = cn;

  const sansInput = document.createElement("input");
  sansInput.type = "text";
  sansInput.className = "form-input req-sans";
  sansInput.placeholder = "alt." + _dom + ", 10.1.2.3";
  sansInput.autocomplete = "off";
  sansInput.value = sans;

  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "req-remove";
  rm.textContent = "×";
  rm.title = "Remove this request";
  rm.addEventListener("click", () => {
    row.remove();
    if (!requestRows.querySelector(".request-row")) addRequestRow();
  });

  row.appendChild(cnInput);
  row.appendChild(sansInput);
  row.appendChild(rm);
  requestRows.appendChild(row);
  return row;
}

document.getElementById("add-request-btn").addEventListener("click", () => {
  const row = addRequestRow();
  row.querySelector(".req-cn").focus();
});

function getRequestEntries() {
  return Array.from(requestRows.querySelectorAll(".request-row")).map(row => ({
    cn: row.querySelector(".req-cn").value.trim(),
    sans: row.querySelector(".req-sans").value.trim(),
  })).filter(e => e.cn || e.sans);
}

// Returns null + sets an error status if any populated row is invalid.
function buildCertlistContent() {
  const lines = [];
  for (const e of getRequestEntries()) {
    if (!e.cn) {
      setStatus(saveStatus, "Each request needs a hostname/CN.", "err");
      return null;
    }
    if (!ENTRY_RE.test(e.cn)) {
      setStatus(saveStatus, `Invalid characters in hostname: ${e.cn}`, "err");
      return null;
    }
    const sanTokens = e.sans
      ? e.sans.split(",").map(s => s.trim()).filter(Boolean)
      : [];
    for (const s of sanTokens) {
      if (!ENTRY_RE.test(s)) {
        setStatus(saveStatus, `Invalid characters in SAN: ${s}`, "err");
        return null;
      }
    }
    lines.push([e.cn, ...sanTokens].join(","));
  }
  return lines.length ? lines.join("\n") + "\n" : "";
}

function setRequestRowsFromContent(content) {
  requestRows.innerHTML = "";
  (content || "").split("\n")
    .map(l => l.trim())
    .filter(l => l && !l.startsWith("#"))
    .forEach(line => {
      const parts = line.split(",").map(p => p.trim()).filter(Boolean);
      addRequestRow(parts[0] || "", parts.slice(1).join(", "));
    });
  if (!requestRows.querySelector(".request-row")) addRequestRow();
}

async function loadCertlist() {
  setStatus(saveStatus, "Loading…");
  const r = await jsonReq("/rhel/certlist");
  if (!r.ok) { setStatus(saveStatus, "Failed to load", "err"); return; }
  setRequestRowsFromContent(r.body.content || "");
  setStatus(saveStatus, "Loaded", "ok");
}

async function saveCertlist() {
  const content = buildCertlistContent();
  if (content === null) return false;
  setStatus(saveStatus, "Saving…");
  const r = await jsonReq("/rhel/certlist", {
    method: "POST",
    body: JSON.stringify({ content }),
  });
  if (!r.ok) {
    setStatus(saveStatus, (r.body && r.body.error) || "Save failed", "err");
    return false;
  }
  setStatus(saveStatus, "Saved", "ok");
  return true;
}

document.getElementById("reload-btn").addEventListener("click", loadCertlist);
document.getElementById("save-btn").addEventListener("click", saveCertlist);
document.getElementById("clear-btn").addEventListener("click", () => {
  requestRows.innerHTML = "";
  addRequestRow();
  setStatus(saveStatus, "Cleared (unsaved — click Save to persist)", "");
});

// ===== Generate =====
const genBtn = document.getElementById("generate-btn");
const genStatus = document.getElementById("generate-status");
const genLog = document.getElementById("generate-log");

async function generateRhel() {
  if (getRequestEntries().length === 0) {
    setStatus(genStatus, "Add at least one request first.", "err");
    return;
  }
  genBtn.disabled = true;

  // Auto-save the request rows before running the script
  setStatus(genStatus, "Saving certlist…");
  const saved = await saveCertlist();
  if (!saved) {
    setStatus(genStatus, "Aborted: certlist save failed", "err");
    genBtn.disabled = false;
    return;
  }

  setStatus(genStatus, "Running csr-rhel.sh…");
  genLog.hidden = false;
  genLog.textContent = "(running, please wait)";
  const notifyEmail = (document.getElementById("notify-email").value || "").trim();
  const groupId = document.getElementById("generate-group").value;
  const certTypes = getGenCertTypes();
  if (certTypes.length === 0) {
    setStatus(genStatus, "Select a certificate template first.", "err");
    genLog.hidden = true;
    return;
  }
  const body = { cert_type: certTypes,
                 key_algo: document.getElementById("generate-key-algo").value };
  if (notifyEmail) body.requester_email = notifyEmail;
  if (groupId) body.group_id = parseInt(groupId, 10);
  // Chosen domain suffix (only present when the admin configured alternates).
  const domSel = document.getElementById("generate-domain");
  const domField = document.getElementById("generate-domain-field");
  if (domSel && domField && !domField.hidden && domSel.value) {
    body.domain_suffix = domSel.value;
  }
  // Carry the chosen template so the request inherits its signing policy.
  const tplSel = document.getElementById("generate-template");
  if (tplSel && tplSel.value && tplSel.value !== "__custom__") {
    body.template_id = parseInt(tplSel.value, 10);
  }
  const r = await jsonReq("/rhel/generate", {
    method: "POST",
    body: JSON.stringify(body),
  });
  genBtn.disabled = false;
  if (!r.ok) {
    setStatus(genStatus, (r.body && r.body.error) || "Request failed", "err");
    genLog.textContent = (r.body && r.body.error) || "request failed";
    return;
  }
  const rc = r.body.returncode;
  const jobs = (r.body.jobs || []).length;
  setStatus(genStatus,
    rc === 0 ? `Completed: ${jobs} job(s) created` : `Failed (rc=${rc})`,
    rc === 0 ? "ok" : "err");
  genLog.textContent = r.body.output || "(no output)";

  // Server clears the on-disk certlist after success; mirror that in the UI
  if (rc === 0) {
    requestRows.innerHTML = "";
    addRequestRow();
    document.getElementById("notify-email").value = "";
    document.getElementById("generate-group").value = "";
    const genSel = document.getElementById("generate-template");
    genSel?.querySelector('option[value="__custom__"]')?.remove();
    if (genSel) { genSel.value = ""; populateTemplateDropdown(); }
    document.getElementById("generate-key-algo").value = "rsa2048";
    setStatus(saveStatus, "Cleared after generation", "");
  }

  await refreshJobs();
  await refreshKeys();
}

genBtn.addEventListener("click", generateRhel);

// ===== Session keys =====
const keysCard = document.getElementById("keys-card");
const keysTbody = document.getElementById("keys-tbody");
const sessionStatus = document.getElementById("session-status");

async function refreshKeys() {
  const r = await jsonReq("/rhel/keys");
  const keys = (r.ok && r.body.keys) ? r.body.keys : [];
  if (!keys.length) {
    keysCard.hidden = true;
    keysTbody.innerHTML = "";
    return;
  }
  keysCard.hidden = false;
  keysTbody.innerHTML = keys.map(row => `
    <tr>
      <td><code>${escapeHtml(row.name)}</code></td>
      <td class="size">${fmtBytes(row.size)}</td>
      <td>${escapeHtml(row.mtime)}</td>
      <td><a class="dl" href="${API}/rhel/keys/${encodeURIComponent(row.name)}">Download</a></td>
    </tr>`).join("");
}

async function endSession() {
  if (!confirm("End your session? Private keys will no longer be downloadable from this browser.")) return;
  setStatus(sessionStatus, "Ending session…");
  const r = await jsonReq("/session/end", { method: "POST" });
  if (!r.ok) { setStatus(sessionStatus, "Failed", "err"); return; }
  setStatus(sessionStatus, "Session ended.", "ok");
  await refreshKeys();
}
document.getElementById("end-session-btn").addEventListener("click", endSession);

