// CSR Dashboard frontend - Linux-only flow with jobs DB
const API = "/csr/api";
const CSRF = { "X-Requested-With": "csr-dashboard", "Content-Type": "application/json" };
const PAGE_SIZE = 50;

// ===== DoD banner =====
const banner = document.getElementById("dod-banner");
const ACCEPTED_KEY = "csr-dod-accepted";
const accepted = sessionStorage.getItem(ACCEPTED_KEY) === "1";
if (accepted) banner.style.display = "none";

document.getElementById("dod-accept").addEventListener("click", () => {
  sessionStorage.setItem(ACCEPTED_KEY, "1");
  banner.style.display = "none";
  init();
});
document.getElementById("dod-decline").addEventListener("click", () => {
  document.documentElement.innerHTML =
    "<body style='font-family:sans-serif;padding:40px;'>Access declined. Close this tab.</body>";
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

document.querySelectorAll("#admin-nav button").forEach(b => {
  b.addEventListener("click", () => showAdminPanel(b.dataset.panel));
});
document.querySelectorAll("#main-nav button").forEach(b => {
  b.addEventListener("click", () => showMainPanel(b.dataset.panel));
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
                <td>${m.role !== "owner"
                  ? `<button class="link-btn mygroup-remove" data-gid="${grp.id}" data-dn="${escapeHtml(m.dn)}" style="color:var(--danger)">Remove</button>`
                  : ""}</td>
              </tr>`).join("")}
          </tbody>
        </table>
        <div class="row" style="margin-top:8px; gap:6px">
          <input type="email" class="form-input mygroup-add-email" data-gid="${grp.id}"
                 placeholder="member's dashboard email" style="width:260px">
          <button class="mygroup-add-btn" data-gid="${grp.id}" type="button">Add member</button>
          <span class="status mygroup-status" data-gid="${grp.id}"></span>
        </div>` : ""}
    </div>`).join("");

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

function addRequestRow(cn = "", sans = "") {
  const row = document.createElement("div");
  row.className = "request-row";

  const cnInput = document.createElement("input");
  cnInput.type = "text";
  cnInput.className = "form-input req-cn";
  cnInput.placeholder = "myserver  or  myserver.eucom.mil";
  cnInput.autocomplete = "off";
  cnInput.value = cn;

  const sansInput = document.createElement("input");
  sansInput.type = "text";
  sansInput.className = "form-input req-sans";
  sansInput.placeholder = "alt.eucom.mil, 10.1.2.3";
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

// ===== Jobs =====
let currentPage = 0;
let jobsTotal = 0;
const jobsTbody = document.getElementById("jobs-tbody");
const pageInfo = document.getElementById("page-info");
const prevBtn = document.getElementById("prev-btn");
const nextBtn = document.getElementById("next-btn");

const filterSearch = document.getElementById("filter-search");
const filterStatus = document.getElementById("filter-status");
const filterSource = document.getElementById("filter-source");
const filterDays = document.getElementById("filter-days");

let expiringActive = false;
function buildJobsQuery() {
  const params = new URLSearchParams();
  params.set("limit", PAGE_SIZE);
  params.set("offset", currentPage * PAGE_SIZE);
  const q = filterSearch.value.trim();
  if (q) params.set("q", q);
  if (filterStatus.value) params.set("status", filterStatus.value);
  if (filterSource.value) params.set("source", filterSource.value);
  if (filterDays.value) params.set("days", filterDays.value);
  if (expiringActive) params.set("expiring_within", "60");
  return "?" + params.toString();
}

async function refreshJobs() {
  jobsTbody.innerHTML = '<tr><td colspan="8" class="status">Loading…</td></tr>';
  const r = await jsonReq("/jobs" + buildJobsQuery());
  if (!r.ok) {
    jobsTbody.innerHTML = '<tr><td colspan="8" class="status err">Failed to load jobs</td></tr>';
    return;
  }
  const jobs = r.body.jobs || [];
  jobsTotal = r.body.total || 0;

  if (!jobs.length) {
    jobsTbody.innerHTML = '<tr><td colspan="8" class="status">No jobs match your filter.</td></tr>';
  } else {
    jobsTbody.innerHTML = jobs.map(job => `
      <tr>
        <td>${job.can_cancel
          ? `<input type="checkbox" class="job-select-cb" value="${job.id}">`
          : ""}</td>
        <td title="${fmtTime(job.created_at)}">${fmtRelTime(job.created_at)}</td>
        <td><code>${escapeHtml(job.target_host)}</code></td>
        <td>${certTypePill(job.cert_type)}</td>
        <td>${statusPill(job.status)}</td>
        <td title="${escapeHtml(job.requester_dn)}">${escapeHtml(job.requester_display || shortDN(job.requester_dn))}</td>
        <td>${job.group_name ? `<span class="pill pill-blue">${escapeHtml(job.group_name)}</span>` : '<span class="status">&mdash;</span>'}</td>
        <td><button class="link-btn job-detail-btn" data-id="${job.id}">Details</button></td>
      </tr>`).join("");
    jobsTbody.querySelectorAll(".job-detail-btn").forEach(b => {
      b.addEventListener("click", () => openDetailModal(b.dataset.id));
    });
    jobsTbody.querySelectorAll(".job-select-cb").forEach(cb => {
      cb.addEventListener("change", updateBulkCancelState);
    });
  }
  const selAll = document.getElementById("jobs-select-all");
  if (selAll) selAll.checked = false;
  updateBulkCancelState();

  const start = currentPage * PAGE_SIZE + 1;
  const end = Math.min(start + jobs.length - 1, jobsTotal);
  pageInfo.textContent = jobsTotal === 0 ? "0 jobs" : `${start}–${end} of ${jobsTotal}`;
  prevBtn.disabled = currentPage === 0;
  nextBtn.disabled = (currentPage + 1) * PAGE_SIZE >= jobsTotal;
}

filterSearch.addEventListener("input", debounce(() => { currentPage = 0; refreshJobs(); }, 300));
filterStatus.addEventListener("change", () => { currentPage = 0; refreshJobs(); });
filterSource.addEventListener("change", () => { currentPage = 0; refreshJobs(); });

document.getElementById("filter-expiring-btn")?.addEventListener("click", (e) => {
  expiringActive = !expiringActive;
  e.target.classList.toggle("active", expiringActive);
  e.target.style.borderColor = expiringActive ? "var(--warning)" : "";
  e.target.style.color = expiringActive ? "var(--warning)" : "";
  currentPage = 0;
  refreshJobs();
});

document.getElementById("export-csv-btn")?.addEventListener("click", () => {
  const params = new URLSearchParams();
  if (filterStatus.value) params.set("status", filterStatus.value);
  if (filterSource.value) params.set("source", filterSource.value);
  if (expiringActive) params.set("expiring_within", "60");
  window.location = API + "/jobs/export.csv?" + params.toString();
});
filterDays.addEventListener("change", () => { currentPage = 0; refreshJobs(); });
document.getElementById("refresh-btn").addEventListener("click", refreshJobs);
prevBtn.addEventListener("click", () => { if (currentPage > 0) { currentPage--; refreshJobs(); } });
nextBtn.addEventListener("click", () => { currentPage++; refreshJobs(); });

// ===== Modals =====
const overlay = document.getElementById("modal-overlay");
const allModalIds = ["external-modal", "upload-cert-modal", "cancel-modal", "fail-modal", "detail-modal"];

function openModal(id) {
  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== id); });
  overlay.hidden = false;
}
function closeModal() {
  overlay.hidden = true;
  allModalIds.forEach(m => { document.getElementById(m).hidden = true; });
}

overlay.addEventListener("click", (e) => { if (e.target === overlay) closeModal(); });
document.querySelectorAll(".modal-cancel").forEach(b => b.addEventListener("click", closeModal));
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !overlay.hidden) closeModal(); });

// ===== External CSR submit =====
document.getElementById("submit-external-btn").addEventListener("click", () => {
  document.getElementById("external-target").value = "";
  document.getElementById("external-email").value = currentUser?.email || "";
  document.getElementById("external-group").value = "";
  resetCertTypes("external-cert-types", []);
  document.getElementById("external-csr").value = "";
  setStatus(document.getElementById("external-status"), "");
  openModal("external-modal");
  setTimeout(() => document.getElementById("external-target").focus(), 50);
});

document.getElementById("external-submit-btn").addEventListener("click", async () => {
  const target_host = document.getElementById("external-target").value.trim();
  const requester_email = document.getElementById("external-email").value.trim();
  const groupId = document.getElementById("external-group").value;
  const certTypes = getCertTypes("external-cert-types");
  const csr_pem = document.getElementById("external-csr").value;
  const status = document.getElementById("external-status");
  if (!target_host || !csr_pem) {
    setStatus(status, "Hostname and CSR are required.", "err");
    return;
  }
  setStatus(status, "Submitting…");
  const payload = { target_host, csr_pem };
  if (requester_email) payload.requester_email = requester_email;
  if (groupId) payload.group_id = parseInt(groupId, 10);
  if (certTypes.length) payload.cert_type = certTypes;
  const r = await jsonReq("/external/submit", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Submission failed", "err");
    return;
  }
  setStatus(status, `Submitted as job ${r.body.job_id.substring(0,12)}…`, "ok");
  setTimeout(() => { closeModal(); refreshJobs(); }, 1000);
});

// ===== Job detail modal =====
async function openDetailModal(jobId) {
  const r = await jsonReq(`/jobs/${jobId}`);
  if (!r.ok) return;
  renderDetailModal(r.body);
  openModal("detail-modal");
}

function renderDetailModal(job) {
  document.getElementById("detail-title").textContent = `Job: ${job.target_host}`;
  const body = document.getElementById("detail-body");

  const sansHtml = (job.sans || []).length
    ? job.sans.map(s => `<code>${escapeHtml(s)}</code>`).join(" ")
    : "<em>none</em>";

  const errorHtml = job.error
    ? `<div class="error-box"><strong>Error:</strong> ${escapeHtml(job.error)}</div>`
    : "";

  const actions = [];
  actions.push(`<a class="btn" href="${API}/jobs/${job.id}/csr">Download CSR</a>`);
  if (job.can_download_key) {
    actions.push(`<a class="btn" href="${API}/jobs/${job.id}/key">Download Key</a>`);
  }
  if (job.status === "issued") {
    actions.push(`<a class="btn" href="${API}/jobs/${job.id}/cert">Download Cert</a>`);
  }
  if (job.status === "issued" || job.status === "expired") {
    actions.push(`<button class="btn" data-action="renew" data-id="${job.id}" data-host="${escapeHtml(job.target_host)}">Renew</button>`);
  }
  if (job.status === "pending") {
    actions.push(`<button class="btn" data-action="upload" data-id="${job.id}" data-host="${escapeHtml(job.target_host)}">Upload Cert</button>`);
    if (job.can_cancel) {
      actions.push(`<button class="btn secondary" data-action="cancel" data-id="${job.id}" data-host="${escapeHtml(job.target_host)}">Cancel Job</button>`);
    }
    if (job.can_mark_failed) {
      actions.push(`<button class="btn secondary" data-action="fail" data-id="${job.id}" data-host="${escapeHtml(job.target_host)}">Mark Failed</button>`);
    }
  }

  const csrToggle = `
    <details class="openssl-toggle" data-job-id="${job.id}" data-kind="csr">
      <summary>View CSR details (openssl req -noout -text)</summary>
      <pre class="openssl-text">Loading&hellip;</pre>
    </details>`;

  const certToggle = job.status === "issued" ? `
    <details class="openssl-toggle" data-job-id="${job.id}" data-kind="cert">
      <summary>View certificate details (openssl x509 -noout -text)</summary>
      <pre class="openssl-text">Loading&hellip;</pre>
    </details>` : "";

  // Build the Group row: shows current group as a pill, plus an edit
  // control for the requester or any admin. Always present when the user
  // has edit rights, so they can assign a group to a previously-unassigned job.
  let groupRowHtml = "";
  if (job.can_edit_group || job.group_name) {
    const pill = job.group_name
      ? `<span class="pill pill-blue" id="job-group-pill">${escapeHtml(job.group_name)}</span>`
      : `<span class="status" id="job-group-pill">&mdash;</span>`;
    const edit = job.can_edit_group
      ? ` <button class="link-btn" id="job-group-edit-btn" data-job-id="${job.id}" data-current="${job.group_id ?? ''}">${job.group_id ? 'change' : 'assign'}</button>`
      : "";
    groupRowHtml = `<tr><th>Group</th><td>${pill}${edit}</td></tr>`;
  }

  body.innerHTML = `
    <table class="detail-table">
      <tr><th>Job ID</th><td><code>${escapeHtml(job.id)}</code></td></tr>
      <tr><th>Target host</th><td><code>${escapeHtml(job.target_host)}</code></td></tr>
      <tr><th>SANs</th><td>${sansHtml}</td></tr>
      <tr><th>Source</th><td>${sourcePill(job.source)}</td></tr>
      ${job.cert_type ? `<tr><th>Cert type</th><td>${certTypePill(job.cert_type)}</td></tr>` : ""}
      <tr><th>Status</th><td>${statusPill(job.status)}</td></tr>
      ${job.expires_at ? `<tr><th>Expires</th><td>${fmtTime(job.expires_at)} <span class="status">(${expiryCountdown(job.expires_at)})</span></td></tr>` : ""}
      ${job.key_algo ? `<tr><th>Key</th><td><code>${escapeHtml(job.key_algo)}</code></td></tr>` : ""}
      ${job.renewed_from ? `<tr><th>Renewed from</th><td><button class="link-btn" onclick="openDetailModal('${job.renewed_from}')">previous job</button></td></tr>` : ""}
      <tr><th>Requester</th><td>${
        job.requester_email
          ? `<code>${escapeHtml(job.requester_email)}</code> <span class="status" title="${escapeHtml(job.requester_dn)}">(${escapeHtml(job.requester_cn || '?')})</span>`
          : `<code>${escapeHtml(job.requester_cn || job.requester_dn)}</code>`
      }</td></tr>
      ${groupRowHtml}
      <tr><th>Created</th><td>${fmtTime(job.created_at)}</td></tr>
      ${job.completed_at ? `<tr><th>Completed</th><td>${fmtTime(job.completed_at)}</td></tr>` : ""}
      ${job.completed_by_cn ? `<tr><th>Completed by</th><td><code>${escapeHtml(job.completed_by_cn)}</code></td></tr>` : ""}
      ${job.has_local_key ? `<tr><th>Local key</th><td><code>${escapeHtml(job.local_key_name || '')}</code></td></tr>` : ""}
    </table>
    ${errorHtml}
    ${csrToggle}
    ${certToggle}
    <div class="row" style="margin-top:16px; gap:8px">
      ${actions.join("")}
    </div>
  `;

  // Wire up action buttons inside the detail modal
  body.querySelectorAll("[data-action]").forEach(b => {
    b.addEventListener("click", () => {
      const id = b.dataset.id;
      const host = b.dataset.host;
      if (b.dataset.action === "upload") openUploadCert(id, host);
      else if (b.dataset.action === "cancel") openCancel(id, host);
      else if (b.dataset.action === "fail") openMarkFailed(id, host);
      else if (b.dataset.action === "renew") renewJob(id, host, b);
    });
  });

  // Wire up the group-edit control if present
  const editGrpBtn = body.querySelector("#job-group-edit-btn");
  if (editGrpBtn) {
    editGrpBtn.addEventListener("click", () => {
      openGroupEditorInline(editGrpBtn, job.id);
    });
  }

  // Lazy-load openssl text on first expand
  body.querySelectorAll("details.openssl-toggle").forEach(d => {
    d.addEventListener("toggle", async () => {
      if (!d.open || d.dataset.loaded === "1") return;
      const id = d.dataset.jobId;
      const kind = d.dataset.kind; // "csr" or "cert"
      const pre = d.querySelector(".openssl-text");
      pre.textContent = "Loading…";
      const r = await jsonReq(`/jobs/${id}/${kind}-info`);
      if (r.ok) {
        pre.textContent = r.body.text;
        d.dataset.loaded = "1";
      } else {
        pre.textContent = "Failed: " + ((r.body && r.body.error) || "unknown");
      }
    });
  });
}

// ===== Upload cert =====
function openUploadCert(jobId, targetHost) {
  const t = document.getElementById("upload-job-target");
  t.textContent = targetHost;
  t.dataset.id = jobId;
  document.getElementById("upload-cert-text").value = "";
  document.getElementById("upload-cert-file").value = "";
  setStatus(document.getElementById("upload-cert-status"), "");
  openModal("upload-cert-modal");
}

document.getElementById("upload-cert-file").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => { document.getElementById("upload-cert-text").value = reader.result; };
  reader.readAsText(file);
});

document.getElementById("upload-cert-submit-btn").addEventListener("click", async () => {
  const jobId = document.getElementById("upload-job-target").dataset.id;
  const cert_pem = document.getElementById("upload-cert-text").value;
  const status = document.getElementById("upload-cert-status");
  if (!cert_pem) {
    setStatus(status, "Cert content required.", "err");
    return;
  }
  setStatus(status, "Uploading…");
  const r = await jsonReq(`/jobs/${jobId}/upload-cert`, {
    method: "POST",
    body: JSON.stringify({ cert_pem }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Upload failed", "err");
    return;
  }
  const warns = r.body.warnings || [];
  if (warns.length) {
    setStatus(status,
      `Uploaded for ${r.body.target_host}, with warnings:\n• ` + warns.join("\n• "),
      "err");
    refreshJobs();
    // leave the modal open so the warnings are actually read
  } else {
    setStatus(status, `Uploaded for ${r.body.target_host}. Cert dropped to /home/ansible/issued/`, "ok");
    setTimeout(() => { closeModal(); refreshJobs(); }, 1500);
  }
});

// ===== Cancel job =====
function openCancel(jobId, targetHost) {
  const t = document.getElementById("cancel-job-target");
  t.textContent = targetHost;
  t.dataset.id = jobId;
  document.getElementById("cancel-reason").value = "";
  setStatus(document.getElementById("cancel-status"), "");
  openModal("cancel-modal");
}

document.getElementById("cancel-submit-btn").addEventListener("click", async () => {
  const jobId = document.getElementById("cancel-job-target").dataset.id;
  const reason = document.getElementById("cancel-reason").value;
  const status = document.getElementById("cancel-status");
  setStatus(status, "Cancelling…");
  const r = await jsonReq(`/jobs/${jobId}/cancel`, {
    method: "POST",
    body: JSON.stringify({ reason }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Cancel failed", "err");
    return;
  }
  setStatus(status, "Cancelled.", "ok");
  setTimeout(() => { closeModal(); refreshJobs(); }, 800);
});

// ===== Mark failed =====
function openMarkFailed(jobId, targetHost) {
  const t = document.getElementById("fail-job-target");
  t.textContent = targetHost;
  t.dataset.id = jobId;
  document.getElementById("fail-reason").value = "";
  setStatus(document.getElementById("fail-status"), "");
  openModal("fail-modal");
}

document.getElementById("fail-submit-btn").addEventListener("click", async () => {
  const jobId = document.getElementById("fail-job-target").dataset.id;
  const error = document.getElementById("fail-reason").value;
  const status = document.getElementById("fail-status");
  if (!error) {
    setStatus(status, "Reason required.", "err");
    return;
  }
  setStatus(status, "Marking…");
  const r = await jsonReq(`/jobs/${jobId}/mark-failed`, {
    method: "POST",
    body: JSON.stringify({ error }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Mark failed", "err");
    return;
  }
  setStatus(status, "Marked as failed.", "ok");
  setTimeout(() => { closeModal(); refreshJobs(); }, 800);
});

// ===== init =====
let currentUser = null;

async function loadMe() {
  const r = await jsonReq("/me");
  if (!r.ok) return;
  currentUser = r.body;
  if (currentUser.is_admin) {
    document.body.classList.add("is-admin");
  }
  if (currentUser.email) {
    const notifyEl = document.getElementById("notify-email");
    if (notifyEl && !notifyEl.value) notifyEl.value = currentUser.email;
  }
  const sqBtn = document.getElementById("main-nav-signing");
  if (sqBtn) sqBtn.hidden = !(currentUser && (currentUser.is_signer || currentUser.is_admin));
}

// ===== Settings modal =====
allModalIds.push("settings-modal", "user-edit-modal");

function openSettings() {
  if (!currentUser) return;
  document.getElementById("settings-dn").textContent = currentUser.dn;
  document.getElementById("settings-email").value = currentUser.email || "";
  setStatus(document.getElementById("settings-status"), "");
  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== "settings-modal"); });
  overlay.hidden = false;
}

document.getElementById("nav-settings").addEventListener("click", openSettings);

document.getElementById("settings-save-btn").addEventListener("click", async () => {
  const status = document.getElementById("settings-status");
  const email = document.getElementById("settings-email").value.trim();
  setStatus(status, "Saving…");
  const r = await jsonReq("/me/prefs", {
    method: "PUT",
    body: JSON.stringify({ email }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
    return;
  }
  setStatus(status, "Saved", "ok");
  currentUser.email = r.body.email;
  const notifyEl = document.getElementById("notify-email");
  if (notifyEl && !notifyEl.value && r.body.email) notifyEl.value = r.body.email;
  setTimeout(closeModal, 600);
});

// ===== Nav routing =====
const mainView = document.getElementById("main-view");
const adminView = document.getElementById("admin-view");
const navDashBtn = document.getElementById("nav-dashboard");
const navAdminBtn = document.getElementById("nav-admin");

function applyRoute() {
  const wantAdmin = location.hash === "#admin" && currentUser && currentUser.is_admin;
  if (wantAdmin) {
    mainView.hidden = true;
    adminView.hidden = false;
    navDashBtn.classList.remove("active");
    navAdminBtn.classList.add("active");
    refreshAdminView();
  } else {
    mainView.hidden = false;
    adminView.hidden = true;
    navDashBtn.classList.add("active");
    navAdminBtn.classList.remove("active");
    if (location.hash === "#admin") location.hash = "";
  }
}
navDashBtn.addEventListener("click", () => { location.hash = ""; });
navAdminBtn.addEventListener("click", () => { location.hash = "#admin"; });
window.addEventListener("hashchange", applyRoute);

// ===== Admin view =====
async function refreshAdminView() {
  await Promise.all([
    refreshAdminStats(),
    refreshAdminUsers(),
    refreshAdminGroups(),
    refreshOrphanKeys(),
    refreshOrphanCerts(),
    loadEmailConfig(),
    loadGitlabConfig(),
    loadTrust(),
    refreshAdminTemplates(),
  ]);
}

// ===== Admin: templates =====
async function refreshAdminTemplates() {
  const tbody = document.getElementById("admin-templates-tbody");
  if (!tbody) return;
  await loadTemplates();  // refreshes myTemplates + the Generate dropdown
  const scopeLabel = (t) => {
    if (t.scope === "builtin") {
      return t.created_by_dn === "system"
        ? '<span class="pill" style="background:#10b981;color:white">built-in</span>'
        : '<span class="pill" style="background:#10b981;color:white">instance</span>';
    }
    if (t.scope === "personal") return '<span class="pill" style="background:#6b7280;color:white">personal</span>';
    return `<span class="pill pill-blue">${escapeHtml(t.group_name || "group")}</span>`;
  };
  if (!myTemplates.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="status">No templates.</td></tr>';
  } else {
    tbody.innerHTML = myTemplates.map(t => `
      <tr>
        <td><code>${escapeHtml(t.name)}</code>${t.description ? `<br><span class="status">${escapeHtml(t.description)}</span>` : ""}</td>
        <td>${certTypePill(t.cert_types)}</td>
        <td>${scopeLabel(t)}</td>
        <td class="status">${t.created_by_dn === "system" ? "system" : escapeHtml(shortDN(t.created_by_dn || ""))}</td>
        <td><button class="link-btn admin-template-del" data-id="${t.id}" data-name="${escapeHtml(t.name)}" style="color:var(--danger)">Delete</button></td>
      </tr>`).join("");
    tbody.querySelectorAll(".admin-template-del").forEach(b => {
      b.addEventListener("click", async () => {
        if (!confirm(`Delete template "${b.dataset.name}"? (Admin action)`)) return;
        const r = await jsonReq("/admin/templates/" + b.dataset.id, { method: "DELETE" });
        if (r.ok) refreshAdminTemplates();
        else alert("Delete failed: " + ((r.body && r.body.error) || "unknown"));
      });
    });
  }
  // Scope select: instance-wide + every group
  const sel = document.getElementById("admin-template-scope");
  if (sel) {
    const current = sel.value;
    sel.innerHTML = '<option value="global">Instance-wide (all users)</option>' +
      (adminAllGroups || []).map(grp =>
        `<option value="${grp.id}">Group: ${escapeHtml(grp.name)}</option>`).join("");
    if ([...sel.options].some(o => o.value === current)) sel.value = current;
  }
}

document.getElementById("admin-templates-refresh")?.addEventListener("click", refreshAdminTemplates);

// ===== Admin: audit log =====
let auditOffset = 0;

async function loadAudit(append = false) {
  const tbody = document.getElementById("audit-tbody");
  if (!tbody) return;
  if (!append) { auditOffset = 0; tbody.innerHTML = '<tr><td colspan="5" class="status">Loading…</td></tr>'; }
  const params = new URLSearchParams({ limit: 100, offset: auditOffset });
  const fa = document.getElementById("audit-filter-action").value.trim();
  const fu = document.getElementById("audit-filter-actor").value.trim();
  const fq = document.getElementById("audit-filter-q").value.trim();
  if (fa) params.set("action", fa);
  if (fu) params.set("actor", fu);
  if (fq) params.set("q", fq);
  const r = await jsonReq("/admin/audit?" + params.toString());
  if (!r.ok) { tbody.innerHTML = '<tr><td colspan="5" class="status err">Failed to load</td></tr>'; return; }
  const rows = (r.body.events || []).map(e => `
    <tr>
      <td title="${fmtTime(e.ts)}">${fmtRelTime(e.ts)}</td>
      <td title="${escapeHtml(e.actor || "")}">${escapeHtml(shortDN(e.actor || "") || "—")}</td>
      <td><code>${escapeHtml(e.action)}</code></td>
      <td>${escapeHtml(e.result)}</td>
      <td class="status" style="font-size:11px">${escapeHtml(Object.entries(e.detail || {}).map(([k,v]) => k + "=" + v).join(" "))}</td>
    </tr>`).join("");
  if (append) tbody.insertAdjacentHTML("beforeend", rows);
  else tbody.innerHTML = rows || '<tr><td colspan="5" class="status">No events match.</td></tr>';
  auditOffset += (r.body.events || []).length;
  document.getElementById("audit-more-btn").hidden = auditOffset >= r.body.total;
  setStatus(document.getElementById("audit-status"),
    `${auditOffset} of ${r.body.total} event(s)`, "");
}

document.getElementById("audit-refresh-btn")?.addEventListener("click", () => loadAudit(false));
document.getElementById("audit-search-btn")?.addEventListener("click", () => loadAudit(false));
document.getElementById("audit-more-btn")?.addEventListener("click", () => loadAudit(true));
document.querySelector('#admin-nav button[data-panel="audit"]')
  ?.addEventListener("click", () => loadAudit(false));

document.getElementById("admin-run-expiry-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("audit-status");
  setStatus(status, "Running expiry warnings…");
  const r = await jsonReq("/admin/run-expiry-warnings", { method: "POST" });
  if (!r.ok) { setStatus(status, "Failed", "err"); return; }
  setStatus(status, `Expiry run: ${r.body.sent} warning(s) sent, ${r.body.errors} error(s).`, "ok");
});

document.getElementById("admin-template-create-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("admin-template-status");
  const name = document.getElementById("admin-template-name").value.trim();
  const description = document.getElementById("admin-template-desc").value.trim();
  const scopeVal = document.getElementById("admin-template-scope").value;
  const certTypes = getCertTypes("admin-template-cert-types");
  if (!name) { setStatus(status, "Name is required.", "err"); return; }
  if (!certTypes.length) { setStatus(status, "Check at least one cert type.", "err"); return; }
  setStatus(status, "Creating…");
  const payload = { name, description, cert_types: certTypes };
  if (scopeVal === "global") payload.scope = "global";
  else payload.group_id = parseInt(scopeVal, 10);
  const r = await jsonReq("/templates", {
    method: "POST",
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Create failed", "err");
    return;
  }
  setStatus(status, "Created", "ok");
  document.getElementById("admin-template-name").value = "";
  document.getElementById("admin-template-desc").value = "";
  resetCertTypes("admin-template-cert-types", []);
  refreshAdminTemplates();
});

// Show only the field groups relevant to the selected delivery method.
function applyEmailProvider(provider) {
  document.querySelectorAll(".email-provider-fields").forEach((el) => {
    const forList = (el.dataset.for || "").split(/\s+/);
    el.style.display = forList.includes(provider) ? "" : "none";
  });
}

async function loadEmailConfig() {
  const r = await jsonReq("/admin/email-config");
  if (!r.ok) return;
  const c = r.body;
  const provider = c.provider || "smg";
  document.getElementById("email-cfg-provider").value = provider;
  document.getElementById("email-cfg-host").value = c.host || "";
  document.getElementById("email-cfg-port").value = c.port || 25;
  document.getElementById("email-cfg-timeout").value = c.timeout || 10;
  document.getElementById("email-cfg-security").value = c.security || "none";
  document.getElementById("email-cfg-username").value = c.username || "";
  document.getElementById("email-cfg-password").value = "";
  document.getElementById("email-cfg-password").placeholder =
    c.password_set ? "(blank = keep current)" : "(none set)";
  document.getElementById("email-cfg-mg-domain").value = c.mailgun_domain || "";
  document.getElementById("email-cfg-mg-base").value =
    c.mailgun_base_url || "https://api.mailgun.net";
  document.getElementById("email-cfg-mg-key").value = "";
  document.getElementById("email-cfg-mg-key").placeholder =
    c.mailgun_api_key_set ? "(blank = keep current)" : "(none set)";
  document.getElementById("email-cfg-from").value = c.from_address || "";
  document.getElementById("email-cfg-cc").value = c.cc || "";
  document.getElementById("email-cfg-url").value = c.dashboard_url || "";
  applyEmailProvider(provider);
  const state = document.getElementById("email-config-state");
  if (c.enabled) {
    state.innerHTML = `<span class="pill pill-ok">notifications enabled</span> <span class="status">via ${escapeHtml(provider)}</span>`;
  } else {
    state.innerHTML = `<span class="pill pill-err">disabled</span> <span class="status">${escapeHtml(c.disabled_reason || "")}</span>`;
  }
}

document.getElementById("email-cfg-provider")?.addEventListener("change", (e) => {
  applyEmailProvider(e.target.value);
});

document.getElementById("email-cfg-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("email-cfg-status");
  setStatus(status, "Saving…");
  const body = {
    provider: document.getElementById("email-cfg-provider").value,
    host: document.getElementById("email-cfg-host").value.trim(),
    port: parseInt(document.getElementById("email-cfg-port").value, 10),
    timeout: parseInt(document.getElementById("email-cfg-timeout").value, 10),
    security: document.getElementById("email-cfg-security").value,
    username: document.getElementById("email-cfg-username").value.trim(),
    password: document.getElementById("email-cfg-password").value,
    mailgun_domain: document.getElementById("email-cfg-mg-domain").value.trim(),
    mailgun_base_url: document.getElementById("email-cfg-mg-base").value,
    mailgun_api_key: document.getElementById("email-cfg-mg-key").value,
    from_address: document.getElementById("email-cfg-from").value.trim(),
    cc: document.getElementById("email-cfg-cc").value.trim(),
    dashboard_url: document.getElementById("email-cfg-url").value.trim(),
  };
  const r = await jsonReq("/admin/email-config", { method: "PUT", body: JSON.stringify(body) });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
    return;
  }
  setStatus(status, r.body.reason || "Saved", "ok");
  loadEmailConfig();
});

document.getElementById("admin-email-test-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("email-cfg-status");
  setStatus(status, "Sending test email…");
  const r = await jsonReq("/admin/test-email", { method: "POST" });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || (r.body && r.body.reason) || "Test failed", "err");
    return;
  }
  setStatus(status, `Test email sent to ${r.body.sent_to || "you"}.`, "ok");
});

async function loadGitlabConfig() {
  const r = await jsonReq("/admin/gitlab-config");
  if (!r.ok) return;
  const c = r.body;
  document.getElementById("gitlab-enabled").checked = !!c.enabled;
  document.getElementById("gitlab-base").value = c.base_url || "";
  document.getElementById("gitlab-project").value = c.project || "";
  document.getElementById("gitlab-assignees").value = c.assignee_ids || "";
  document.getElementById("gitlab-labels").value = c.labels || "";
  const tok = document.getElementById("gitlab-token");
  tok.value = ""; tok.placeholder = c.api_token_set ? "(blank = keep current)" : "(none set)";
  const sec = document.getElementById("gitlab-secret");
  sec.value = ""; sec.placeholder = c.webhook_secret_set ? "(blank = keep current)" : "(none set)";
  document.getElementById("gitlab-webhook-url").textContent =
    `${location.origin}/csr/api/webhooks/gitlab`;
  document.getElementById("gitlab-config-state").innerHTML = c.enabled
    ? '<span class="pill pill-ok">enabled</span>'
    : '<span class="pill pill-err">disabled</span>';
}

document.getElementById("gitlab-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("gitlab-status");
  setStatus(status, "Saving…");
  const body = {
    enabled: document.getElementById("gitlab-enabled").checked,
    base_url: document.getElementById("gitlab-base").value.trim(),
    project: document.getElementById("gitlab-project").value.trim(),
    assignee_ids: document.getElementById("gitlab-assignees").value.trim(),
    labels: document.getElementById("gitlab-labels").value.trim(),
    api_token: document.getElementById("gitlab-token").value,
    webhook_secret: document.getElementById("gitlab-secret").value,
  };
  const r = await jsonReq("/admin/gitlab-config", { method: "PUT", body: JSON.stringify(body) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Save failed", "err"); return; }
  setStatus(status, r.body.reason || "Saved", "ok");
  loadGitlabConfig();
});

document.getElementById("gitlab-test-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("gitlab-status");
  setStatus(status, "Testing connection…");
  const r = await jsonReq("/admin/gitlab-test", { method: "POST" });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Test failed", "err"); return; }
  setStatus(status, r.body.reason || "OK", "ok");
});

// ===== Admin: Trust portal (publish CA certs) =====
async function loadTrust() {
  const urlEl = document.getElementById("trust-public-url");
  if (urlEl) urlEl.textContent = `${location.origin}/csr/api/trust`;
  const box = document.getElementById("trust-list");
  if (!box) return;
  const r = await jsonReq("/admin/trust");
  if (!r.ok) { box.textContent = "Failed to load."; return; }
  const certs = (r.body && r.body.certs) || [];
  if (!certs.length) { box.innerHTML = "<em>No CA certificates published yet.</em>"; return; }
  box.innerHTML = certs.map((c) => `
    <div class="row" style="justify-content:space-between; gap:10px; padding:6px 0; border-bottom:1px solid var(--border,#333)">
      <div>
        <a href="${location.origin}/csr/api/trust/${encodeURIComponent(c.name)}">${escapeHtml(c.name)}</a>
        <div class="status">${escapeHtml(c.subject || "")}</div>
        <div class="status" style="font-family:monospace; font-size:11px">${escapeHtml(c.sha256 || "")}</div>
      </div>
      <button type="button" class="secondary trust-del" data-name="${escapeHtml(c.name)}">Delete</button>
    </div>`).join("");
  box.querySelectorAll(".trust-del").forEach((b) => b.addEventListener("click", async () => {
    if (!confirm(`Delete ${b.dataset.name}?`)) return;
    const rr = await jsonReq(`/admin/trust/${encodeURIComponent(b.dataset.name)}`, { method: "DELETE" });
    if (rr.ok) loadTrust(); else alert((rr.body && rr.body.error) || "delete failed");
  }));
}

document.getElementById("trust-upload-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("trust-status");
  const name = document.getElementById("trust-name").value.trim();
  const pem = document.getElementById("trust-pem").value.trim();
  if (!name || !pem) { setStatus(status, "Name and PEM required", "err"); return; }
  setStatus(status, "Publishing…");
  const r = await jsonReq("/admin/trust", { method: "POST", body: JSON.stringify({ name, pem }) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Failed", "err"); return; }
  setStatus(status, "Published", "ok");
  document.getElementById("trust-name").value = "";
  document.getElementById("trust-pem").value = "";
  loadTrust();
});

async function refreshAdminStats() {
  const grid = document.getElementById("stats-grid");
  grid.innerHTML = '<div class="stat-tile"><div class="label">Loading…</div></div>';
  const r = await jsonReq("/admin/stats");
  if (!r.ok) {
    grid.innerHTML = '<div class="stat-tile"><div class="label">Error</div></div>';
    return;
  }
  const s = r.body;
  const sub = (obj) => Object.entries(obj || {})
    .map(([k,v]) => `${escapeHtml(k)}: ${v}`).join(" · ") || "none";
  const dbMB = (s.db.size_bytes / 1024 / 1024).toFixed(2);
  grid.innerHTML = `
    <div class="stat-tile">
      <div class="label">Jobs total</div>
      <div class="value">${s.jobs.total}</div>
      <div class="sub">${sub(s.jobs.by_status)}</div>
    </div>
    <div class="stat-tile">
      <div class="label">By source</div>
      <div class="value">${sub(s.jobs.by_source)}</div>
    </div>
    <div class="stat-tile">
      <div class="label">Expiring &le;60 days</div>
      <div class="value">${s.jobs.expiring_60d ?? 0}</div>
      <div class="sub">issued certs nearing expiry</div>
    </div>
    <div class="stat-tile">
      <div class="label">Fleet certs</div>
      <div class="value">${s.fleet?.total ?? 0}</div>
      <div class="sub">${s.fleet?.expiring_60d ?? 0} expiring &le;60d</div>
    </div>
    <div class="stat-tile">
      <div class="label">Users</div>
      <div class="value">${s.users.total}</div>
      <div class="sub">${s.users.admin} admin · ${s.users.active} active</div>
    </div>
    <div class="stat-tile">
      <div class="label">DB size</div>
      <div class="value">${dbMB} MB</div>
      <div class="sub"><code>${escapeHtml(s.db.path)}</code></div>
    </div>
    <div class="stat-tile">
      <div class="label">Version</div>
      <div class="value">v${escapeHtml((currentUser && currentUser.version) || "?")}</div>
      <div class="sub">running on this host</div>
    </div>
    <div class="stat-tile">
      <div class="label">Email</div>
      <div class="value">${s.email.enabled ? "Enabled" : "Disabled"}</div>
      <div class="sub">${escapeHtml(s.email.reason || "")}</div>
    </div>
  `;
}

async function refreshAdminUsers() {
  const tbody = document.getElementById("admin-users-tbody");
  tbody.innerHTML = '<tr><td colspan="6" class="status">Loading…</td></tr>';
  const r = await jsonReq("/admin/users");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="6" class="status err">Failed to load</td></tr>';
    return;
  }
  const users = r.body.users || [];
  if (!users.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="status">No users yet.</td></tr>';
    return;
  }
  tbody.innerHTML = users.map(u => `
    <tr>
      <td title="${escapeHtml(u.dn)}"><code>${escapeHtml(u.cn || shortDN(u.dn))}</code></td>
      <td>${u.email ? `<code>${escapeHtml(u.email)}</code>` : '<em>—</em>'}</td>
      <td>${u.is_admin ? '<span class="pill pill-purple">admin</span>' : '<span class="pill pill-mute">user</span>'}</td>
      <td>${u.is_active ? '<span class="pill pill-ok">active</span>' : '<span class="pill pill-err">inactive</span>'}</td>
      <td title="${fmtTime(u.last_seen_at)}">${fmtRelTime(u.last_seen_at)}</td>
      <td><button class="link-btn user-edit-btn" data-dn="${escapeHtml(u.dn)}">Edit</button></td>
    </tr>
  `).join("");
  tbody.querySelectorAll(".user-edit-btn").forEach(b => {
    b.addEventListener("click", () => openUserEdit(users.find(u => u.dn === b.dataset.dn)));
  });
}
document.getElementById("admin-users-refresh").addEventListener("click", refreshAdminUsers);

document.getElementById("admin-test-email-btn").addEventListener("click", async () => {
  const status = document.getElementById("admin-test-email-status");
  const recipient = prompt(
    "Send test email to (leave blank to use your Settings email):",
    currentUser?.email || ""
  );
  if (recipient === null) return;  // user cancelled
  setStatus(status, "Sending…");
  const body = recipient.trim() ? JSON.stringify({ to: recipient.trim() }) : "{}";
  const r = await jsonReq("/admin/test-email", { method: "POST", body });
  if (r.ok) {
    setStatus(status, `Sent to ${r.body.sent_to}`, "ok");
  } else {
    setStatus(status, "Failed: " + ((r.body && r.body.error) || "unknown"), "err");
  }
});

function openUserEdit(user) {
  document.getElementById("user-edit-dn").textContent = user.dn;
  document.getElementById("user-edit-dn").dataset.dn = user.dn;
  document.getElementById("user-edit-email").value = user.email || "";
  document.getElementById("user-edit-admin").checked = !!user.is_admin;
  document.getElementById("user-edit-active").checked = !!user.is_active;
  document.getElementById("user-edit-notes").value = user.notes || "";
  const isSelf = currentUser && user.dn === currentUser.dn;
  document.getElementById("user-edit-admin").disabled = isSelf;
  document.getElementById("user-edit-active").disabled = isSelf;
  setStatus(document.getElementById("user-edit-status"),
    isSelf ? "You can't change your own admin or active flags." : "");
  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== "user-edit-modal"); });
  overlay.hidden = false;
}

document.getElementById("user-edit-save-btn").addEventListener("click", async () => {
  const status = document.getElementById("user-edit-status");
  const dn = document.getElementById("user-edit-dn").dataset.dn;
  const payload = {
    dn,
    email: document.getElementById("user-edit-email").value.trim(),
    is_admin: document.getElementById("user-edit-admin").checked,
    is_active: document.getElementById("user-edit-active").checked,
    notes: document.getElementById("user-edit-notes").value,
  };
  setStatus(status, "Saving…");
  const r = await jsonReq("/admin/users", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
    return;
  }
  setStatus(status, "Saved", "ok");
  setTimeout(() => { closeModal(); refreshAdminUsers(); }, 600);
});

// ===== Bulk job cleanup =====
function collectCleanupFilters() {
  const out = {};
  const s = document.getElementById("cleanup-status").value;
  const src = document.getElementById("cleanup-source").value;
  const days = document.getElementById("cleanup-days").value;
  if (s) out.status = s;
  if (src) out.source = src;
  if (days) out.older_than_days = parseInt(days, 10);
  if (!Object.keys(out).length) {
    setStatus(document.getElementById("cleanup-status-msg"),
      "At least one filter is required.", "err");
    return null;
  }
  out.delete_files = document.getElementById("cleanup-delete-files").checked;
  return out;
}

let cleanupPreviewLoaded = false;

function invalidateCleanupPreview() {
  cleanupPreviewLoaded = false;
  document.getElementById("cleanup-preview-wrap").hidden = true;
  document.getElementById("cleanup-preview-tbody").innerHTML = "";
  updateCleanupRunBtn();
}

function cleanupSelectedIds() {
  return Array.from(document.querySelectorAll("#cleanup-preview-tbody .cleanup-cb:checked"))
    .map(cb => cb.value);
}

function updateCleanupRunBtn() {
  const btn = document.getElementById("cleanup-run-btn");
  if (!cleanupPreviewLoaded) {
    btn.disabled = true;
    btn.textContent = "Delete (preview first)";
    return;
  }
  const n = cleanupSelectedIds().length;
  btn.disabled = (n === 0);
  btn.textContent = n ? `Delete selected (${n})` : "Delete selected";
}

// Changing any filter invalidates the loaded preview
["cleanup-status", "cleanup-source", "cleanup-days"].forEach(id => {
  document.getElementById(id)?.addEventListener("change", invalidateCleanupPreview);
});

document.getElementById("cleanup-select-all")?.addEventListener("change", (e) => {
  document.querySelectorAll("#cleanup-preview-tbody .cleanup-cb").forEach(cb => {
    cb.checked = e.target.checked;
  });
  updateCleanupRunBtn();
});
updateCleanupRunBtn();

document.getElementById("cleanup-preview-btn").addEventListener("click", async () => {
  const filters = collectCleanupFilters();
  if (!filters) return;
  const status = document.getElementById("cleanup-status-msg");
  setStatus(status, "Loading preview…");
  const r = await jsonReq("/admin/jobs/bulk-delete", {
    method: "POST",
    body: JSON.stringify({ ...filters, preview: true }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Preview failed", "err");
    invalidateCleanupPreview();
    return;
  }
  const jobs = r.body.jobs || [];
  const tbody = document.getElementById("cleanup-preview-tbody");
  const wrap = document.getElementById("cleanup-preview-wrap");
  const note = document.getElementById("cleanup-preview-note");
  if (!jobs.length) {
    setStatus(status, "0 jobs match — nothing to delete.", "");
    invalidateCleanupPreview();
    return;
  }
  tbody.innerHTML = jobs.map(j => `
    <tr>
      <td><input type="checkbox" class="cleanup-cb" value="${j.id}" checked></td>
      <td title="${fmtTime(j.created_at)}">${fmtRelTime(j.created_at)}</td>
      <td><code>${escapeHtml(j.target_host)}</code></td>
      <td>${statusPill(j.status)}</td>
      <td>${sourcePill(j.source)}</td>
      <td>${escapeHtml(j.requester_display || "")}</td>
    </tr>`).join("");
  tbody.querySelectorAll(".cleanup-cb").forEach(cb => {
    cb.addEventListener("change", updateCleanupRunBtn);
  });
  document.getElementById("cleanup-select-all").checked = true;
  wrap.hidden = false;
  setStatus(status, `${r.body.total} job(s) match.`, "");
  note.textContent = r.body.truncated
    ? `Showing the first ${jobs.length} of ${r.body.total}. Deleting acts only on the records selected here — run again after deleting to continue.`
    : "";
  cleanupPreviewLoaded = true;
  updateCleanupRunBtn();
});

document.getElementById("cleanup-run-btn").addEventListener("click", async () => {
  const ids = cleanupSelectedIds();
  if (!ids.length) return;
  const filters = collectCleanupFilters() || {};
  if (!confirm(`Permanently delete ${ids.length} selected job record(s)?\n` +
               `Delete files: ${filters.delete_files ? "YES" : "no"}\n\n` +
               "This cannot be undone. Continue?")) return;
  const status = document.getElementById("cleanup-status-msg");
  setStatus(status, "Deleting…");
  const r = await jsonReq("/admin/jobs/bulk-delete", {
    method: "POST",
    body: JSON.stringify({ ids, delete_files: !!filters.delete_files }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Delete failed", "err");
    return;
  }
  setStatus(status, `Deleted ${r.body.deleted} job(s); ${r.body.files_removed} file(s) removed.`, "ok");
  invalidateCleanupPreview();
  refreshAdminStats();
});

// ===== Orphan keys =====
async function refreshOrphanKeys() {
  const tbody = document.getElementById("admin-orphan-keys-tbody");
  tbody.innerHTML = '<tr><td colspan="4" class="status">Loading…</td></tr>';
  const r = await jsonReq("/admin/orphans/keys");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="4" class="status err">Failed to load</td></tr>';
    return;
  }
  const keys = r.body.keys || [];
  if (!keys.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="status">No orphan keys.</td></tr>';
    return;
  }
  tbody.innerHTML = keys.map(k => `
    <tr>
      <td><code>${escapeHtml(k.name)}</code></td>
      <td class="size">${fmtBytes(k.size)}</td>
      <td>${escapeHtml(k.mtime)}</td>
      <td><button class="link-btn orphan-key-del" data-name="${escapeHtml(k.name)}">Delete</button></td>
    </tr>
  `).join("");
  tbody.querySelectorAll(".orphan-key-del").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm(`Delete ${b.dataset.name}? This is permanent.`)) return;
      const r2 = await jsonReq("/admin/orphans/keys/" + encodeURIComponent(b.dataset.name), { method: "DELETE" });
      if (r2.ok) refreshOrphanKeys();
      else alert("Delete failed: " + ((r2.body && r2.body.error) || "unknown"));
    });
  });
}
document.getElementById("admin-orphan-keys-refresh").addEventListener("click", refreshOrphanKeys);

// ===== Orphan certs =====
async function refreshOrphanCerts() {
  const tbody = document.getElementById("admin-orphan-certs-tbody");
  tbody.innerHTML = '<tr><td colspan="4" class="status">Loading…</td></tr>';
  const r = await jsonReq("/admin/orphans/certs");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="4" class="status err">Failed to load</td></tr>';
    return;
  }
  const certs = r.body.certs || [];
  if (!certs.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="status">No orphan certs.</td></tr>';
    return;
  }
  tbody.innerHTML = certs.map(c => `
    <tr>
      <td><code>${escapeHtml(c.name)}</code></td>
      <td class="size">${fmtBytes(c.size)}</td>
      <td>${escapeHtml(c.mtime)}</td>
      <td><button class="link-btn orphan-cert-del" data-name="${escapeHtml(c.name)}">Delete</button></td>
    </tr>
  `).join("");
  tbody.querySelectorAll(".orphan-cert-del").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm(`Delete ${b.dataset.name}? This is permanent.`)) return;
      const r2 = await jsonReq("/admin/orphans/certs/" + encodeURIComponent(b.dataset.name), { method: "DELETE" });
      if (r2.ok) refreshOrphanCerts();
      else alert("Delete failed: " + ((r2.body && r2.body.error) || "unknown"));
    });
  });
}
document.getElementById("admin-orphan-certs-refresh").addEventListener("click", refreshOrphanCerts);

async function init() {
  await jsonReq("/session");
  await loadMe();
  await loadMyGroups();
  applyRoute();
  await Promise.all([loadCertlist(), refreshJobs(), refreshKeys(), loadTemplates()]);
}

// ===== Groups: dropdowns for job creation =====
let myGroups = [];

async function loadMyGroups() {
  const r = await jsonReq("/me/groups");
  if (!r.ok) { myGroups = []; return; }
  myGroups = r.body.groups || [];
  populateGroupDropdowns();
}

function populateGroupDropdowns() {
  // Admins can assign to any existing group; otherwise only their own.
  let options = myGroups.slice();
  const selects = [
    document.getElementById("generate-group"),
    document.getElementById("external-group"),
  ].filter(Boolean);
  for (const sel of selects) {
    const current = sel.value;
    sel.innerHTML = '<option value="">(none — personal job)</option>' +
      options.map(g => `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
    sel.value = current;
  }
}

async function openGroupEditorInline(btn, jobId) {
  // Replace the button + pill with a dropdown + Save / Cancel.
  // Admins see every group; non-admins see only their own.
  const td = btn.closest("td");
  if (!td) return;
  const originalHtml = td.innerHTML;

  // Pick the candidate list. If admin and adminAllGroups isn't loaded yet
  // (e.g. they're viewing this from Dashboard without visiting Admin first),
  // fetch it now.
  let candidates;
  if (currentUser?.is_admin) {
    if (!adminAllGroups || adminAllGroups.length === 0) {
      const r = await jsonReq("/admin/groups");
      if (r.ok) adminAllGroups = r.body.groups || [];
    }
    candidates = adminAllGroups;
  } else {
    candidates = myGroups;
  }

  const current = btn.dataset.current || "";
  const opts = '<option value="">(none — personal job)</option>' +
    candidates.map(g =>
      `<option value="${g.id}" ${String(g.id) === current ? 'selected' : ''}>${escapeHtml(g.name)}</option>`
    ).join("");

  td.innerHTML = `
    <select id="job-group-select" class="form-input" style="display:inline-block; width:auto; max-width:240px">${opts}</select>
    <button id="job-group-save-btn" type="button">Save</button>
    <button id="job-group-cancel-btn" class="secondary" type="button">Cancel</button>
    <span id="job-group-edit-status" class="status"></span>
  `;

  document.getElementById("job-group-cancel-btn").addEventListener("click", () => {
    td.innerHTML = originalHtml;
    // Re-bind the original button's handler since innerHTML wiped it
    const newBtn = td.querySelector("#job-group-edit-btn");
    if (newBtn) newBtn.addEventListener("click", () => openGroupEditorInline(newBtn, jobId));
  });

  document.getElementById("job-group-save-btn").addEventListener("click", async () => {
    const sel = document.getElementById("job-group-select");
    const status = document.getElementById("job-group-edit-status");
    const groupId = sel.value === "" ? null : parseInt(sel.value, 10);
    setStatus(status, "Saving…");
    const r = await jsonReq(`/jobs/${jobId}/group`, {
      method: "PUT",
      body: JSON.stringify({ group_id: groupId }),
    });
    if (!r.ok) {
      setStatus(status, (r.body && r.body.error) || "Save failed", "err");
      return;
    }
    // Re-render the detail modal and refresh the jobs table so the Group
    // column reflects the change.
    await openDetailModal(jobId);
    refreshJobs();
  });
}

// ===== Admin Groups card =====
let adminAllGroups = [];

async function refreshAdminGroups() {
  const tbody = document.getElementById("admin-groups-tbody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="status">Loading…</td></tr>';
  const r = await jsonReq("/admin/groups");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="6" class="status err">Failed to load</td></tr>';
    return;
  }
  adminAllGroups = r.body.groups || [];
  if (!adminAllGroups.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="status">No groups yet. Click "Create group" to add one.</td></tr>';
    return;
  }
  tbody.innerHTML = adminAllGroups.map(grp => `
    <tr>
      <td><code>${escapeHtml(grp.name)}</code>${grp.notify_on_new ? ' <span class="pill" style="background:#f59e0b;color:white" title="Members are notified when new CSRs are created">signer</span>' : ''}</td>
      <td>${escapeHtml(grp.description || "")}</td>
      <td>${grp.email ? `<code>${escapeHtml(grp.email)}</code>` : '<span class="status">—</span>'}</td>
      <td>${grp.member_count}</td>
      <td>${grp.job_count}</td>
      <td>
        <button class="link-btn admin-group-edit-btn" data-id="${grp.id}">Edit</button>
        &nbsp;&middot;&nbsp;
        <button class="link-btn admin-group-del-btn" data-id="${grp.id}" data-name="${escapeHtml(grp.name)}" style="color:var(--danger)">Delete</button>
      </td>
    </tr>
  `).join("");

  tbody.querySelectorAll(".admin-group-edit-btn").forEach(b => {
    b.addEventListener("click", () => {
      const grp = adminAllGroups.find(g => g.id == b.dataset.id);
      openGroupEdit(grp);
    });
  });
  tbody.querySelectorAll(".admin-group-del-btn").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm(
        `Delete group "${b.dataset.name}"?\n\n` +
        `Any jobs currently assigned to this group will have their group cleared ` +
        `(jobs themselves are kept). Memberships are removed.`
      )) return;
      const r = await jsonReq("/admin/groups/" + b.dataset.id, { method: "DELETE" });
      if (r.ok) { refreshAdminGroups(); loadMyGroups(); }
      else alert("Delete failed: " + ((r.body && r.body.error) || "unknown"));
    });
  });
}

document.getElementById("admin-groups-refresh")
  ?.addEventListener("click", refreshAdminGroups);

document.getElementById("admin-group-create-btn")
  ?.addEventListener("click", () => openGroupEdit(null));

function openGroupEdit(grp) {
  // grp = null means create-new
  const modal = document.getElementById("group-edit-modal");
  document.getElementById("group-edit-title").textContent =
    grp ? `Edit group: ${grp.name}` : "Create group";
  document.getElementById("group-edit-name").value = grp ? grp.name : "";
  document.getElementById("group-edit-desc").value = grp ? (grp.description || "") : "";
  document.getElementById("group-edit-email").value = grp ? (grp.email || "") : "";
  document.getElementById("group-edit-notify-new").checked = grp ? !!grp.notify_on_new : false;
  modal.dataset.groupId = grp ? grp.id : "";
  setStatus(document.getElementById("group-edit-status"), "");

  const divider = document.getElementById("group-members-divider");
  const section = document.getElementById("group-members-section");
  if (grp) {
    divider.hidden = false; section.hidden = false;
    refreshGroupMembers(grp.id);
    loadAddMemberCandidates(grp.id);
  } else {
    divider.hidden = true; section.hidden = true;
  }

  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== "group-edit-modal"); });
  overlay.hidden = false;
}

document.getElementById("group-edit-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("group-edit-status");
  const modal = document.getElementById("group-edit-modal");
  const groupId = modal.dataset.groupId;
  const name = document.getElementById("group-edit-name").value.trim();
  const description = document.getElementById("group-edit-desc").value.trim();
  const email = document.getElementById("group-edit-email").value.trim();
  const notifyOnNew = document.getElementById("group-edit-notify-new").checked;
  setStatus(status, "Saving…");

  let r;
  if (groupId) {
    r = await jsonReq("/admin/groups/" + groupId, {
      method: "PUT",
      body: JSON.stringify({ name, description, email: email || null, notify_on_new: notifyOnNew }),
    });
  } else {
    r = await jsonReq("/admin/groups", {
      method: "POST",
      body: JSON.stringify({ name, description, email: email || null, notify_on_new: notifyOnNew }),
    });
  }
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
    return;
  }
  setStatus(status, "Saved", "ok");
  // If we just created the group, switch the modal into edit mode
  // so the user can add members without reopening it.
  if (!groupId && r.body.id) {
    modal.dataset.groupId = r.body.id;
    document.getElementById("group-edit-title").textContent =
      `Edit group: ${r.body.name}`;
    document.getElementById("group-members-divider").hidden = false;
    document.getElementById("group-members-section").hidden = false;
    refreshGroupMembers(r.body.id);
    loadAddMemberCandidates(r.body.id);
  }
  refreshAdminGroups();
  loadMyGroups();
});

async function refreshGroupMembers(groupId) {
  const tbody = document.getElementById("group-members-tbody");
  tbody.innerHTML = '<tr><td colspan="4" class="status">Loading…</td></tr>';
  const r = await jsonReq("/admin/groups/" + groupId + "/members");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="4" class="status err">Failed to load</td></tr>';
    return;
  }
  const members = r.body.members || [];
  if (!members.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="status">No members yet.</td></tr>';
    return;
  }
  tbody.innerHTML = members.map(m => `
    <tr>
      <td title="${escapeHtml(m.dn)}"><code>${escapeHtml(m.cn || shortDN(m.dn))}</code>
        ${m.role === "owner" ? ' <span class="pill" style="background:#10b981;color:white">owner</span>' : ""}</td>
      <td>${m.email ? `<code>${escapeHtml(m.email)}</code>` : '<em>—</em>'}</td>
      <td>${fmtRelTime(m.added_at)}</td>
      <td>
        <button class="link-btn group-member-role-btn" data-dn="${escapeHtml(m.dn)}"
                data-role="${m.role === "owner" ? "member" : "owner"}">
          ${m.role === "owner" ? "Revoke owner" : "Make owner"}</button>
        <button class="link-btn group-member-remove-btn" data-dn="${escapeHtml(m.dn)}" style="color:var(--danger)">Remove</button>
      </td>
    </tr>
  `).join("");
  tbody.querySelectorAll(".group-member-role-btn").forEach(b => {
    b.addEventListener("click", async () => {
      const r2 = await jsonReq("/admin/groups/" + groupId + "/members/role", {
        method: "PUT",
        body: JSON.stringify({ dn: b.dataset.dn, role: b.dataset.role }),
      });
      if (r2.ok) refreshGroupMembers(groupId);
      else alert("Role change failed: " + ((r2.body && r2.body.error) || "unknown"));
    });
  });
  tbody.querySelectorAll(".group-member-remove-btn").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm("Remove this user from the group?")) return;
      const r2 = await jsonReq("/admin/groups/" + groupId + "/members", {
        method: "DELETE",
        body: JSON.stringify({ dn: b.dataset.dn }),
      });
      if (r2.ok) { refreshGroupMembers(groupId); refreshAdminGroups(); loadAddMemberCandidates(groupId); }
      else alert("Remove failed: " + ((r2.body && r2.body.error) || "unknown"));
    });
  });
}

async function loadAddMemberCandidates(groupId) {
  // Show users not yet in the group
  const allR = await jsonReq("/admin/users");
  const memR = await jsonReq("/admin/groups/" + groupId + "/members");
  if (!allR.ok || !memR.ok) return;
  const memberDns = new Set((memR.body.members || []).map(m => m.dn));
  const candidates = (allR.body.users || []).filter(u => !memberDns.has(u.dn) && u.is_active);
  const sel = document.getElementById("group-add-member-select");
  sel.innerHTML = '<option value="">— select a user —</option>' +
    candidates.map(u => `<option value="${escapeHtml(u.dn)}">${escapeHtml(u.cn || shortDN(u.dn))}${u.email ? " — " + escapeHtml(u.email) : ""}</option>`).join("");
}

document.getElementById("group-add-member-btn")?.addEventListener("click", async () => {
  const sel = document.getElementById("group-add-member-select");
  const dn = sel.value;
  if (!dn) return;
  const modal = document.getElementById("group-edit-modal");
  const groupId = modal.dataset.groupId;
  if (!groupId) return;
  const r = await jsonReq("/admin/groups/" + groupId + "/members", {
    method: "POST",
    body: JSON.stringify({ dn }),
  });
  if (r.ok) {
    refreshGroupMembers(groupId);
    refreshAdminGroups();
    loadAddMemberCandidates(groupId);
  } else {
    alert("Add failed: " + ((r.body && r.body.error) || "unknown"));
  }
});

// Tie groups into the admin modal map
allModalIds.push("group-edit-modal");

// ============================================================
// User Feedback
// ============================================================
allModalIds.push("feedback-modal", "feedback-detail-modal");

document.getElementById("nav-feedback").addEventListener("click", () => {
  document.getElementById("feedback-category").value = "general";
  document.getElementById("feedback-message").value = "";
  setStatus(document.getElementById("feedback-status"), "");
  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== "feedback-modal"); });
  overlay.hidden = false;
  setTimeout(() => document.getElementById("feedback-message").focus(), 50);
});

document.getElementById("feedback-submit-btn").addEventListener("click", async () => {
  const status = document.getElementById("feedback-status");
  const category = document.getElementById("feedback-category").value;
  const message = document.getElementById("feedback-message").value.trim();
  if (!message) {
    setStatus(status, "Message is required.", "err");
    return;
  }
  setStatus(status, "Submitting…");
  const r = await jsonReq("/feedback", {
    method: "POST",
    body: JSON.stringify({ category, message }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Submit failed", "err");
    return;
  }
  setStatus(status, "Thanks — your feedback was sent to the admins.", "ok");
  setTimeout(() => { closeModal(); }, 1500);
});

// Admin feedback list
let adminFeedback = [];
let openFeedbackId = null;

async function refreshAdminFeedback() {
  const tbody = document.getElementById("admin-feedback-tbody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="status">Loading…</td></tr>';
  const filter = document.getElementById("admin-feedback-filter").value;
  const r = await jsonReq("/admin/feedback?status=" + encodeURIComponent(filter));
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="6" class="status err">Failed to load</td></tr>';
    return;
  }
  adminFeedback = r.body.feedback || [];
  if (!adminFeedback.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="status">No feedback matches this filter.</td></tr>';
    return;
  }
  tbody.innerHTML = adminFeedback.map(fb => `
    <tr>
      <td title="${fmtTime(fb.submitted_at)}">${fmtRelTime(fb.submitted_at)}</td>
      <td title="${escapeHtml(fb.user_dn)}">${escapeHtml(fb.user_cn || shortDN(fb.user_dn))}${fb.user_email ? `<br><span class="status">${escapeHtml(fb.user_email)}</span>` : ''}</td>
      <td><span class="pill pill-blue">${escapeHtml(fb.category)}</span></td>
      <td>${escapeHtml((fb.message || '').substring(0, 100))}${fb.message.length > 100 ? '…' : ''}</td>
      <td>${feedbackStatusPill(fb.status)}</td>
      <td><button class="link-btn admin-feedback-open-btn" data-id="${fb.id}">Open</button></td>
    </tr>
  `).join("");
  tbody.querySelectorAll(".admin-feedback-open-btn").forEach(b => {
    b.addEventListener("click", () => openFeedbackDetail(parseInt(b.dataset.id, 10)));
  });
}

function feedbackStatusPill(status) {
  if (status === "new") return '<span class="pill" style="background:#7c3aed; color:white">new</span>';
  if (status === "read") return '<span class="pill" style="background:#f59e0b; color:white">read</span>';
  if (status === "resolved") return '<span class="pill" style="background:#10b981; color:white">resolved</span>';
  return `<span class="pill">${escapeHtml(status)}</span>`;
}

function openFeedbackDetail(id) {
  const fb = adminFeedback.find(f => f.id === id);
  if (!fb) return;
  openFeedbackId = id;
  document.getElementById("feedback-detail-title").textContent = `Feedback #${id}`;
  document.getElementById("feedback-detail-from").innerHTML =
    `<code>${escapeHtml(fb.user_cn || shortDN(fb.user_dn))}</code>` +
    (fb.user_email ? ` &lt;${escapeHtml(fb.user_email)}&gt;` : '');
  document.getElementById("feedback-detail-submitted").textContent = fmtTime(fb.submitted_at);
  document.getElementById("feedback-detail-category").innerHTML = `<span class="pill pill-blue">${escapeHtml(fb.category)}</span>`;
  document.getElementById("feedback-detail-status").innerHTML = feedbackStatusPill(fb.status);
  document.getElementById("feedback-detail-message").textContent = fb.message;
  document.getElementById("feedback-detail-notes").value = fb.resolution_notes || "";
  setStatus(document.getElementById("feedback-detail-status-msg"), "");
  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== "feedback-detail-modal"); });
  overlay.hidden = false;

  // Auto-mark as read on open if currently new
  if (fb.status === "new") {
    jsonReq("/admin/feedback/" + id, {
      method: "PUT", body: JSON.stringify({ status: "read" }),
    }).then(r => { if (r.ok) { fb.status = "read"; document.getElementById("feedback-detail-status").innerHTML = feedbackStatusPill("read"); refreshAdminFeedback(); refreshAdminStats(); } });
  }
}

document.getElementById("admin-feedback-filter").addEventListener("change", refreshAdminFeedback);
document.getElementById("admin-feedback-refresh").addEventListener("click", refreshAdminFeedback);

document.getElementById("feedback-mark-read-btn").addEventListener("click", async () => {
  if (!openFeedbackId) return;
  const notes = document.getElementById("feedback-detail-notes").value;
  const r = await jsonReq("/admin/feedback/" + openFeedbackId, {
    method: "PUT",
    body: JSON.stringify({ status: "read", resolution_notes: notes || null }),
  });
  if (r.ok) {
    setStatus(document.getElementById("feedback-detail-status-msg"), "Marked read", "ok");
    refreshAdminFeedback();
    refreshAdminStats();
  }
});

document.getElementById("feedback-mark-resolved-btn").addEventListener("click", async () => {
  if (!openFeedbackId) return;
  const notes = document.getElementById("feedback-detail-notes").value;
  const r = await jsonReq("/admin/feedback/" + openFeedbackId, {
    method: "PUT",
    body: JSON.stringify({ status: "resolved", resolution_notes: notes || null }),
  });
  if (r.ok) {
    setStatus(document.getElementById("feedback-detail-status-msg"), "Marked resolved", "ok");
    setTimeout(() => { closeModal(); refreshAdminFeedback(); refreshAdminStats(); }, 800);
  }
});

document.getElementById("feedback-delete-btn").addEventListener("click", async () => {
  if (!openFeedbackId) return;
  if (!confirm("Delete this feedback permanently? The submitter won't be notified.")) return;
  const r = await jsonReq("/admin/feedback/" + openFeedbackId, { method: "DELETE" });
  if (r.ok) {
    closeModal();
    refreshAdminFeedback();
    refreshAdminStats();
  }
});

// Update the admin-feedback badge after stats refresh
function updateFeedbackBadge(newCount) {
  const badge = document.getElementById("nav-admin-badge");
  if (!badge) return;
  if (newCount > 0) {
    badge.textContent = newCount;
    badge.hidden = false;
  } else {
    badge.hidden = true;
  }
}

// Hook into refreshAdminStats response. We need to extend its behavior.
const _origRefreshAdminStats = refreshAdminStats;
refreshAdminStats = async function () {
  const r = await jsonReq("/admin/stats");
  if (!r.ok) return _origRefreshAdminStats();
  // Re-do the normal render
  await _origRefreshAdminStats();
  // Plus update the feedback badge
  const fb = (r.body && r.body.feedback) || {};
  updateFeedbackBadge(fb.new || 0);
};

// Tie feedback refresh into the admin view
const _origRefreshAdminView2 = refreshAdminView;
refreshAdminView = async function () {
  await _origRefreshAdminView2();
  await refreshAdminFeedback();
};

// Also keep the badge fresh even when the admin tab isn't open.
// Poll on a long interval so it doesn't add load.
async function pollFeedbackBadge() {
  if (!currentUser?.is_admin) return;
  const r = await jsonReq("/admin/stats");
  if (r.ok) {
    const fb = (r.body && r.body.feedback) || {};
    updateFeedbackBadge(fb.new || 0);
  }
}

// ============================================================
// Admin: Webhooks
// ============================================================
allModalIds.push("webhook-edit-modal");

let adminWebhooks = [];
let webhookAvailableEvents = [];

async function refreshAdminWebhooks() {
  const tbody = document.getElementById("admin-webhooks-tbody");
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="status">Loading…</td></tr>';
  const r = await jsonReq("/admin/webhooks");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="6" class="status err">Failed to load</td></tr>';
    return;
  }
  adminWebhooks = r.body.webhooks || [];
  webhookAvailableEvents = r.body.available_events || [];
  if (!adminWebhooks.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="status">No webhooks configured. Click "Add webhook" to create one.</td></tr>';
    return;
  }
  tbody.innerHTML = adminWebhooks.map(wh => {
    const lastCall = wh.last_called_at
      ? `${fmtRelTime(wh.last_called_at)} (${wh.last_status_code || '?'}${wh.last_error ? ' err' : ''})`
      : '<span class="status">—</span>';
    const lastTitle = wh.last_error || `HTTP ${wh.last_status_code || '?'}`;
    return `
      <tr>
        <td><code>${escapeHtml(wh.name)}</code></td>
        <td><code style="font-size:11px">${escapeHtml(wh.url.length > 60 ? wh.url.substring(0, 60) + '…' : wh.url)}</code></td>
        <td>${(wh.events || []).map(e => `<span class="pill pill-blue">${escapeHtml(e)}</span>`).join(' ')}</td>
        <td>${wh.enabled ? '<span class="pill" style="background:#10b981;color:white">on</span>' : '<span class="pill" style="background:#6b7280;color:white">off</span>'}</td>
        <td title="${escapeHtml(lastTitle)}">${lastCall} <span class="status">(${wh.call_count} total)</span></td>
        <td>
          <button class="link-btn admin-webhook-edit-btn" data-id="${wh.id}">Edit</button>
          &nbsp;&middot;&nbsp;
          <button class="link-btn admin-webhook-del-btn" data-id="${wh.id}" data-name="${escapeHtml(wh.name)}" style="color:var(--danger)">Delete</button>
        </td>
      </tr>
    `;
  }).join("");
  tbody.querySelectorAll(".admin-webhook-edit-btn").forEach(b => {
    b.addEventListener("click", () => {
      const wh = adminWebhooks.find(w => w.id == b.dataset.id);
      openWebhookEdit(wh);
    });
  });
  tbody.querySelectorAll(".admin-webhook-del-btn").forEach(b => {
    b.addEventListener("click", async () => {
      if (!confirm(`Delete webhook "${b.dataset.name}"?`)) return;
      const r = await jsonReq("/admin/webhooks/" + b.dataset.id, { method: "DELETE" });
      if (r.ok) refreshAdminWebhooks();
      else alert("Delete failed: " + ((r.body && r.body.error) || "unknown"));
    });
  });
}

document.getElementById("admin-webhooks-refresh")?.addEventListener("click", refreshAdminWebhooks);
document.getElementById("admin-webhook-create-btn")?.addEventListener("click", () => openWebhookEdit(null));

function openWebhookEdit(wh) {
  const modal = document.getElementById("webhook-edit-modal");
  document.getElementById("webhook-edit-title").textContent =
    wh ? `Edit webhook: ${wh.name}` : "Add webhook";
  document.getElementById("webhook-edit-name").value = wh ? wh.name : "";
  document.getElementById("webhook-edit-url").value = wh ? wh.url : "";
  document.getElementById("webhook-edit-enabled").checked = wh ? wh.enabled : true;
  modal.dataset.webhookId = wh ? wh.id : "";
  setStatus(document.getElementById("webhook-edit-status"), "");

  // Events checkboxes
  const events = (wh && wh.events) || [];
  const evDiv = document.getElementById("webhook-edit-events");
  evDiv.innerHTML = webhookAvailableEvents.map(ev => `
    <label style="display:flex; gap:6px; align-items:center; cursor:pointer">
      <input type="checkbox" class="webhook-event-cb" value="${escapeHtml(ev)}" ${events.includes(ev) ? 'checked' : ''}>
      <code>${escapeHtml(ev)}</code>
    </label>
  `).join("");

  // Headers (start with existing or one blank row)
  const headers = (wh && wh.headers) || {};
  const hDiv = document.getElementById("webhook-edit-headers");
  hDiv.innerHTML = "";
  const entries = Object.entries(headers);
  if (entries.length === 0) {
    addWebhookHeaderRow("", "");
  } else {
    entries.forEach(([k, v]) => addWebhookHeaderRow(k, v));
  }

  // Hide test button for unsaved (no id yet)
  document.getElementById("webhook-edit-test-btn").disabled = !wh;
  document.getElementById("webhook-edit-test-btn").title = wh
    ? "Send a synchronous test POST and show the result"
    : "Save first, then you can test";

  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== "webhook-edit-modal"); });
  overlay.hidden = false;
}

function addWebhookHeaderRow(k, v) {
  const hDiv = document.getElementById("webhook-edit-headers");
  const row = document.createElement("div");
  row.className = "row";
  row.style.cssText = "gap:6px; margin-bottom:4px";
  row.innerHTML = `
    <input type="text" class="form-input webhook-header-key" placeholder="Header-Name" value="${escapeHtml(k)}" style="flex:1">
    <input type="text" class="form-input webhook-header-value" placeholder="value" value="${escapeHtml(v)}" style="flex:2">
    <button class="link-btn webhook-header-remove" type="button" style="color:var(--danger); padding:0 8px">×</button>
  `;
  row.querySelector(".webhook-header-remove").addEventListener("click", () => row.remove());
  hDiv.appendChild(row);
}

document.getElementById("webhook-edit-add-header-btn")?.addEventListener("click", () => addWebhookHeaderRow("", ""));

function collectWebhookFormState() {
  const events = Array.from(document.querySelectorAll(".webhook-event-cb"))
    .filter(cb => cb.checked).map(cb => cb.value);

  const headers = {};
  document.querySelectorAll("#webhook-edit-headers .row").forEach(row => {
    const k = row.querySelector(".webhook-header-key").value.trim();
    const v = row.querySelector(".webhook-header-value").value;
    if (k) headers[k] = v;
  });

  return {
    name: document.getElementById("webhook-edit-name").value.trim(),
    url: document.getElementById("webhook-edit-url").value.trim(),
    events,
    headers,
    enabled: document.getElementById("webhook-edit-enabled").checked,
  };
}

document.getElementById("webhook-edit-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("webhook-edit-status");
  const modal = document.getElementById("webhook-edit-modal");
  const webhookId = modal.dataset.webhookId;
  const state = collectWebhookFormState();

  if (!state.name) { setStatus(status, "Name is required", "err"); return; }
  if (!state.url) { setStatus(status, "URL is required", "err"); return; }
  if (state.events.length === 0) { setStatus(status, "Select at least one event", "err"); return; }

  setStatus(status, "Saving…");
  let r;
  if (webhookId) {
    r = await jsonReq("/admin/webhooks/" + webhookId, {
      method: "PUT", body: JSON.stringify(state),
    });
  } else {
    r = await jsonReq("/admin/webhooks", {
      method: "POST", body: JSON.stringify(state),
    });
  }
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
    return;
  }
  setStatus(status, "Saved", "ok");

  if (!webhookId && r.body.id) {
    modal.dataset.webhookId = r.body.id;
    document.getElementById("webhook-edit-title").textContent = `Edit webhook: ${state.name}`;
    document.getElementById("webhook-edit-test-btn").disabled = false;
    document.getElementById("webhook-edit-test-btn").title =
      "Send a synchronous test POST and show the result";
  }
  refreshAdminWebhooks();
});

document.getElementById("webhook-edit-test-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("webhook-edit-status");
  const modal = document.getElementById("webhook-edit-modal");
  const webhookId = modal.dataset.webhookId;
  if (!webhookId) {
    setStatus(status, "Save the webhook first, then you can test it", "err");
    return;
  }
  setStatus(status, "Sending test…");
  const r = await jsonReq("/admin/webhooks/" + webhookId + "/test", { method: "POST" });
  if (r.ok && r.body.ok) {
    setStatus(status, `Test sent — HTTP ${r.body.status_code}`, "ok");
  } else {
    const code = r.body && r.body.status_code;
    const err = r.body && (r.body.error || "unknown");
    setStatus(status, `Test failed: HTTP ${code || '?'} — ${err}`, "err");
  }
  refreshAdminWebhooks();
});

// Tie into admin refresh
const _origRefreshAdminView3 = refreshAdminView;
refreshAdminView = async function () {
  await _origRefreshAdminView3();
  await refreshAdminWebhooks();
};

// ============================================================
// Tutorial walkthrough
// ============================================================
const TUTORIAL_STEPS = [
  {
    target: null,
    title: "Welcome to the CSR Dashboard",
    body: "This quick tour shows you the key parts of the page — creating requests with templates, tracking jobs, and where to get help. Replay it anytime from the Tour link in the header.",
  },
  {
    target: "#certlist-section",
    title: "Stage your CSR requests",
    body: "One row per certificate — add as many requests as you need and they all generate in a single batch. Short names get the domain added automatically (test → test.eucom.mil), and IPs in the SANs field are detected and encoded correctly.",
    position: "right",
  },
  {
    target: "#generate-template",
    title: "Pick a certificate template",
    body: "The template determines the certificate's usages. The Standard set uses the same names as the Windows CA console (Web Server, Computer, User…), so pick the one you'd pick there — the line below the dropdown previews exactly what will be requested.",
    position: "bottom",
  },
  {
    target: '#main-panels [data-panel="usertemplates"]',
    title: "Make your own templates",
    body: "Need a combination that isn't in the standard set? Create a personal template here and it appears in your Generate dropdown. Group owners can also publish templates to their whole group.",
    position: "right",
  },
  {
    target: "#generate-btn",
    title: "Generate CSRs",
    body: "Creates a key and CSR for every certlist entry. RSA 2048 is the default key — pick a stronger RSA or ECDSA option when a system calls for it. Set a notification email to get a message when your cert is issued, and assign a group if your team should share access to the private key.",
    position: "top",
  },
  {
    target: "#submit-external-btn",
    title: "Or paste an external CSR",
    body: "Already have a CSR from another system (Windows IIS, an appliance, OpenSSL elsewhere)? Bring it in here for tracking and signing alongside everything else.",
    position: "bottom",
  },
  {
    target: "#jobs-tbody",
    title: "Track and complete jobs",
    body: "Click Details on any row to view or download the CSR, upload the signed certificate back, or assign it to a group after the fact. Checkboxes appear on your own pending requests — select several and cancel them in one action.",
    position: "top",
  },
  {
    target: "#filter-expiring-btn",
    title: "Certificates have a lifecycle",
    body: "Issued certs are tracked to their expiry date: warning emails go out automatically at 30, 14, and 7 days, this toggle filters to anything expiring within 60 days, and a Renew button inside each issued job regenerates the same request in one click. Export CSV gives you the current view for reporting.",
    position: "bottom",
  },
  {
    target: '#main-panels [data-panel="fleet"]',
    title: "Fleet certificates",
    body: "Certs discovered on our servers by the weekly scan — including ones that were never requested through this dashboard. They get the same expiry warnings, and Renew here pre-fills a new request with the same names and usages. Identical certs deployed in several places are grouped into one row.",
    position: "right",
  },
  {
    target: '#main-panels [data-panel="mygroups"]',
    title: "Your groups",
    body: "Groups share access to private keys and get copied on notifications. If you're a group owner, you can add and remove members right here — and owners are always copied on expiry warnings for their group's certs.",
    position: "right",
  },
  {
    target: "#nav-feedback",
    title: "Found a bug? Want a feature?",
    body: "Send feedback straight to the dashboard admins from here — bug reports, feature requests, or general comments. The admins are notified by email when something comes in.",
    position: "bottom",
  },
  {
    target: "#nav-settings",
    title: "Set your defaults",
    body: "Save your email once and every Generate and External Submit pre-fills it. And if you ever want to see this tour again, the Tour link is right next door.",
    position: "bottom",
  },
];

let tutorialIdx = 0;

function showTutorial() {
  tutorialIdx = 0;
  renderTutorialStep();
  document.getElementById("tutorial-overlay").hidden = false;
  document.getElementById("tutorial-tooltip").hidden = false;
}

function endTutorial(dismiss) {
  // Remove the spotlight class from any previously highlighted element
  document.querySelectorAll(".tutorial-spotlight").forEach(el => el.classList.remove("tutorial-spotlight"));
  document.getElementById("tutorial-overlay").hidden = true;
  document.getElementById("tutorial-tooltip").hidden = true;
  if (dismiss) {
    jsonReq("/me/prefs", {
      method: "PUT",
      body: JSON.stringify({ tutorial_dismissed: true }),
    }).then(r => {
      if (r.ok && currentUser) currentUser.tutorial_dismissed = true;
    });
  }
}

function renderTutorialStep() {
  // Clear previous spotlight
  document.querySelectorAll(".tutorial-spotlight").forEach(el => el.classList.remove("tutorial-spotlight"));

  const step = TUTORIAL_STEPS[tutorialIdx];
  document.getElementById("tutorial-step-title").textContent = step.title;
  document.getElementById("tutorial-step-body").textContent = step.body;
  document.getElementById("tutorial-progress").textContent =
    `Step ${tutorialIdx + 1} of ${TUTORIAL_STEPS.length}`;

  const prevBtn = document.getElementById("tutorial-prev-btn");
  const nextBtn = document.getElementById("tutorial-next-btn");
  prevBtn.disabled = (tutorialIdx === 0);
  nextBtn.textContent = (tutorialIdx === TUTORIAL_STEPS.length - 1) ? "Finish" : "Next";

  const tooltip = document.getElementById("tutorial-tooltip");

  if (step.target) {
    const targetEl = document.querySelector(step.target);
    if (targetEl) {
      // Activate the side-nav panel the target lives in (dashboard or admin)
      const panelEl = targetEl.closest("[data-panel]");
      if (panelEl) {
        if (panelEl.closest("#admin-panels")) showAdminPanel(panelEl.dataset.panel);
        else if (panelEl.closest("#main-panels")) showMainPanel(panelEl.dataset.panel);
      }
      // If the target lives inside collapsed <details> (e.g. the certlist
      // editor), expand them so the highlight is actually visible.
      let det = targetEl.closest("details");
      while (det) {
        det.open = true;
        det = det.parentElement ? det.parentElement.closest("details") : null;
      }
      // Make sure target is in viewport
      targetEl.scrollIntoView({ behavior: "smooth", block: "center" });
      // Wait a tick for scroll to settle, then highlight + position
      setTimeout(() => {
        targetEl.classList.add("tutorial-spotlight");
        positionTooltip(tooltip, targetEl, step.position || "bottom");
      }, 200);
      return;
    }
  }

  // Centered (welcome / fallback)
  tooltip.style.top = "50%";
  tooltip.style.left = "50%";
  tooltip.style.transform = "translate(-50%, -50%)";
}

function positionTooltip(tooltip, target, position) {
  const rect = target.getBoundingClientRect();
  tooltip.style.transform = "none";
  const tipW = tooltip.offsetWidth;
  const tipH = tooltip.offsetHeight;
  const pad = 16;
  let top, left;

  switch (position) {
    case "top":
      top = rect.top - tipH - pad;
      left = rect.left + (rect.width / 2) - (tipW / 2);
      break;
    case "right":
      top = rect.top + (rect.height / 2) - (tipH / 2);
      left = rect.right + pad;
      break;
    case "left":
      top = rect.top + (rect.height / 2) - (tipH / 2);
      left = rect.left - tipW - pad;
      break;
    case "bottom":
    default:
      top = rect.bottom + pad;
      left = rect.left + (rect.width / 2) - (tipW / 2);
      break;
  }

  // Clamp to viewport
  top = Math.max(pad, Math.min(window.innerHeight - tipH - pad, top));
  left = Math.max(pad, Math.min(window.innerWidth - tipW - pad, left));

  tooltip.style.top = top + "px";
  tooltip.style.left = left + "px";
}

document.getElementById("tutorial-next-btn").addEventListener("click", () => {
  if (tutorialIdx < TUTORIAL_STEPS.length - 1) {
    tutorialIdx++;
    renderTutorialStep();
  } else {
    const dismiss = document.getElementById("tutorial-dismiss-check").checked;
    endTutorial(dismiss);
  }
});

document.getElementById("tutorial-prev-btn").addEventListener("click", () => {
  if (tutorialIdx > 0) {
    tutorialIdx--;
    renderTutorialStep();
  }
});

document.getElementById("tutorial-skip-btn").addEventListener("click", () => {
  const dismiss = document.getElementById("tutorial-dismiss-check").checked;
  endTutorial(dismiss);
});

document.getElementById("nav-tour").addEventListener("click", () => {
  // Always show, even if dismissed — Tour link is the manual replay
  document.getElementById("tutorial-dismiss-check").checked = false;
  showTutorial();
});

// ===== First-login email gate =====
function showEmailGate() {
  document.getElementById("email-gate").hidden = false;
  setTimeout(() => document.getElementById("email-gate-input").focus(), 50);
}

async function saveEmailGate() {
  const status = document.getElementById("email-gate-status");
  const email = document.getElementById("email-gate-input").value.trim();
  if (!email) {
    setStatus(status, "An email address is required to use the dashboard.", "err");
    return;
  }
  setStatus(status, "Saving…");
  const r = await jsonReq("/me/prefs", {
    method: "PUT",
    body: JSON.stringify({ email }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
    return;
  }
  currentUser.email = r.body.email || email;
  const notifyEl = document.getElementById("notify-email");
  if (notifyEl && !notifyEl.value) notifyEl.value = currentUser.email;
  document.getElementById("email-gate").hidden = true;
  // Now that the gate has cleared, run the first-login tour if applicable
  if (currentUser && !currentUser.tutorial_dismissed) {
    setTimeout(showTutorial, 400);
  }
}

document.getElementById("email-gate-save-btn")?.addEventListener("click", saveEmailGate);
document.getElementById("email-gate-input")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") saveEmailGate();
});

// Auto-show on first login if not dismissed.
// Wired into init() via a small hook below.
const _origInit = init;
init = async function () {
  await _origInit();
  if (currentUser && !currentUser.email) {
    // Email gate blocks everything, including the tour. The tour runs
    // after a successful save instead (see saveEmailGate).
    showEmailGate();
  } else if (currentUser && !currentUser.tutorial_dismissed) {
    setTimeout(showTutorial, 600);
  }
  // Kick the feedback badge once on load (and every 5 min thereafter)
  if (currentUser?.is_admin) {
    pollFeedbackBadge();
    setInterval(pollFeedbackBadge, 5 * 60 * 1000);
  }
};

// ===== Cert-type templates =====
let myTemplates = [];

async function loadTemplates() {
  const r = await jsonReq("/templates");
  myTemplates = r.ok ? (r.body.templates || []) : [];
  populateTemplateDropdown();
}

function populateTemplateDropdown() {
  const sel = document.getElementById("generate-template");
  if (!sel) return;
  const current = sel.value;
  const builtin = myTemplates.filter(t => t.scope === "builtin");
  const personal = myTemplates.filter(t => t.scope === "personal");
  const byGroup = {};
  myTemplates.filter(t => t.scope === "group" && t.can_use).forEach(t => {
    (byGroup[t.group_name || ("group " + t.group_id)] ||= []).push(t);
  });

  let html = "";
  if (builtin.length) {
    html += '<optgroup label="Standard (Windows-style)">' +
      builtin.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join("") +
      '</optgroup>';
  }
  if (personal.length) {
    html += '<optgroup label="Personal">' +
      personal.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join("") +
      '</optgroup>';
  }
  for (const [gname, items] of Object.entries(byGroup)) {
    html += `<optgroup label="${escapeHtml(gname)}">` +
      items.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join("") +
      '</optgroup>';
  }
  sel.innerHTML = html;
  sel.value = current;
  if (!sel.value) {
    // Default to the Web Server template (plain "web"), else first option
    const web = myTemplates.find(t => t.scope === "builtin" && t.cert_types === "web")
             || myTemplates.find(t => t.cert_types === "web")
             || myTemplates[0];
    if (web) sel.value = String(web.id);
  }
  updateGenTypesPreview();
}

// The cert types the Generate form will use: from the selected template,
// or from a transient custom option (fleet "Renew here").
function getGenCertTypes() {
  const sel = document.getElementById("generate-template");
  if (!sel || !sel.value) return [];
  const opt = sel.selectedOptions[0];
  if (sel.value === "__custom__" && opt) {
    return (opt.dataset.types || "").split(",").filter(Boolean);
  }
  const t = myTemplates.find(x => String(x.id) === sel.value);
  return t ? t.cert_types.split(",").filter(Boolean) : [];
}

function updateGenTypesPreview() {
  const p = document.getElementById("generate-types-preview");
  if (!p) return;
  const types = getGenCertTypes();
  p.innerHTML = types.length
    ? "Will request: " + certTypePill(types.join(","))
    : "Select a template to set the certificate's usages.";
}

// Inject a transient "custom" choice (used by fleet Renew here) carrying
// explicit cert types that don't come from a saved template.
function setGenTypesCustom(label, typesCsv) {
  const sel = document.getElementById("generate-template");
  if (!sel) return;
  sel.querySelector('option[value="__custom__"]')?.remove();
  const opt = document.createElement("option");
  opt.value = "__custom__";
  opt.textContent = label;
  opt.dataset.types = typesCsv;
  sel.prepend(opt);
  sel.value = "__custom__";
  updateGenTypesPreview();
}

document.getElementById("generate-template")?.addEventListener("change", (e) => {
  // Leaving the custom option removes it
  if (e.target.value !== "__custom__") {
    e.target.querySelector('option[value="__custom__"]')?.remove();
  }
  updateGenTypesPreview();
});

// ===== Templates panel (personal + owned-group templates) =====
async function refreshUserTemplates() {
  const tbody = document.getElementById("user-templates-tbody");
  if (!tbody) return;
  await loadTemplates();
  if (!myTemplates.length) {
    tbody.innerHTML = '<tr><td colspan="4" class="status">No templates visible.</td></tr>';
  } else {
    tbody.innerHTML = myTemplates.map(t => `
      <tr>
        <td><code>${escapeHtml(t.name)}</code>${t.description ? `<br><span class="status">${escapeHtml(t.description)}</span>` : ""}</td>
        <td>${certTypePill(t.cert_types)}</td>
        <td>${t.scope === "builtin"
          ? '<span class="pill" style="background:#10b981;color:white">standard</span>'
          : t.scope === "personal"
          ? '<span class="pill" style="background:#6b7280;color:white">personal</span>'
          : `<span class="pill pill-blue">${escapeHtml(t.group_name || "group")}</span>`}</td>
        <td>${t.can_edit
          ? `<button class="link-btn user-template-del" data-id="${t.id}" data-name="${escapeHtml(t.name)}" style="color:var(--danger)">Delete</button>`
          : ""}</td>
      </tr>`).join("");
    tbody.querySelectorAll(".user-template-del").forEach(b => {
      b.addEventListener("click", async () => {
        if (!confirm(`Delete template "${b.dataset.name}"?`)) return;
        const r = await jsonReq("/templates/" + b.dataset.id, { method: "DELETE" });
        if (r.ok) refreshUserTemplates();
        else alert("Delete failed: " + ((r.body && r.body.error) || "unknown"));
      });
    });
  }
  // Scope: Personal + groups the user OWNS (admins additionally manage
  // group/instance templates from the Admin panel)
  const sel = document.getElementById("user-template-scope");
  if (sel) {
    const current = sel.value;
    const gr = await jsonReq("/my-groups");
    const owned = gr.ok ? (gr.body.groups || []).filter(x => x.role === "owner") : [];
    sel.innerHTML = '<option value="" selected>Personal (only me)</option>' +
      owned.map(grp => `<option value="${grp.id}">Group: ${escapeHtml(grp.name)} (owner)</option>`).join("");
    if ([...sel.options].some(o => o.value === current)) sel.value = current;
  }
}

document.getElementById("user-templates-refresh")?.addEventListener("click", refreshUserTemplates);
document.querySelector('#main-nav button[data-panel="usertemplates"]')
  ?.addEventListener("click", refreshUserTemplates);

document.getElementById("user-template-create-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("user-template-status");
  const name = document.getElementById("user-template-name").value.trim();
  const description = document.getElementById("user-template-desc").value.trim();
  const scopeVal = document.getElementById("user-template-scope").value;
  const certTypes = getCertTypes("user-template-cert-types");
  if (!name) { setStatus(status, "Name is required.", "err"); return; }
  if (!certTypes.length) { setStatus(status, "Check at least one cert type.", "err"); return; }
  setStatus(status, "Creating…");
  const payload = { name, description, cert_types: certTypes };
  if (scopeVal) payload.group_id = parseInt(scopeVal, 10);
  const r = await jsonReq("/templates", { method: "POST", body: JSON.stringify(payload) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Create failed", "err"); return; }
  setStatus(status, "Created", "ok");
  document.getElementById("user-template-name").value = "";
  document.getElementById("user-template-desc").value = "";
  resetCertTypes("user-template-cert-types", []);
  refreshUserTemplates();
});

if (accepted) init();
