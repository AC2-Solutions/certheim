// ===== Admin view =====
async function refreshAdminView() {
  await loadCapabilities();   // first, so the other loaders can consult it
  await Promise.all([
    refreshAdminStats(),
    refreshAdminUsers(),
    refreshAdminGroups(),
    refreshOrphanKeys(),
    refreshOrphanCerts(),
    loadEmailConfig(),
    refreshAdminTemplates(),
    loadSigningConfig(),
    loadCsrSubject(),
  ]);
}

// ===== Capabilities (what THIS deployment can actually do) =====
// available(cap) = entitled (license) AND env_supports (e.g. internet egress).
// We surface the reason so the admin UI self-explains per deployment instead of
// offering things that can't work here.
let _capCache = null;
async function loadCapabilities() {
  const r = await jsonReq("/admin/capabilities");
  _capCache = (r.ok && r.body && r.body.capabilities) ? r.body.capabilities : {};
  applyCapabilityHints();
}
function capAvail(key) {
  return !_capCache || !_capCache[key] || _capCache[key].available;
}
function applyCapabilityHints() {
  const note = (id, key) => {
    const el = document.getElementById(id);
    if (!el) return;
    const c = _capCache && _capCache[key];
    if (c && !c.available) {
      el.textContent = "⚠ " + (c.desc || key) + " — " + c.reason;
      el.hidden = false;
    } else {
      el.hidden = true;
    }
  };
  note("cap-note-email-api", "notify.email.api");
  note("cap-note-chat", "integrations.chat");
  note("cap-note-slack", "integrations.slack.interactive");
  // Disable the HTTP email providers in the dropdown when unavailable.
  const emailApiOk = capAvail("notify.email.api");
  ["mailgun", "sendgrid"].forEach(v => {
    const opt = document.querySelector(`#email-cfg-method option[value="${v}"]`);
    if (opt) {
      opt.disabled = !emailApiOk;
      if (!emailApiOk && !/unavailable/.test(opt.textContent)) {
        opt.textContent += " (unavailable here)";
      }
    }
  });
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
    tbody.innerHTML = '<tr><td colspan="6" class="status">No templates.</td></tr>';
  } else {
    tbody.innerHTML = myTemplates.map(t => `
      <tr>
        <td><code>${escapeHtml(t.name)}</code>${t.description ? `<br><span class="status">${escapeHtml(t.description)}</span>` : ""}</td>
        <td>${certTypePill(t.cert_types)}</td>
        <td>${scopeLabel(t)}</td>
        <td class="tmpl-sign" data-id="${t.id}">${signingBadge(t)} <button class="link-btn admin-template-sign" data-id="${t.id}">Edit</button></td>
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
    tbody.querySelectorAll(".admin-template-sign").forEach(b => {
      b.addEventListener("click", () => {
        const t = myTemplates.find(x => String(x.id) === b.dataset.id);
        if (t) editTemplateSigning(b.closest(".tmpl-sign"), t);
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

// Per-template signing policy: 'manual' inherits the global Signing/CA default;
// 'openbao' uses this template's role/TTL and optional auto-sign.
function signingBadge(t) {
  if ((t.signer_backend || "manual") === "manual") {
    return '<span class="pill pill-mute">inherit</span>';
  }
  return `<span class="pill pill-ok">${escapeHtml(t.signer_backend)}</span>`
       + (t.auto_sign ? ' <span class="pill pill-purple">auto-sign</span>' : "")
       + (t.auto_renew ? ' <span class="pill pill-purple">auto-renew</span>' : "");
}

function editTemplateSigning(td, t) {
  const isOB = (t.signer_backend || "manual") !== "manual";
  td.innerHTML = `
    <select class="sig-backend form-input" style="width:auto;display:inline-block">
      <option value="manual"${!isOB ? " selected" : ""}>Inherit global</option>
      <option value="openbao"${isOB ? " selected" : ""}>OpenBao</option>
    </select>
    <span class="sig-ob"${isOB ? "" : " hidden"}>
      <input class="sig-role form-input" style="width:130px;display:inline-block"
             placeholder="role (optional)" value="${escapeHtml(t.openbao_role || "")}">
      <input class="sig-ttl form-input" type="number" min="1" style="width:90px;display:inline-block"
             placeholder="TTL s" value="${t.max_ttl || ""}">
      <label class="status" style="margin-left:4px"><input type="checkbox" class="sig-auto"${t.auto_sign ? " checked" : ""}> auto-sign</label>
      <label class="status" style="margin-left:4px"><input type="checkbox" class="sig-renew"${t.auto_renew ? " checked" : ""}> auto-renew</label>
      <input class="sig-renew-days form-input" type="number" min="1" max="365" style="width:70px;display:inline-block"
             placeholder="days" title="Days before expiry to renew (blank = global default)" value="${t.renew_before_days || ""}">
    </span>
    <button class="btn sig-save" style="padding:2px 10px">Save</button>
    <button class="link-btn sig-cancel">Cancel</button>
    <span class="sig-status status"></span>`;
  const backSel = td.querySelector(".sig-backend");
  const obWrap = td.querySelector(".sig-ob");
  backSel.addEventListener("change", () => { obWrap.hidden = backSel.value !== "openbao"; });
  td.querySelector(".sig-cancel").addEventListener("click", () => {
    td.innerHTML = `${signingBadge(t)} <button class="link-btn admin-template-sign" data-id="${t.id}">Edit</button>`;
    td.querySelector(".admin-template-sign").addEventListener("click", () => editTemplateSigning(td, t));
  });
  td.querySelector(".sig-save").addEventListener("click", async () => {
    const ttlRaw = td.querySelector(".sig-ttl").value.trim();
    const renewRaw = td.querySelector(".sig-renew-days").value.trim();
    const body = {
      signer_backend: backSel.value,
      openbao_role: td.querySelector(".sig-role").value.trim(),
      max_ttl: ttlRaw === "" ? null : parseInt(ttlRaw, 10),
      auto_sign: td.querySelector(".sig-auto").checked,
      auto_renew: td.querySelector(".sig-renew").checked,
      renew_before_days: renewRaw === "" ? null : parseInt(renewRaw, 10),
    };
    setStatus(td.querySelector(".sig-status"), "Saving…");
    const r = await jsonReq(`/admin/templates/${t.id}/signing`, {
      method: "PUT", body: JSON.stringify(body),
    });
    if (!r.ok) {
      setStatus(td.querySelector(".sig-status"), (r.body && r.body.error) || "Save failed", "err");
      return;
    }
    refreshAdminTemplates();
  });
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

document.querySelector('#admin-nav button[data-panel="authentication"]')
  ?.addEventListener("click", refreshAuthSettings);

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

// Field set per method - must match EMAIL_METHODS in notify.py. Input ids are
// `${method}-${field}`; secret fields show a "(stored)" hint instead of a value.
const EMAIL_METHOD_FIELDS = {
  smg:      ["host", "port", "timeout"],
  smtp:     ["host", "port", "timeout", "security", "username", "password"],
  mailgun:  ["api_key", "domain", "region"],
  sendgrid: ["api_key"],
};
const EMAIL_SECRET_FIELDS = new Set(["password", "api_key"]);

function _emailToggleMethod() {
  const m = document.getElementById("email-cfg-method").value;
  document.querySelectorAll(".email-method").forEach(d => {
    d.hidden = (d.dataset.emethod !== m);
  });
  const none = (m === "none");
  document.getElementById("email-none-note").hidden = !none;
  // hide the shared from/cc/url + their labels when email is off
  ["email-cfg-from", "email-cfg-cc", "email-cfg-url"].forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.hidden = none; const lbl = el.previousElementSibling;
              if (lbl && lbl.classList.contains("textarea-label")) lbl.hidden = none; }
  });
}
document.getElementById("email-cfg-method")?.addEventListener("change", _emailToggleMethod);

async function loadEmailConfig() {
  const r = await jsonReq("/admin/email-config");
  if (!r.ok) return;
  const c = r.body;
  // method dropdown
  const sel = document.getElementById("email-cfg-method");
  sel.replaceChildren(...(c.available_methods || []).map(o => {
    const opt = document.createElement("option");
    opt.value = o.key; opt.textContent = o.label; return opt;
  }));
  sel.value = c.method || "smg";
  // per-method field values (secrets come back blank with a *_set flag)
  const M = c.methods || {};
  for (const [m, vals] of Object.entries(M)) {
    for (const [f, v] of Object.entries(vals)) {
      if (f.endsWith("_set")) {
        const hint = document.getElementById(`${m}-${f.slice(0, -4)}-hint`);
        if (hint) hint.textContent = v ? "(stored — leave blank to keep)" : "(not set)";
        continue;
      }
      const el = document.getElementById(`${m}-${f}`);
      if (el) el.value = v;
    }
  }
  document.getElementById("email-cfg-from").value = c.from_address || "";
  document.getElementById("email-cfg-cc").value = c.cc || "";
  document.getElementById("email-cfg-url").value = c.dashboard_url || "";
  _emailToggleMethod();
  applyCapabilityHints();   // disable HTTP providers if unavailable here
  const state = document.getElementById("email-config-state");
  if (c.enabled) {
    state.innerHTML = '<span class="pill pill-ok">notifications enabled</span>';
  } else {
    state.innerHTML = `<span class="pill pill-err">disabled</span> <span class="status">${escapeHtml(c.disabled_reason || "")}</span>`;
  }
}

document.getElementById("email-cfg-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("email-cfg-status");
  const method = document.getElementById("email-cfg-method").value;
  const fields = {};
  (EMAIL_METHOD_FIELDS[method] || []).forEach(f => {
    const el = document.getElementById(`${method}-${f}`);
    if (el) fields[f] = el.value.trim();
  });
  setStatus(status, "Saving…");
  const r = await jsonReq("/admin/email-config", {
    method: "PUT",
    body: JSON.stringify({
      method, fields,
      from_address: document.getElementById("email-cfg-from").value.trim(),
      cc: document.getElementById("email-cfg-cc").value.trim(),
      dashboard_url: document.getElementById("email-cfg-url").value.trim(),
    }),
  });
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
  setStatus(status, `Test email sent to ${r.body.recipient || "you"}.`, "ok");
});

// ===== Admin: Signing / CA (v2 in-UI signing) =====
// Provider-driven: the backend returns a provider registry (OpenBao / CyberArk
// / …), each with its own connection fields. The dropdown picks the provider;
// its fields render dynamically so the signing "location" is changeable in-UI.
let _signingCfgCache = null;

function _signingSelectedProvider() {
  const c = _signingCfgCache;
  const key = document.getElementById("signing-cfg-backend").value;
  return (c && (c.providers || []).find(p => p.key === key)) || null;
}

// Render the selected provider's connection fields + credential/help lines.
function _signingRenderProvider() {
  const p = _signingSelectedProvider();
  const wrap = document.getElementById("signing-provider-fields");
  const hint = document.getElementById("signing-backend-hint");
  const cred = document.getElementById("signing-cred-state");
  document.getElementById("signing-ttl-wrap").hidden = !(p && p.automated);
  if (!p || !p.automated) {
    wrap.innerHTML = ""; cred.innerHTML = "";
    hint.textContent = "Manual: signers return certs via Upload Cert; the "
                     + "Approve & sign / Revoke actions stay hidden.";
    return;
  }
  hint.innerHTML = p.stub
    ? `<span class="pill pill-purple">framework</span> ${escapeHtml(p.label)} can be configured here, but its signing API isn't wired in this build yet.`
    : `Sign through ${escapeHtml(p.label)}.`;
  wrap.innerHTML = (p.fields || []).map(f => `
    <label class="textarea-label" for="sigf-${f.key}">${escapeHtml(f.label)}</label>
    <input type="text" id="sigf-${f.key}" class="form-input" data-fkey="${f.key}"
           placeholder="${escapeHtml(f.placeholder || "")}" value="${escapeHtml(f.value || "")}">`
  ).join("");
  cred.innerHTML = (p.credential_present
      ? '<span class="pill pill-ok">credential configured</span>'
      : '<span class="pill pill-err">no credential</span>')
    + (p.secret_hint ? ` <span class="status">${escapeHtml(p.secret_hint)}</span>` : "");
}
document.getElementById("signing-cfg-backend")?.addEventListener("change", _signingRenderProvider);

async function loadSigningConfig() {
  const r = await jsonReq("/admin/signing-config");
  if (!r.ok) return;
  const c = r.body;
  _signingCfgCache = c;

  // Populate the provider dropdown from the registry.
  const sel = document.getElementById("signing-cfg-backend");
  sel.innerHTML = (c.providers || []).map(p =>
    `<option value="${p.key}">${escapeHtml(p.label)}</option>`).join("");
  sel.value = c.default_backend || "manual";
  document.getElementById("signing-cfg-ttl").value = c.max_ttl || "";
  document.getElementById("signing-cfg-autorenew").checked = !!c.auto_renew_enabled;
  document.getElementById("signing-cfg-renewdays").value = c.auto_renew_before_days || 30;
  _signingRenderProvider();

  // CRL / OCSP distribution points (OpenBao; informational).
  const crlEl = document.getElementById("signing-crl-info");
  const dp = c.crl_ocsp || {};
  if (c.default_backend === "openbao" && dp.crl) {
    crlEl.innerHTML = `CRL: <code>${escapeHtml(dp.crl)}</code> &nbsp; OCSP: <code>${escapeHtml(dp.ocsp || "-")}</code>`;
    crlEl.hidden = false;
  } else {
    crlEl.hidden = true;
  }

  // Capability note for OpenBao (offline deployment / entitlement self-explains).
  const cap = c.capability || {};
  const note = document.getElementById("cap-note-signing");
  if (c.default_backend === "openbao" && cap.available === false) {
    note.textContent = "⚠ OpenBao signing unavailable here" + (cap.reason ? " — " + cap.reason : "");
    note.hidden = false;
  } else {
    note.hidden = true;
  }

  // Overall state line.
  const p = _signingSelectedProvider();
  const state = document.getElementById("signing-config-state");
  if (!p || !p.automated) {
    state.innerHTML = '<span class="pill pill-mute">manual signing</span> <span class="status">automated Approve &amp; sign is disabled</span>';
  } else if (p.stub) {
    state.innerHTML = `<span class="pill pill-purple">framework only</span> <span class="status">${escapeHtml(p.label)} signing not wired in this build</span>`;
  } else if (c.default_backend === "openbao" && cap.available === false) {
    state.innerHTML = `<span class="pill pill-err">unavailable</span> <span class="status">${escapeHtml(cap.reason || "backend not usable here")}</span>`;
  } else if (!p.credential_present) {
    state.innerHTML = '<span class="pill pill-err">not configured</span> <span class="status">provider credential missing</span>';
  } else {
    state.innerHTML = `<span class="pill pill-ok">automated signing enabled</span> <span class="status">via ${escapeHtml(p.label)}</span>`;
  }
}

document.getElementById("signing-cfg-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("signing-cfg-status");
  const ttlRaw = document.getElementById("signing-cfg-ttl").value.trim();
  const fields = {};
  document.querySelectorAll("#signing-provider-fields [data-fkey]").forEach(el => {
    fields[el.dataset.fkey] = el.value.trim();
  });
  const renewDaysRaw = document.getElementById("signing-cfg-renewdays").value.trim();
  setStatus(status, "Saving…");
  const r = await jsonReq("/admin/signing-config", {
    method: "PUT",
    body: JSON.stringify({
      default_backend: document.getElementById("signing-cfg-backend").value,
      max_ttl: ttlRaw === "" ? null : parseInt(ttlRaw, 10),
      auto_renew_enabled: document.getElementById("signing-cfg-autorenew").checked,
      auto_renew_before_days: renewDaysRaw === "" ? 30 : parseInt(renewDaysRaw, 10),
      fields,
    }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
    return;
  }
  setStatus(status, "Saved", "ok");
  loadSigningConfig();
});

document.getElementById("signing-cfg-test-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("signing-cfg-status");
  const backend = document.getElementById("signing-cfg-backend").value;
  setStatus(status, "Testing connection…");
  const r = await jsonReq("/admin/signing-config/test", {
    method: "POST", body: JSON.stringify({ backend }),
  });
  if (!r.ok || !(r.body && r.body.ok)) {
    setStatus(status, (r.body && r.body.error) || "Connection failed", "err");
    return;
  }
  setStatus(status, `OK — ${r.body.addr || "?"} (mount: ${r.body.mount || "?"})`, "ok");
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
  const roleCell = (u) =>
    u.is_admin ? '<span class="pill pill-purple">admin</span>'
               : '<span class="pill pill-mute">user</span>';
  const statusCell = (u) => {
    if (u.auth_status === "pending")
      return '<span class="pill pill-warn">pending</span>';
    if (!u.is_active)
      return '<span class="pill pill-err">inactive</span>';
    return '<span class="pill pill-ok">active</span>';
  };
  const nameCell = (u) => {
    const label = u.username ? u.username : (u.cn || shortDN(u.dn));
    return `<code title="${escapeHtml(u.dn)}">${escapeHtml(label)}</code>`;
  };
  const actionCell = (u) => {
    if (u.auth_status === "pending") {
      return `<button class="link-btn user-approve-btn" data-dn="${escapeHtml(u.dn)}">Approve</button>
              &nbsp;|&nbsp;
              <button class="link-btn user-deny-btn" data-dn="${escapeHtml(u.dn)}"
                      data-name="${escapeHtml(u.username || u.cn || u.dn)}">Deny</button>`;
    }
    return `<button class="link-btn user-edit-btn" data-dn="${escapeHtml(u.dn)}">Edit</button>`;
  };
  tbody.innerHTML = users.map(u => `
    <tr>
      <td>${nameCell(u)}</td>
      <td>${u.email ? `<code>${escapeHtml(u.email)}</code>` : '<em>—</em>'}</td>
      <td>${roleCell(u)}</td>
      <td>${statusCell(u)}</td>
      <td title="${fmtTime(u.last_seen_at)}">${fmtRelTime(u.last_seen_at)}</td>
      <td>${actionCell(u)}</td>
    </tr>
  `).join("");
  tbody.querySelectorAll(".user-edit-btn").forEach(b => {
    b.addEventListener("click", () => openUserEdit(users.find(u => u.dn === b.dataset.dn)));
  });
  tbody.querySelectorAll(".user-approve-btn").forEach(b => {
    b.addEventListener("click", () => approvePendingUser(b.dataset.dn));
  });
  tbody.querySelectorAll(".user-deny-btn").forEach(b => {
    b.addEventListener("click", () => denyPendingUser(b.dataset.dn, b.dataset.name));
  });
}

async function approvePendingUser(dn) {
  const r = await jsonReq(`/admin/users/${encodeURIComponent(dn)}/approve`,
                          { method: "POST" });
  if (r.ok) {
    refreshAdminUsers();
  } else {
    alert("Approve failed: " + ((r.body && r.body.error) || "unknown"));
  }
}

async function denyPendingUser(dn, name) {
  if (!confirm(`Deny and remove the pending account "${name}"?`)) return;
  // Deny = delete the pending user row (uses the existing user-delete endpoint).
  const r = await jsonReq("/admin/users", {
    method: "DELETE",
    body: JSON.stringify({ dn }),
  });
  if (r.ok) {
    refreshAdminUsers();
  } else {
    alert("Deny failed: " + ((r.body && r.body.error) || "unknown"));
  }
}
document.getElementById("admin-users-refresh").addEventListener("click", refreshAdminUsers);

// --- Authentication settings panel -----------------------------------------
async function refreshAuthSettings() {
  const status = document.getElementById("admin-auth-status");
  setStatus(status, "Loading…");
  const r = await jsonReq("/admin/auth-settings");
  if (!r.ok) {
    setStatus(status, "Failed to load auth settings", "err");
    return;
  }
  const s = r.body || {};
  document.getElementById("admin-auth-mode").value = s.auth_mode || "mtls";
  document.getElementById("admin-auth-domain").value = s.trusted_email_domain || "";
  document.getElementById("admin-auth-approval").checked = !!s.require_admin_approval;
  document.getElementById("admin-auth-allow-reg").checked = !!s.allow_registration;
  // Banner dropdown: built from the server's option list, then select current.
  const sel = document.getElementById("admin-banner-select");
  sel.replaceChildren(...(s.banner_options || []).map(o => {
    const opt = document.createElement("option");
    opt.value = o.key; opt.textContent = o.label; return opt;
  }));
  sel.value = s.login_banner || "dod";
  document.getElementById("admin-banner-custom-title").value = s.login_banner_custom_title || "";
  document.getElementById("admin-banner-custom-text").value = s.login_banner_custom_text || "";
  _bannerToggleCustom();
  _authToggleLocalOpts();
  setStatus(status, "");
}

function _bannerToggleCustom() {
  const isCustom = document.getElementById("admin-banner-select").value === "custom";
  document.getElementById("admin-banner-custom").hidden = !isCustom;
}
document.getElementById("admin-banner-select")
  .addEventListener("change", _bannerToggleCustom);

function _authToggleLocalOpts() {
  const mode = document.getElementById("admin-auth-mode").value;
  document.getElementById("admin-auth-local-opts").style.display =
    (mode === "local") ? "" : "none";
  // warn when switching to mtls (only if it isn't already mtls server-side)
  document.getElementById("admin-auth-mtls-warn").hidden = (mode !== "mtls");
}

document.getElementById("admin-auth-mode")
  .addEventListener("change", _authToggleLocalOpts);

document.getElementById("admin-auth-refresh")
  .addEventListener("click", refreshAuthSettings);

document.getElementById("admin-auth-save-btn").addEventListener("click", async () => {
  const status = document.getElementById("admin-auth-status");
  const mode = document.getElementById("admin-auth-mode").value;
  const domain = document.getElementById("admin-auth-domain").value.trim();
  const approval = document.getElementById("admin-auth-approval").checked;
  const allowReg = document.getElementById("admin-auth-allow-reg").checked;

  const payload = {
    auth_mode: mode,
    trusted_email_domain: domain,
    require_admin_approval: approval,
    allow_registration: allowReg,
    login_banner: document.getElementById("admin-banner-select").value,
    login_banner_custom_title:
      document.getElementById("admin-banner-custom-title").value.trim(),
    login_banner_custom_text:
      document.getElementById("admin-banner-custom-text").value,
  };
  // Switching to mtls needs explicit confirmation (backend enforces this too).
  if (mode === "mtls") {
    if (!confirm("Enable CAC mTLS?\n\nConfirm that CAC certificate "
               + "verification works on this host first, or admins may be "
               + "locked out. Password accounts remain as a fallback.")) {
      return;
    }
    payload.confirm_mtls = true;
  }
  setStatus(status, "Saving…");
  const r = await jsonReq("/admin/auth-settings", {
    method: "PUT",
    body: JSON.stringify(payload),
  });
  if (r.ok) {
    setStatus(status, "Saved", "ok");
    refreshAuthSettings();
  } else {
    setStatus(status, "Failed: " + ((r.body && r.body.error) || "unknown"), "err");
  }
});

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

// Render the group-membership checkboxes in the user-edit modal. Owner
// memberships are shown checked + disabled (managed from the group side).
function _renderUserEditGroups(user) {
  const wrap = document.getElementById("user-edit-groups");
  if (!wrap) return;
  const memberOf = new Set(user.group_ids || []);
  const ownerOf = new Set(user.owner_group_ids || []);
  const groups = adminAllGroups || [];
  if (!groups.length) { wrap.innerHTML = '<span class="status">No groups defined.</span>'; return; }
  wrap.innerHTML = groups.map(g => {
    const owner = ownerOf.has(g.id);
    const checked = memberOf.has(g.id) || owner;
    return `<label style="display:inline-flex;align-items:center;gap:4px;font-size:13px">`
      + `<input type="checkbox" class="ue-group" data-gid="${g.id}"${checked ? " checked" : ""}${owner ? " disabled" : ""}> `
      + escapeHtml(g.name)
      + (owner ? ' <span class="pill pill-blue" style="font-size:10px">owner</span>' : "")
      + `</label>`;
  }).join("");
}

function openUserEdit(user) {
  document.getElementById("user-edit-dn").textContent = user.dn;
  document.getElementById("user-edit-dn").dataset.dn = user.dn;
  document.getElementById("user-edit-first").value = user.first_name || "";
  document.getElementById("user-edit-last").value = user.last_name || "";
  document.getElementById("user-edit-username").textContent = user.username || "—";
  document.getElementById("user-edit-email").value = user.email || "";
  document.getElementById("user-edit-admin").checked = !!user.is_admin;
  document.getElementById("user-edit-active").checked = !!user.is_active;
  document.getElementById("user-edit-notes").value = user.notes || "";
  _renderUserEditGroups(user);
  const pwField = document.getElementById("user-edit-password");
  if (pwField) pwField.value = "";
  const isSelf = currentUser && user.dn === currentUser.dn;
  document.getElementById("user-edit-admin").disabled = isSelf;
  document.getElementById("user-edit-active").disabled = isSelf;
  // Delete is hidden for your own account (the backend also blocks it).
  const delBtn = document.getElementById("user-edit-delete-btn");
  delBtn.hidden = isSelf;
  delBtn.dataset.dn = user.dn;
  delBtn.dataset.cn = user.cn || shortDN(user.dn);
  setStatus(document.getElementById("user-edit-status"),
    isSelf ? "You can't change your own admin or active flags." : "");
  allModalIds.forEach(m => { document.getElementById(m).hidden = (m !== "user-edit-modal"); });
  overlay.hidden = false;
}

// Live preview of the username as the admin types first/last.
function _previewEditUsername() {
  const norm = (s) => (s || "").toLowerCase().replace(/[^a-z0-9]/g, "");
  const f = norm(document.getElementById("user-edit-first").value);
  const l = norm(document.getElementById("user-edit-last").value);
  const base = [f, l].filter(Boolean).join(".");
  const el = document.getElementById("user-edit-username");
  if (base) el.textContent = base + " (a number is added if already taken)";
}
document.getElementById("user-edit-first").addEventListener("input", _previewEditUsername);
document.getElementById("user-edit-last").addEventListener("input", _previewEditUsername);

document.getElementById("user-edit-password-btn").addEventListener("click", async () => {
  const status = document.getElementById("user-edit-status");
  const dn = document.getElementById("user-edit-dn").dataset.dn;
  const pw = document.getElementById("user-edit-password").value;
  if (!pw) { setStatus(status, "Enter a password to set.", "err"); return; }
  setStatus(status, "Setting password…");
  const r = await jsonReq("/admin/users/set-password", {
    method: "POST",
    body: JSON.stringify({ dn, password: pw }),
  });
  if (r.ok) {
    document.getElementById("user-edit-password").value = "";
    setStatus(status, "Password set", "ok");
  } else {
    setStatus(status, (r.body && r.body.error) || "Failed to set password", "err");
  }
});

document.getElementById("user-edit-save-btn").addEventListener("click", async () => {
  const status = document.getElementById("user-edit-status");
  const dn = document.getElementById("user-edit-dn").dataset.dn;
  const payload = {
    dn,
    first_name: document.getElementById("user-edit-first").value.trim(),
    last_name: document.getElementById("user-edit-last").value.trim(),
    email: document.getElementById("user-edit-email").value.trim(),
    is_admin: document.getElementById("user-edit-admin").checked,
    is_active: document.getElementById("user-edit-active").checked,
    notes: document.getElementById("user-edit-notes").value,
    group_ids: [...document.querySelectorAll("#user-edit-groups .ue-group")]
      .filter(c => c.checked).map(c => parseInt(c.dataset.gid, 10)),
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
  const newName = r.body && r.body.username;
  setStatus(status, newName ? `Saved — username: ${newName}` : "Saved", "ok");
  setTimeout(() => { closeModal(); refreshAdminUsers(); }, 700);
});

document.getElementById("user-edit-delete-btn").addEventListener("click", async () => {
  const status = document.getElementById("user-edit-status");
  const btn = document.getElementById("user-edit-delete-btn");
  const dn = btn.dataset.dn;
  const cn = btn.dataset.cn || dn;
  // Destructive: require the admin to type the CN to confirm, not just click.
  const typed = prompt(
    `Delete user "${cn}"?\n\nTheir group memberships are removed. Their existing ` +
    `certificate jobs are KEPT as historical records.\n\n` +
    `Type the name to confirm:`, "");
  if (typed === null) return;                 // cancelled
  if (typed.trim() !== cn) {
    setStatus(status, "Name didn't match - not deleted.", "err");
    return;
  }
  setStatus(status, "Deleting…");
  const r = await jsonReq("/admin/users", {
    method: "DELETE",
    body: JSON.stringify({ dn }),
  });
  if (!r.ok) {
    setStatus(status, (r.body && r.body.error) || "Delete failed", "err");
    return;
  }
  const kept = r.body && r.body.jobs_retained;
  setStatus(status,
    "Deleted" + (kept ? ` (${kept} job record${kept === 1 ? "" : "s"} retained)` : ""),
    "ok");
  setTimeout(() => { closeModal(); refreshAdminUsers(); }, 800);
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
  loadSlackConfig();
  if (_capCache === null) loadCapabilities(); else applyCapabilityHints();
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
        <td><code>${escapeHtml(wh.name)}</code> <span class="pill pill-blue">${escapeHtml(wh.type || 'generic')}</span></td>
        <td><code style="font-size:11px">${escapeHtml(wh.url.length > 50 ? wh.url.substring(0, 50) + '…' : wh.url)}</code></td>
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

// --- Slack interactivity config -------------------------------------------
function _slackModeToggle() {
  const m = document.getElementById("slack-mode").value;
  document.querySelectorAll(".slack-mode-fields").forEach(d => {
    d.hidden = (d.dataset.smode !== m);
  });
}
document.getElementById("slack-mode")?.addEventListener("change", _slackModeToggle);

async function loadSlackConfig() {
  const r = await jsonReq("/admin/slack-config");
  if (!r.ok) return;
  const c = r.body || {};
  document.getElementById("slack-request-url").value =
    location.origin + (c.request_path || "/csr/api/slack/interact");
  document.getElementById("slack-interactive-enabled").checked = !!c.enabled;
  document.getElementById("slack-mode").value = c.mode || "http";
  document.getElementById("slack-secret-hint").textContent =
    c.signing_secret_set ? "(stored — leave blank to keep)" : "(not set)";
  document.getElementById("slack-apptoken-hint").textContent =
    c.app_token_set ? "(stored — leave blank to keep)" : "(not set)";
  _slackModeToggle();
}
document.getElementById("slack-config-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("slack-config-status");
  const body = {
    enabled: document.getElementById("slack-interactive-enabled").checked,
    mode: document.getElementById("slack-mode").value,
  };
  const sec = document.getElementById("slack-signing-secret").value.trim();
  if (sec) body.signing_secret = sec;
  const appTok = document.getElementById("slack-app-token").value.trim();
  if (appTok) body.app_token = appTok;
  setStatus(status, "Saving…");
  const r = await jsonReq("/admin/slack-config", { method: "PUT", body: JSON.stringify(body) });
  if (r.ok) {
    setStatus(status, "Saved", "ok");
    document.getElementById("slack-signing-secret").value = "";
    document.getElementById("slack-app-token").value = "";
    loadSlackConfig();
  } else {
    setStatus(status, (r.body && r.body.error) || "Save failed", "err");
  }
});

function openWebhookEdit(wh) {
  const modal = document.getElementById("webhook-edit-modal");
  document.getElementById("webhook-edit-title").textContent =
    wh ? `Edit integration: ${wh.name}` : "Add integration";
  document.getElementById("webhook-edit-name").value = wh ? wh.name : "";
  document.getElementById("webhook-edit-type").value = (wh && wh.type) || "slack";
  document.getElementById("webhook-edit-url").value = wh ? wh.url : "";
  document.getElementById("webhook-edit-enabled").checked = wh ? wh.enabled : true;
  modal.dataset.webhookId = wh ? wh.id : "";
  setStatus(document.getElementById("webhook-edit-status"), "");
  _webhookTypeChanged();

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

const WEBHOOK_TYPE_HINTS = {
  slack: "Slack incoming-webhook URL (Apps → Incoming Webhooks). Posts a chat message on the selected events.",
  teams: "Microsoft Teams incoming-webhook / connector URL. Posts a message card.",
  discord: "Discord channel webhook URL (Channel → Integrations → Webhooks).",
  generic: "Any HTTPS endpoint — receives the raw JSON payload. Use custom headers for auth tokens.",
};
function _webhookTypeChanged() {
  const t = document.getElementById("webhook-edit-type").value;
  document.getElementById("webhook-edit-type-hint").textContent = WEBHOOK_TYPE_HINTS[t] || "";
  // Custom headers only apply to the generic (raw JSON) type.
  document.getElementById("webhook-edit-headers-wrap").hidden = (t !== "generic");
}
document.getElementById("webhook-edit-type")?.addEventListener("change", _webhookTypeChanged);

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
    type: document.getElementById("webhook-edit-type").value,
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


// ===== Admin: CSR Subject / Organization (configurable, OOBE) =====
let _csrSubjectProfiles = [];
let _csrSubjectOobePrompted = false;

function _csrSubjectCfg() {
  return {
    country: document.getElementById("csrsubject-c").value.trim(),
    state: document.getElementById("csrsubject-st").value.trim(),
    locality: document.getElementById("csrsubject-l").value.trim(),
    org: document.getElementById("csrsubject-o").value.trim(),
    ous: [...document.querySelectorAll("#csrsubject-ou-chips [data-ou]")].map(c => c.dataset.ou),
    domain_suffix: document.getElementById("csrsubject-domain").value.trim(),
  };
}

function _csrSubjectPreview() {
  const c = _csrSubjectCfg(), parts = [];
  if (c.country) parts.push("C=" + c.country);
  if (c.state) parts.push("ST=" + c.state);
  if (c.locality) parts.push("L=" + c.locality);
  if (c.org) parts.push("O=" + c.org);
  c.ous.forEach(ou => parts.push("OU=" + ou));
  parts.push("CN=<hostname>");
  document.getElementById("csrsubject-preview").textContent = parts.join(", ");
}

function _csrSubjectRenderOUs(ous) {
  const wrap = document.getElementById("csrsubject-ou-chips");
  wrap.innerHTML = (ous && ous.length)
    ? ous.map(ou => `<span class="pill pill-blue" data-ou="${escapeHtml(ou)}">${escapeHtml(ou)} <a href="#" class="csrsubject-ou-del" data-ou="${escapeHtml(ou)}" style="text-decoration:none;font-weight:700">&times;</a></span>`).join("")
    : '<span class="status">no OUs</span>';
  wrap.querySelectorAll(".csrsubject-ou-del").forEach(a => a.addEventListener("click", (e) => {
    e.preventDefault();
    _csrSubjectRenderOUs(_csrSubjectCfg().ous.filter(x => x !== a.dataset.ou));
    _csrSubjectPreview();
  }));
}

async function loadCsrSubject() {
  const r = await jsonReq("/admin/csr-subject");
  if (!r.ok) return;
  const b = r.body, cfg = b.config || {};
  _csrSubjectProfiles = b.profiles || [];
  document.getElementById("csrsubject-c").value = cfg.country || "";
  document.getElementById("csrsubject-st").value = cfg.state || "";
  document.getElementById("csrsubject-l").value = cfg.locality || "";
  document.getElementById("csrsubject-o").value = cfg.org || "";
  document.getElementById("csrsubject-domain").value = cfg.domain_suffix || "";
  _csrSubjectRenderOUs(cfg.ous || []);
  document.getElementById("csrsubject-profile").innerHTML =
    '<option value="">&mdash; choose a profile &mdash;</option>' +
    _csrSubjectProfiles.map(p => `<option value="${p.key}">${escapeHtml(p.label)}</option>`).join("");
  document.getElementById("csrsubject-ou-suggestions").innerHTML =
    (b.suggested_ous || []).map(o => `<option value="${escapeHtml(o)}">`).join("");
  _csrSubjectPreview();
  const oobe = document.getElementById("csrsubject-oobe");
  if (!b.configured) {
    oobe.textContent = "⚙ Initial setup: choose your organization profile, adjust the fields, and Save so new CSRs carry the correct subject.";
    oobe.hidden = false;
    // First-run prompt: bring the admin to this tab once.
    if (!_csrSubjectOobePrompted) {
      _csrSubjectOobePrompted = true;
      document.querySelector('#admin-nav button[data-panel="csrsubject"]')?.click();
    }
  } else {
    oobe.hidden = true;
  }
}

document.getElementById("csrsubject-apply-profile")?.addEventListener("click", () => {
  const p = _csrSubjectProfiles.find(x => x.key === document.getElementById("csrsubject-profile").value);
  if (!p) return;
  document.getElementById("csrsubject-c").value = p.country || "";
  document.getElementById("csrsubject-st").value = p.state || "";
  document.getElementById("csrsubject-l").value = p.locality || "";
  document.getElementById("csrsubject-o").value = p.org || "";
  document.getElementById("csrsubject-domain").value = p.domain_suffix || "";
  _csrSubjectRenderOUs(p.ous || []);
  _csrSubjectPreview();
});

function _csrSubjectAddOU() {
  const inp = document.getElementById("csrsubject-ou-add");
  const v = inp.value.trim();
  if (!v) return;
  const cur = _csrSubjectCfg().ous;
  if (!cur.some(x => x.toLowerCase() === v.toLowerCase())) {
    cur.push(v); _csrSubjectRenderOUs(cur); _csrSubjectPreview();
  }
  inp.value = "";
}
document.getElementById("csrsubject-ou-add-btn")?.addEventListener("click", _csrSubjectAddOU);
document.getElementById("csrsubject-ou-add")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); _csrSubjectAddOU(); }
});
["csrsubject-c", "csrsubject-st", "csrsubject-l", "csrsubject-o"].forEach(id =>
  document.getElementById(id)?.addEventListener("input", _csrSubjectPreview));

document.getElementById("csrsubject-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("csrsubject-status");
  setStatus(status, "Saving…");
  const r = await jsonReq("/admin/csr-subject", { method: "PUT", body: JSON.stringify(_csrSubjectCfg()) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Save failed", "err"); return; }
  setStatus(status, "Saved — new CSRs will use this subject.", "ok");
  loadCsrSubject();
});
