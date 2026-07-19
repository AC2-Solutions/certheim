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
    loadLicense(),
    refreshTrustStore(),
    refreshSealedKeystore(),
    refreshEnrollSign(),
    loadAutomation(),   // issuance / delivery / renewals — populate on entry,
                        // not only after a manual Refresh click.
  ]);
}

// ===== Admin: License / entitlements =====
async function loadLicense() {
  const r = await jsonReq("/admin/license");
  if (!r.ok) return;
  const c = r.body;
  const st = document.getElementById("license-status");
  const det = document.getElementById("license-details");
  const mm = document.getElementById("license-mismatch");
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  // A valid license that outranks the running build: the paid features aren't in
  // this artifact, so show the pill in a warning state and surface the actionable
  // upgrade text instead of implying the tier is active.
  if (mm) {
    if (c.valid && c.edition_mismatch) { mm.hidden = false; mm.textContent = c.edition_mismatch; }
    else { mm.hidden = true; mm.textContent = ""; }
  }
  if (c.valid) {
    st.innerHTML = c.edition_mismatch
      ? `<span class="pill pill-warn">${escapeHtml(cap(c.edition || "commercial"))} license · ${escapeHtml(cap(c.build_edition || "community"))} build</span>`
      : `<span class="pill pill-ok">${escapeHtml(cap(c.edition || "commercial"))} Edition</span>`;
    det.hidden = false;
    document.getElementById("license-customer").textContent = c.customer || "—";
    document.getElementById("license-edition").textContent = cap(c.edition || "commercial");
    document.getElementById("license-entitlements").textContent =
      (c.effective_entitlements || []).join(", ") || "(base features only)";
    document.getElementById("license-expires").textContent =
      c.expires ? new Date(c.expires * 1000).toISOString().slice(0, 10) : "—";
  } else {
    // unlicensed = the free Community edition
    st.innerHTML = `<span class="pill pill-mute">Community Edition</span> ` +
      `<span class="status">${escapeHtml(c.reason || "no license")}</span>` +
      (c.gateable && c.gateable.length
        ? ` &middot; a license unlocks: <code>${escapeHtml(c.gateable.join(", "))}</code>` : "");
    det.hidden = true;
  }
}

document.getElementById("license-refresh-btn")?.addEventListener("click", loadLicense);
document.getElementById("license-install-btn")?.addEventListener("click", async () => {
  const msg = document.getElementById("license-msg");
  const blob = document.getElementById("license-input").value.trim();
  if (!blob) { setStatus(msg, "Paste a license first", "err"); return; }
  setStatus(msg, "Installing…");
  const r = await jsonReq("/admin/license", { method: "PUT", body: JSON.stringify({ license: blob }) });
  if (!r.ok) { setStatus(msg, (r.body && r.body.error) || "Install failed", "err"); await loadLicense(); return; }
  setStatus(msg, "License installed — reloading…", "ok");
  document.getElementById("license-input").value = "";
  await Promise.all([loadLicense(), loadCapabilities(), loadCsrSubject()]);
});
document.getElementById("license-remove-btn")?.addEventListener("click", async () => {
  const msg = document.getElementById("license-msg");
  if (!confirm("Remove the installed license? Licensed features will be hidden.")) return;
  const r = await jsonReq("/admin/license", { method: "DELETE" });
  if (!r.ok) { setStatus(msg, "Remove failed", "err"); return; }
  setStatus(msg, "License removed", "ok");
  await Promise.all([loadLicense(), loadCapabilities(), loadCsrSubject()]);
});

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
// Strict variant for ADDITIVE gating (tour steps / guide pages we only want to
// SHOW when a feature is actually entitled on THIS edition). Unlike capAvail
// (fail-open), this stays false until the capability cache confirms the feature
// is available here — so a dormant gov/commercial capability never surfaces
// onboarding content for a feature the running edition doesn't ship.
function capOn(key) {
  return !!(_capCache && _capCache[key] && _capCache[key].available);
}
function currentEdition() {
  return (typeof currentUser !== "undefined" && currentUser && currentUser.edition) || "community";
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
  note("cap-note-inventory", "visibility.inventory");
  // Trust store: gate the SSH-push controls when no credential manager is wired
  // (the pull script + local install still work everywhere).
  const sshOk = capAvail("trust.distribute.ssh");
  const pushHint = document.getElementById("ts-push-hint");
  ["ts-target-host", "ts-target-label", "ts-target-add-btn", "ts-push-all-btn"].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.disabled = !sshOk;
  });
  if (pushHint && !sshOk && _capCache && _capCache["trust.distribute.ssh"]) {
    pushHint.innerHTML = "⚠ " + escapeHtml(_capCache["trust.distribute.ssh"].reason) +
      " — use the pull install script above instead.";
  }
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
  applyCommunityGating(document);
}

// ---- Community-edition upsell gating --------------------------------------
// On the free Community build, licensed features this build physically cannot
// run (capability.upgrade === true) are disabled + badged "Commercial" so
// admins don't configure things that can never work. Deliberately scoped to the
// Community edition: Commercial/Government keep these controls live because they
// can genuinely license/configure them (a capability there reads "needs <env>",
// not "upgrade"). We key off `upgrade` (build/edition gating), NOT `available`
// (which folds in env config) — else free-but-unconfigured backends like
// OpenBao would be wrongly grayed on Community.
function _isCommunityEdition() {
  return typeof currentUser !== "undefined" && !!currentUser
    && currentUser.edition === "community";
}
function capUpgrade(key) {
  return !!(_capCache && _capCache[key] && _capCache[key].upgrade);
}
function _upgradeBadgeAfter(host) {
  if (!host || !host.parentNode) return;
  const sib = host.nextElementSibling;
  if (sib && sib.classList && sib.classList.contains("upgrade-badge")) return; // no dupes
  const b = document.createElement("span");
  b.className = "upgrade-badge";
  b.textContent = "Commercial";
  b.title = "Available in the Commercial and Government editions";
  host.parentNode.insertBefore(b, host.nextSibling);
}
// Disable + badge a fixed control (by id) tied to a capability.
function _gateControl(id, key) {
  const el = document.getElementById(id);
  if (!el || !(_isCommunityEdition() && capUpgrade(key))) return;
  el.disabled = true;
  const host = el.closest("label") || el;
  host.classList.add("upgrade-locked");
  _upgradeBadgeAfter(host);
}
// Disable + label the <option>s of a select whose backing feature isn't in this
// build. keyFor maps an option value -> capability key (null = leave it alone).
function _gateOptions(root, selector, keyFor) {
  root.querySelectorAll(selector).forEach(opt => {
    const key = keyFor(opt.value);
    if (key && _isCommunityEdition() && capUpgrade(key)) {
      opt.disabled = true;
      if (!/—\s*Commercial/.test(opt.textContent)) opt.textContent += "  —  Commercial";
    }
  });
}
function applyCommunityGating(root) {
  if (!_isCommunityEdition() || !_capCache) return;
  root = root || document;
  // Signing / CA backends — both the global picker and the per-template one.
  // OpenBao + ACME stay free (upgrade=false), so they're never gated here.
  _gateOptions(root, "#signing-cfg-backend option, .sig-backend option, .a-backend option",
    v => (v && v !== "manual") ? "ca.signing." + v : null);
  // Automated delivery destinations.
  _gateOptions(root, ".sig-deliver option, .a-deliver option",
    v => (v && v !== "none") ? "delivery." + v : null);
  // Global toggles: automated renewal + the ACME server.
  _gateControl("signing-cfg-autorenew", "lifecycle.auto_renew");
  _gateControl("signing-cfg-acmesrv", "ca.server.acme");
  // Per-template auto-renew checkboxes.
  if (capUpgrade("lifecycle.auto_renew")) {
    root.querySelectorAll(".sig-renew, .a-autorenew").forEach(el => {
      el.disabled = true;
      const l = el.closest("label");
      if (l) { l.classList.add("upgrade-locked"); l.title = "Automated renewal is a Commercial feature"; }
    });
  }
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
        <td class="tmpl-sign" data-id="${t.id}">${signingBadge(t)} <button type="button" class="link-btn tmpl-goto-automation">Manage →</button></td>
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
    tbody.querySelectorAll(".tmpl-goto-automation").forEach(b => {
      b.addEventListener("click", () => {
        document.querySelector('#admin-nav button[data-panel="automation"]')?.click();
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

// Automated signing backends a template may pin (besides "manual" = inherit
// the global default). Labels mirror the provider registry.
const SIGNING_BACKENDS = [
  ["openbao", "OpenBao"], ["windows_ca", "Windows CA"],
  ["cyberark", "CyberArk"], ["acme", "ACME"],
  ["ejbca", "EJBCA"], ["venafi", "Venafi"], ["aws_pca", "AWS Private CA"],
];

// ===== Admin: Automation (per-template lifecycle: issuance / delivery / renewals) =====
// The per-template signing/delivery/renewal controls live here (own admin area
// with sub-tabs), not buried in the template editor. All three save through the
// same PUT /admin/templates/<id>/signing, merging so editing one phase never
// nulls another.

// Delivery destinations a template may ship to (besides "none"). Edition-specific
// endpoint-push providers (F5 / NetScaler / A10 / IIS in Commercial+) extend this.
const DELIVERY_BACKENDS = [
  ["openbao", "OpenBao KV"], ["ssh", "SSH host"], ["pull", "Pull token"],
  ["k8s", "Kubernetes Secret"], ["webhook", "Webhook receiver"], ["cyberark", "CyberArk"],
  ["f5", "F5 BIG-IP"], ["netscaler", "NetScaler / ADC"], ["a10", "A10 Thunder"], ["iis", "IIS / Windows"],
  ["aws_sm", "AWS Secrets Manager"], ["azure_kv", "Azure Key Vault"], ["gcp_sm", "GCP Secret Manager"],
  ["agent", "Certheim agent (pull)"],
];
const DELIVERY_TARGET_HINT = {
  openbao: "KV base (csr-certs)", ssh: "remote dir (/etc/ssl/delivered)",
  k8s: "namespace/secret", webhook: "https://receiver/hook",
  cyberark: "Conjur variable id", pull: "",
  f5: "client-ssl profile (optional)", netscaler: "sslcertkey (optional)",
  a10: "client-ssl template (optional)", iis: "ip:port or IIS site (optional)",
  aws_sm: "[account/]region/secret-name", azure_kv: "vault/secret-name",
  gcp_sm: "project/secret-id", agent: "install dir on the endpoint",
};

function _rowEl(html) { const tr = document.createElement("tr"); tr.innerHTML = html; return tr; }

async function saveTemplateLifecycle(t, patch, statusEl) {
  const body = {
    signer_backend: t.signer_backend || "manual",
    openbao_role: t.openbao_role || "",
    max_ttl: (t.max_ttl === undefined || t.max_ttl === null || t.max_ttl === "") ? null : t.max_ttl,
    auto_sign: !!t.auto_sign,
    auto_renew: !!t.auto_renew,
    renew_before_days: (t.renew_before_days === undefined || t.renew_before_days === null || t.renew_before_days === "") ? null : t.renew_before_days,
    delivery_backend: t.delivery_backend || "none",
    key_mode: t.key_mode || "destination",
    delivery_target: t.delivery_target || "",
    delivery_reload: t.delivery_reload || "",
    key_storage: t.key_storage || "default",
    ...patch,
  };
  if (statusEl) setStatus(statusEl, "Saving…");
  const r = await jsonReq(`/admin/templates/${t.id}/signing`, { method: "PUT", body: JSON.stringify(body) });
  if (!r.ok) { if (statusEl) setStatus(statusEl, (r.body && r.body.error) || "Save failed", "err"); return false; }
  return true;
}

// --- Issuance row: signer backend / role / TTL / auto-sign / key storage ---
function _autoIssuanceRow(t) {
  const cur = t.signer_backend || "manual";
  const opts = SIGNING_BACKENDS.map(([v, l]) => `<option value="${v}"${cur === v ? " selected" : ""}>${l}</option>`).join("");
  const stores = ["default", "vault", "return_once", "host"]
    .map(v => `<option value="${v}"${(t.key_storage || "default") === v ? " selected" : ""}>key store: ${v}</option>`).join("");
  const tr = _rowEl(`
    <td><code>${escapeHtml(t.name)}</code></td>
    <td><select class="a-backend form-input" style="width:auto">
      <option value="manual"${cur === "manual" ? " selected" : ""}>Inherit global</option>${opts}</select></td>
    <td><span class="a-ob"${cur === "openbao" ? "" : " hidden"}>
      <input class="a-role form-input" style="width:110px;display:inline-block" placeholder="role" value="${escapeHtml(t.openbao_role || "")}">
      <input class="a-ttl form-input" type="number" min="1" style="width:80px;display:inline-block" placeholder="TTL s" value="${t.max_ttl || ""}"></span></td>
    <td style="text-align:center"><input type="checkbox" class="a-autosign"${t.auto_sign ? " checked" : ""}></td>
    <td><select class="a-keystore form-input" style="width:auto">${stores}</select></td>
    <td><button type="button" class="btn a-save" style="padding:2px 10px">Save</button> <span class="a-status status"></span></td>`);
  const back = tr.querySelector(".a-backend");
  back.addEventListener("change", () => { tr.querySelector(".a-ob").hidden = back.value !== "openbao"; });
  tr.querySelector(".a-save").addEventListener("click", async () => {
    const ttl = (tr.querySelector(".a-ttl").value || "").trim();
    const ok = await saveTemplateLifecycle(t, {
      signer_backend: back.value,
      openbao_role: (tr.querySelector(".a-role").value || "").trim(),
      max_ttl: ttl === "" ? null : parseInt(ttl, 10),
      auto_sign: tr.querySelector(".a-autosign").checked,
      key_storage: tr.querySelector(".a-keystore").value,
    }, tr.querySelector(".a-status"));
    if (ok) loadAutomation();
  });
  return tr;
}

// --- Delivery: Destinations management (Wave 1 P5) ---
// Delivery pivots from per-template columns to first-class Destinations:
// named targets that templates attach to; per-(cert, destination) state and
// drift come from the backend state machine. Transport availability is
// reported by the server, so unusable transports gray out in any edition.
let _destData = null;   // {destinations, transports, key_modes} or null (unavailable)

async function loadDestinationsData() {
  const r = await jsonReq("/admin/destinations");
  _destData = r.ok ? r.body : null;
}

const DEST_STATE_PILLS = [
  ["verified", "pill-ok"], ["delivered", "pill-ok"], ["desired", "pill-mute"],
  ["failed", "pill-warn"], ["drift", "pill-warn"], ["abandoned", "pill-warn"],
];

function _destStatusCell(counts) {
  const bits = DEST_STATE_PILLS
    .filter(([k]) => counts[k])
    .map(([k, cls]) => `<span class="pill ${cls}" title="${k}">${counts[k]} ${k}</span>`);
  return bits.length ? bits.join(" ") : '<span class="status">no deliveries yet</span>';
}

function _destTransportSelect(cls, cur) {
  const opts = DELIVERY_BACKENDS.map(([v, lbl]) => {
    const avail = !_destData || !(v in _destData.transports) || _destData.transports[v];
    return `<option value="${v}"${cur === v ? " selected" : ""}${avail ? "" : " disabled"}>` +
           `${lbl}${avail ? "" : " — unavailable"}</option>`;
  }).join("");
  return `<select class="${cls} form-input" style="width:auto">${opts}</select>`;
}

function _destTransportLabel(v) {
  const m = DELIVERY_BACKENDS.find(([x]) => x === v);
  return m ? m[1] : v;
}

// ---- Clean, read-only summary row (edit happens in a dialog) ----
function _destRowEl(d) {
  const chips = (d.template_ids || []).map(tid => {
    const t = myTemplates.find(x => x.id === tid);
    return `<span class="pill pill-blue" style="margin-right:4px">${escapeHtml(t ? t.name : "#" + tid)}</span>`;
  }).join("") || '<span class="status">none</span>';
  const sys = d.created_by === "system"
    ? ' <span class="pill pill-mute" title="Synced from a template\'s legacy delivery settings">synced</span>' : "";
  const off = d.enabled ? "" : ' <span class="pill pill-mute">off</span>';
  const tr = _rowEl(`
    <td><strong>${escapeHtml(d.name || "")}</strong>${sys}${off}</td>
    <td>${escapeHtml(_destTransportLabel(d.transport || "ssh"))}</td>
    <td>${d.target ? `<code>${escapeHtml(d.target)}</code>` : '<span class="status">—</span>'}</td>
    <td>${chips}</td>
    <td>${_destStatusCell(d.state_counts || {})}</td>
    <td style="white-space:nowrap;text-align:right">
      <button type="button" class="secondary d-edit" style="padding:3px 12px">Edit</button>
      <button type="button" class="link-btn d-del" style="color:var(--danger);margin-left:6px">Delete</button></td>`);
  tr.querySelector(".d-edit").addEventListener("click", () => openDestModal(d));
  tr.querySelector(".d-del").addEventListener("click", async () => {
    if (!confirm(`Delete destination "${d.name}"? Its delivery history is removed too.`)) return;
    const r = await jsonReq(`/admin/destinations/${d.id}`, { method: "DELETE" });
    if (r.ok) loadAutomation();
  });
  return tr;
}

// ---- Edit / create dialog ----
let _destModalId = null;   // null = creating a new destination
function _destModalToggle() {
  const v = document.getElementById("dest-f-transport").value;
  document.getElementById("dest-f-target").placeholder = DELIVERY_TARGET_HINT[v] || "target";
  document.getElementById("dest-row-target").style.display = (v === "pull") ? "none" : "";
  document.getElementById("dest-row-reload").style.display = (v === "ssh") ? "" : "none";
  document.getElementById("dest-f-host").placeholder =
    (v === "agent") ? "agent name (required)" : "host override (optional)";
}
function _renderDestModalTemplates(d) {
  const cell = document.getElementById("dest-modal-templates");
  if (!cell) return;
  cell.innerHTML = "";
  if (!d) return;
  (d.template_ids || []).forEach(tid => {
    const t = myTemplates.find(x => x.id === tid);
    const chip = document.createElement("span");
    chip.className = "pill pill-blue"; chip.style.marginRight = "4px";
    chip.innerHTML = `${escapeHtml(t ? t.name : "#" + tid)} <a href="#" title="Detach">×</a>`;
    chip.querySelector("a").addEventListener("click", async (e) => {
      e.preventDefault();
      await jsonReq(`/admin/destinations/${d.id}/detach`, { method: "POST", body: JSON.stringify({ template_id: tid }) });
      d.template_ids = (d.template_ids || []).filter(x => x !== tid);
      _renderDestModalTemplates(d);
      loadDestinationsData().then(renderDestinations);
    });
    cell.appendChild(chip);
  });
  const avail = myTemplates.filter(t => !(d.template_ids || []).includes(t.id));
  if (avail.length) {
    const sel = document.createElement("select");
    sel.className = "form-input"; sel.style.width = "auto";
    sel.innerHTML = '<option value="">+ attach template…</option>' +
      avail.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join("");
    sel.addEventListener("change", async () => {
      if (!sel.value) return;
      const tid = parseInt(sel.value, 10);
      await jsonReq(`/admin/destinations/${d.id}/attach`, { method: "POST", body: JSON.stringify({ template_id: tid }) });
      d.template_ids = [...(d.template_ids || []), tid];
      _renderDestModalTemplates(d);
      loadDestinationsData().then(renderDestinations);
    });
    cell.appendChild(sel);
  }
}
function openDestModal(d) {
  _destModalId = d ? d.id : null;
  document.getElementById("dest-modal-title").textContent = d ? "Edit destination" : "New destination";
  document.getElementById("dest-f-name").value = d ? (d.name || "") : "";
  document.getElementById("dest-f-transport").innerHTML = DELIVERY_BACKENDS.map(([v, lbl]) => {
    const avail = !_destData || !(v in _destData.transports) || _destData.transports[v];
    return `<option value="${v}"${(d && d.transport) === v ? " selected" : ""}${avail ? "" : " disabled"}>` +
           `${lbl}${avail ? "" : " — unavailable"}</option>`;
  }).join("");
  document.getElementById("dest-f-target").value = d ? (d.target || "") : "";
  document.getElementById("dest-f-reload").value = d ? (d.reload_cmd || "") : "";
  document.getElementById("dest-f-host").value = d ? (d.host || "") : "";
  document.getElementById("dest-f-keymode").value = d ? (d.key_mode || "destination") : "destination";
  document.getElementById("dest-f-verify").checked = !!(d && d.verify_tls);
  document.getElementById("dest-f-vport").value = d ? (d.verify_port || "") : "";
  document.getElementById("dest-f-enabled").checked = d ? !!d.enabled : true;
  _destModalToggle();
  // Templates can only be attached to a destination that already exists.
  document.getElementById("dest-modal-templates-wrap").hidden = !d;
  _renderDestModalTemplates(d);
  setStatus(document.getElementById("dest-modal-status"), "");
  openModal("dest-edit-modal");
}
async function saveDestModal() {
  const st = document.getElementById("dest-modal-status");
  setStatus(st, "Saving…");
  const body = {
    name: document.getElementById("dest-f-name").value.trim(),
    transport: document.getElementById("dest-f-transport").value,
    target: document.getElementById("dest-f-target").value.trim(),
    reload_cmd: document.getElementById("dest-f-reload").value.trim(),
    host: document.getElementById("dest-f-host").value.trim(),
    key_mode: document.getElementById("dest-f-keymode").value,
    verify_tls: document.getElementById("dest-f-verify").checked,
    verify_port: document.getElementById("dest-f-vport").value.trim() || null,
    enabled: document.getElementById("dest-f-enabled").checked,
  };
  const r = _destModalId
    ? await jsonReq(`/admin/destinations/${_destModalId}`, { method: "PUT", body: JSON.stringify(body) })
    : await jsonReq("/admin/destinations", { method: "POST", body: JSON.stringify(body) });
  if (!r.ok) { setStatus(st, (r.body && r.body.error) || "Save failed", "err"); return; }
  closeModal();
  loadAutomation();
}

function renderDestinations() {
  const tbody = document.getElementById("automation-destinations-tbody");
  if (!tbody) return;
  tbody.innerHTML = "";
  const newBtn = document.getElementById("dest-new-btn");
  if (!_destData) {
    tbody.innerHTML = '<tr><td colspan="6" class="status">Delivery destinations are not ' +
      'available in this deployment (Commercial feature).</td></tr>';
    if (newBtn) newBtn.hidden = true;
    return;
  }
  if (newBtn) newBtn.hidden = false;
  if (!_destData.destinations.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="status">No destinations yet — add one. ' +
      'Templates with legacy delivery settings are synced in automatically.</td></tr>';
  }
  _destData.destinations.forEach(d => tbody.appendChild(_destRowEl(d)));
}

document.getElementById("dest-new-btn")?.addEventListener("click", () => openDestModal(null));
document.getElementById("dest-modal-save")?.addEventListener("click", saveDestModal);
document.getElementById("dest-f-transport")?.addEventListener("change", _destModalToggle);
allModalIds.push("dest-edit-modal");

// --- Renewal row: auto-renew / lead days ---
function _autoRenewalRow(t) {
  const tr = _rowEl(`
    <td><code>${escapeHtml(t.name)}</code></td>
    <td style="text-align:center"><input type="checkbox" class="a-autorenew"${t.auto_renew ? " checked" : ""}></td>
    <td><input class="a-renewdays form-input" type="number" min="1" max="365" style="width:110px;display:inline-block"
        placeholder="global default" value="${t.renew_before_days || ""}"></td>
    <td><button type="button" class="btn a-save" style="padding:2px 10px">Save</button> <span class="a-status status"></span></td>`);
  tr.querySelector(".a-save").addEventListener("click", async () => {
    const d = (tr.querySelector(".a-renewdays").value || "").trim();
    const ok = await saveTemplateLifecycle(t, {
      auto_renew: tr.querySelector(".a-autorenew").checked,
      renew_before_days: d === "" ? null : parseInt(d, 10),
    }, tr.querySelector(".a-status"));
    if (ok) loadAutomation();
  });
  return tr;
}

const _AUTOMATION_TABS = { issuance: _autoIssuanceRow, renewals: _autoRenewalRow };

function renderAutomation() {
  Object.keys(_AUTOMATION_TABS).forEach(name => {
    const tb = document.getElementById(`automation-${name}-tbody`);
    if (!tb) return;
    tb.innerHTML = "";
    if (!myTemplates.length) {
      const cols = name === "renewals" ? 4 : 6;
      tb.innerHTML = `<tr><td colspan="${cols}" class="status">No templates yet — create one under Templates.</td></tr>`;
      return;
    }
    myTemplates.forEach(t => tb.appendChild(_AUTOMATION_TABS[name](t)));
  });
  renderDestinations();
  applyCommunityGating(document.querySelector('[data-panel="automation"]') || document);
}

async function loadAutomation() {
  await Promise.all([loadTemplates(), loadDestinationsData()]);
  renderAutomation();
  loadAgents();
}

// Sub-tab switch (Issuance / Delivery / Renewals) — mirrors the shared pattern.
document.querySelectorAll("#automation-subtabs .subtab").forEach(b => {
  b.addEventListener("click", () => {
    const name = b.dataset.subtab;
    document.querySelectorAll("#automation-subtabs .subtab").forEach(x => x.classList.toggle("active", x === b));
    document.querySelectorAll('[data-panel="automation"] [data-subtabpanel]')
      .forEach(p => { p.hidden = (p.dataset.subtabpanel !== name); });
  });
});
document.querySelector('#admin-nav button[data-panel="automation"]')?.addEventListener("click", loadAutomation);
document.getElementById("automation-refresh")?.addEventListener("click", loadAutomation);

document.getElementById("admin-templates-refresh")?.addEventListener("click", refreshAdminTemplates);

// ===== Admin: ACME EAB credentials (Wave 2 - ACME-first delivery) =====
async function loadEabKeys() {
  const tbody = document.getElementById("signing-eab-tbody");
  if (!tbody) return;
  const r = await jsonReq("/admin/acme-eab");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="5" class="status">EAB credentials unavailable.</td></tr>';
    return;
  }
  const keys = r.body.keys || [];
  tbody.innerHTML = keys.length ? "" :
    '<tr><td colspan="5" class="status">No EAB credentials yet - mint one below.</td></tr>';
  keys.forEach(k => {
    const tr = document.createElement("tr");
    const tname = (myTemplates.find(t => t.id === k.template_id) || {}).name;
    tr.innerHTML = `
      <td><code>${escapeHtml(k.name || k.kid)}</code><br><span class="status">${escapeHtml(k.kid)}</span></td>
      <td>${k.template_id ? `<span class="pill pill-blue">${escapeHtml(tname || "#" + k.template_id)}</span>`
                          : '<span class="status">global default</span>'}</td>
      <td>${(k.allowed_domains || []).map(d => `<code>${escapeHtml(d)}</code>`).join(" ")
            || '<span class="status">any</span>'}</td>
      <td>${k.revoked ? '<span class="pill pill-err">revoked</span>'
            : (k.bound_account ? '<span class="pill pill-ok">bound</span>'
                               : '<span class="pill pill-mute">unused</span>')}</td>
      <td>${k.revoked ? "" : '<button type="button" class="link-btn eab-revoke" style="color:var(--danger)">Revoke</button>'}</td>`;
    const rv = tr.querySelector(".eab-revoke");
    if (rv) rv.addEventListener("click", async () => {
      if (!confirm(`Revoke EAB "${k.name || k.kid}"? Its bound ACME account is deactivated too.`)) return;
      await jsonReq(`/admin/acme-eab/${k.kid}/revoke`, { method: "POST" });
      loadEabKeys();
    });
    tbody.appendChild(tr);
  });
  // template dropdown for minting
  const sel = document.getElementById("signing-eab-template");
  if (sel) {
    sel.innerHTML = '<option value="">global default backend</option>' +
      myTemplates.map(t => `<option value="${t.id}">${escapeHtml(t.name)}</option>`).join("");
  }
}

document.getElementById("signing-eab-mint")?.addEventListener("click", async () => {
  const out = document.getElementById("signing-eab-minted");
  const domains = document.getElementById("signing-eab-domains").value
    .split(",").map(x => x.trim()).filter(Boolean);
  setStatus(out, "Minting…");
  const r = await jsonReq("/admin/acme-eab", {
    method: "POST", body: JSON.stringify({
      name: document.getElementById("signing-eab-name").value.trim(),
      template_id: parseInt(document.getElementById("signing-eab-template").value, 10) || null,
      allowed_domains: domains,
    }) });
  if (!r.ok) {
    setStatus(out, (r.body && r.body.error) || "Mint failed", "err");
    return;
  }
  // The HMAC is shown exactly once - copy it now.
  out.innerHTML = `
    <div class="iwz-note" style="margin-top:4px">Copy these now - the HMAC key is <strong>not stored retrievably</strong> and will not be shown again.<br>
      EAB kid: <code>${escapeHtml(r.body.kid)}</code><br>
      EAB HMAC key: <code>${escapeHtml(r.body.hmac)}</code>${r.body.directory
        ? `<br>Directory: <code>${escapeHtml(r.body.directory)}</code>` : ""}<br>
      e.g. <code>certbot register --server ${escapeHtml(r.body.directory || "&lt;directory&gt;")} --eab-kid ${escapeHtml(r.body.kid)} --eab-hmac-key ${escapeHtml(r.body.hmac)}</code></div>`;
  document.getElementById("signing-eab-name").value = "";
  document.getElementById("signing-eab-domains").value = "";
  loadEabKeys();
});

// ===== Admin: delivery agents (Wave 4) =====
function _agentSeenPill(last) {
  if (!last) return '<span class="pill pill-mute">never</span>';
  const age = Date.now() / 1000 - last;
  if (age < 300) return '<span class="pill pill-ok">online</span>';
  if (age < 3600) return `<span class="pill pill-warn">${Math.round(age / 60)}m ago</span>`;
  return `<span class="pill pill-err">${Math.round(age / 3600)}h ago</span>`;
}

async function loadAgents() {
  const tbody = document.getElementById("automation-agents-tbody");
  if (!tbody) return;
  const r = await jsonReq("/admin/agents");
  if (!r.ok) {
    tbody.innerHTML = '<tr><td colspan="6" class="status">Agents unavailable in this deployment.</td></tr>';
    return;
  }
  const agents = r.body.agents || [];
  tbody.innerHTML = agents.length ? "" :
    '<tr><td colspan="6" class="status">No agents enrolled - mint an enrollment token below.</td></tr>';
  agents.forEach(a => {
    const c = a.state_counts || {};
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><code>${escapeHtml(a.name)}</code><br><span class="status">${escapeHtml(a.hostname || "")}</span></td>
      <td>${a.status === "revoked" ? '<span class="pill pill-err">revoked</span>' : _agentSeenPill(a.last_seen)}</td>
      <td>${escapeHtml(a.version || "-")}</td>
      <td>${DEST_STATE_PILLS.filter(([k]) => c[k])
             .map(([k, cls]) => `<span class="pill ${cls}">${c[k]} ${k}</span>`).join(" ")
             || '<span class="status">no pairs</span>'}</td>
      <td class="status">${a.enrolled_at ? new Date(a.enrolled_at * 1000).toISOString().slice(0, 10) : ""}</td>
      <td>${a.status === "revoked" ? "" :
            '<button type="button" class="link-btn ag-revoke" style="color:var(--danger)">Revoke</button>'}</td>`;
    const rv = tr.querySelector(".ag-revoke");
    if (rv) rv.addEventListener("click", async () => {
      if (!confirm(`Revoke agent "${a.name}"? Its credential stops working immediately; its pairs will alert at the delivery deadline.`)) return;
      await jsonReq(`/admin/agents/${a.id}/revoke`, { method: "POST" });
      loadAgents();
    });
    tbody.appendChild(tr);
  });
}

document.getElementById("agent-token-mint")?.addEventListener("click", async () => {
  const out = document.getElementById("agent-token-minted");
  setStatus(out, "Minting…");
  const r = await jsonReq("/admin/agent-tokens", {
    method: "POST", body: JSON.stringify({
      name: document.getElementById("agent-token-name").value.trim(),
      host_pin: document.getElementById("agent-token-pin").value.trim(),
    }) });
  if (!r.ok) {
    setStatus(out, (r.body && r.body.error) || "Mint failed", "err");
    return;
  }
  const base = location.origin + (location.pathname.startsWith("/csr") ? "/csr" : "");
  out.innerHTML = `
    <div class="iwz-note" style="margin-top:4px">Copy now - the token is shown <strong>once</strong> and is single-use.<br>
      On the endpoint host (RPM: <code>dnf install certheim-agent</code>, or download the agent from this page):<br>
      <code>certheim-agent enroll --url ${escapeHtml(base)} --token ${escapeHtml(r.body.token)}</code><br>
      <code>systemctl enable --now certheim-agent</code></div>`;
  document.getElementById("agent-token-name").value = "";
  document.getElementById("agent-token-pin").value = "";
  loadAgents();
});

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


// --- Database: backend status + tailored migrate-to-Postgres steps ---
async function loadDatabase() {
  const r = await jsonReq("/admin/database");
  if (!r.ok) return;
  const b = r.body;
  document.getElementById("admin-db-backend").textContent =
    b.backend === "postgres" ? "PostgreSQL" : "SQLite";
  document.getElementById("admin-db-location").textContent = b.location || "—";
  document.getElementById("admin-db-driver").textContent = b.postgres_driver ? "yes" : "no";
  // Only offer the move-to-Postgres flow when currently on SQLite.
  document.getElementById("admin-db-migrate").hidden = b.backend !== "sqlite";
  document.getElementById("admin-db-steps").hidden = true;
}
document.getElementById("admin-db-refresh")?.addEventListener("click", loadDatabase);
document.querySelector('#admin-nav button[data-panel="database"]')
  ?.addEventListener("click", loadDatabase);

document.getElementById("admin-db-test-btn")?.addEventListener("click", async () => {
  const dsn = document.getElementById("admin-db-dsn").value.trim();
  const status = document.getElementById("admin-db-test-status");
  const steps = document.getElementById("admin-db-steps");
  steps.hidden = true;
  if (!dsn) { setStatus(status, "Enter a PostgreSQL connection string", "err"); return; }
  setStatus(status, "Testing…");
  const r = await jsonReq("/admin/database/test", { method: "POST", body: JSON.stringify({ dsn }) });
  if (!r.ok || !(r.body && r.body.ok)) {
    setStatus(status, "Connection failed: " + ((r.body && r.body.error) || "error"), "err");
    return;
  }
  setStatus(status, "Connected — " + (r.body.server || "PostgreSQL"), "ok");
  document.getElementById("admin-db-cmd-migrate").textContent =
    'sudo -u certheim certheim-db-migrate --to "' + dsn + '"';
  document.getElementById("admin-db-cmd-env").textContent = "CERTHEIM_DB_URL=" + dsn;
  steps.hidden = false;
});

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
  // Community: a gated backend's connection settings must NEVER be shown, even
  // if it is somehow the selected value — render an upgrade note, no fields.
  const _selKey = document.getElementById("signing-cfg-backend").value;
  if (_isCommunityEdition() && capUpgrade("ca.signing." + _selKey)) {
    document.getElementById("signing-ttl-wrap").hidden = true;
    wrap.innerHTML = ""; cred.innerHTML = "";
    hint.innerHTML = '<span class="upgrade-badge">Commercial</span> '
      + escapeHtml((p && p.label) || _selKey)
      + ' signing requires a Commercial or Government license. Community can '
      + 'sign via ACME or accept manual cert uploads.';
    return;
  }
  document.getElementById("signing-ttl-wrap").hidden = !(p && p.automated);
  if (p && p.key === "local_ca") { _renderLocalCA(wrap, cred, hint); return; }
  if (!p || !p.automated) {
    wrap.innerHTML = ""; cred.innerHTML = "";
    hint.textContent = "Manual: signers return certs via Upload Cert; the "
                     + "Approve & sign / Revoke actions stay hidden.";
    return;
  }
  hint.innerHTML = p.stub
    ? `<span class="pill pill-purple">framework</span> ${escapeHtml(p.label)} can be configured here, but its signing API isn't wired in this build yet.`
    : `Sign through ${escapeHtml(p.label)}.`;
  wrap.innerHTML = (p.fields || []).map(f => {
    const ctrl = f.options
      ? `<select id="sigf-${f.key}" class="form-input" data-fkey="${f.key}">`
          + f.options.map(o => `<option value="${escapeHtml(o)}"${f.value === o ? " selected" : ""}>${escapeHtml(o)}</option>`).join("")
          + `</select>`
      : f.multiline
      ? `<textarea id="sigf-${f.key}" class="form-input" data-fkey="${f.key}" rows="3"
             placeholder="${escapeHtml(f.placeholder || "")}">${escapeHtml(f.value || "")}</textarea>`
      : `<input type="text" id="sigf-${f.key}" class="form-input" data-fkey="${f.key}"
             placeholder="${escapeHtml(f.placeholder || "")}" value="${escapeHtml(f.value || "")}">`;
    const showif = f.show_if ? ` data-showif='${JSON.stringify(f.show_if)}'` : "";
    return `<div class="sigf-row"${showif}>
      <label class="textarea-label" for="sigf-${f.key}">${escapeHtml(f.label)}</label>
      ${ctrl}</div>`;
  }).join("");
  _sigApplyShowIf();
  cred.innerHTML = (p.credential_present
      ? '<span class="pill pill-ok">credential configured</span>'
      : '<span class="pill pill-err">no credential</span>')
    + (p.secret_hint ? ` <span class="status">${escapeHtml(p.secret_hint)}</span>` : "");
}
// Built-in Local CA: a self-contained CA whose private key lives in the sealed
// keystore. Unlike the other providers it has no connection fields — instead we
// render a generate / import panel + the current CA status + download links.
function _renderLocalCA(wrap, cred, hint) {
  const c = _signingCfgCache || {};
  const st = c.local_ca || {};
  hint.innerHTML = "Sign locally with a built-in CA — no external vault or CA "
    + "needed. The CA private key is envelope-encrypted in the "
    + "<strong>sealed keystore</strong>.";
  cred.innerHTML = (st.configured
      ? '<span class="pill pill-ok">CA configured</span>'
      : '<span class="pill pill-err">no CA yet</span>')
    + (st.sealed_ready
      ? ' <span class="pill pill-ok">keystore unsealed</span>'
      : ' <span class="pill pill-err">keystore sealed/uninitialised</span>');

  const dl = API;   // download endpoints ride the same-origin admin cookie
  const statusBlock = st.configured
    ? `<div class="status" style="margin:.4rem 0">
         <div><strong>Subject:</strong> <code>${escapeHtml(st.subject || "—")}</code></div>
         <div><strong>Valid until:</strong> ${escapeHtml(st.enddate || "—")}
              &nbsp;·&nbsp; <strong>Created:</strong> ${escapeHtml(st.created || "—")}</div>
         <div><strong>Issued:</strong> ${st.issued || 0}
              &nbsp;·&nbsp; <strong>Revoked:</strong> ${st.revoked || 0}
              &nbsp;·&nbsp; CA key in keystore: ${st.key_present ? "yes" : "<span class='pill pill-err'>MISSING</span>"}</div>
         <div style="margin-top:.3rem">
           <a class="btn" href="${dl}/admin/local-ca/cert">Download CA cert</a>
           <a class="btn" href="${dl}/admin/local-ca/crl">Download CRL</a>
         </div>
       </div>`
    : `<div class="status warn" style="margin:.4rem 0">No Local CA yet — generate a new one or import an existing CA below.</div>`;

  const sealedWarn = st.sealed_ready ? "" :
    `<div class="status err" style="margin:.4rem 0">The sealed keystore must be
       initialised and <strong>unsealed</strong> before the Local CA can
       generate, import, or sign. Set it up under <em>Admin → Sealed keystore</em>.</div>`;

  wrap.innerHTML = `
    ${statusBlock}
    ${sealedWarn}
    <details class="lca-fold"${st.configured ? "" : " open"}>
      <summary><strong>Generate a new CA</strong></summary>
      <div class="sigf-row"><label>Common Name (CN) *</label>
        <input id="lca-cn" class="form-input" placeholder="Certheim Local Root CA"></div>
      <div class="sigf-row"><label>Organisation (O)</label>
        <input id="lca-org" class="form-input" placeholder="Example Corp"></div>
      <div class="sigf-row"><label>Org Unit (OU)</label>
        <input id="lca-ou" class="form-input" placeholder="IT Security"></div>
      <div class="sigf-row"><label>Country (C)</label>
        <input id="lca-country" class="form-input" placeholder="US" maxlength="2" style="max-width:6rem"></div>
      <div class="sigf-row"><label>Key type</label>
        <select id="lca-keytype" class="form-input">
          <option value="ec">EC P-256 (recommended)</option>
          <option value="ec-p384">EC P-384</option>
          <option value="rsa">RSA 3072</option>
          ${st.mldsa_available
            ? `<option value="mldsa65">ML-DSA-65 (post-quantum)</option>
               <option value="mldsa87">ML-DSA-87 (post-quantum, CNSA 2.0)</option>`
            : ""}
        </select></div>
      <div class="sigf-row"><label>Validity (days)</label>
        <input id="lca-days" class="form-input" type="number" value="3650" style="max-width:9rem"></div>
      <button class="btn" onclick="localCaGenerate()"${st.sealed_ready ? "" : " disabled"}>Generate CA</button>
      <span class="status" style="color:var(--err)">Generating replaces any existing Local CA.</span>
    </details>
    <details class="lca-fold">
      <summary><strong>Import an existing CA</strong></summary>
      <div class="sigf-row"><label>CA certificate (PEM)</label>
        <textarea id="lca-cert" class="form-input" rows="4" placeholder="-----BEGIN CERTIFICATE-----"></textarea></div>
      <div class="sigf-row"><label>CA private key (PEM)</label>
        <textarea id="lca-key" class="form-input" rows="4" placeholder="-----BEGIN PRIVATE KEY-----"></textarea></div>
      <div class="sigf-row"><label>Key passphrase (if encrypted)</label>
        <input id="lca-pass" class="form-input" type="password" autocomplete="new-password"></div>
      <button class="btn" onclick="localCaImport()"${st.sealed_ready ? "" : " disabled"}>Import CA</button>
      <span class="status">The key is re-encrypted into the sealed keystore; the passphrase is not stored.</span>
    </details>
    <details class="lca-fold">
      <summary><strong>Revocation endpoints (OCSP + CRL)</strong></summary>
      <div class="sigf-row"><label>Public base URL</label>
        <input id="lca-baseurl" class="form-input" value="${escapeHtml(st.base_url || "")}"
               placeholder="https://certheim.example.com/csr"></div>
      <button class="btn" onclick="localCaSaveSettings()">Save</button>
      <span class="status">When set, newly issued certs carry AIA/CDP pointers to
        <code>&lt;base&gt;/ocsp</code> and <code>&lt;base&gt;/crl</code>, and Certheim
        answers OCSP checks itself. Clear the field to stop stamping.</span>
    </details>
    <div id="lca-msg" class="status" style="margin-top:.4rem"></div>`;
}

async function localCaSaveSettings() {
  const msg = document.getElementById("lca-msg");
  const r = await jsonReq("/admin/local-ca/settings", { method: "POST",
    body: JSON.stringify({ base_url: document.getElementById("lca-baseurl").value.trim() }) });
  if (!r.ok) { setStatus(msg, (r.body && r.body.error) || "save failed", "err"); return; }
  setStatus(msg, "Revocation endpoint settings saved.", "ok");
  await loadSigningConfig();
}

async function localCaGenerate() {
  const msg = document.getElementById("lca-msg");
  const cn = document.getElementById("lca-cn").value.trim();
  if (!cn) { setStatus(msg, "A Common Name is required.", "err"); return; }
  const kt = document.getElementById("lca-keytype").value;
  const payload = {
    cn, org: document.getElementById("lca-org").value.trim(),
    ou: document.getElementById("lca-ou").value.trim(),
    country: document.getElementById("lca-country").value.trim(),
    days: parseInt(document.getElementById("lca-days").value, 10) || 3650,
    key_type: kt.startsWith("mldsa") ? kt : (kt === "rsa" ? "rsa" : "ec"),
    curve: kt === "ec-p384" ? "P-384" : "P-256",
  };
  setStatus(msg, "Generating CA…");
  const r = await jsonReq("/admin/local-ca/generate", { method: "POST", body: JSON.stringify(payload) });
  if (!r.ok) { setStatus(msg, (r.body && r.body.error) || "generate failed", "err"); return; }
  setStatus(msg, "CA generated.", "ok");
  await loadSigningConfig(); _signingRenderProvider();
}

async function localCaImport() {
  const msg = document.getElementById("lca-msg");
  const payload = {
    cert_pem: document.getElementById("lca-cert").value,
    key_pem: document.getElementById("lca-key").value,
    key_passphrase: document.getElementById("lca-pass").value,
  };
  if (!payload.cert_pem.trim() || !payload.key_pem.trim()) {
    setStatus(msg, "Both the CA certificate and private key are required.", "err"); return;
  }
  setStatus(msg, "Importing CA…");
  const r = await jsonReq("/admin/local-ca/import", { method: "POST", body: JSON.stringify(payload) });
  if (!r.ok) { setStatus(msg, (r.body && r.body.error) || "import failed", "err"); return; }
  setStatus(msg, "CA imported.", "ok");
  await loadSigningConfig(); _signingRenderProvider();
}

// Show/hide provider fields whose `show_if` conditions reference sibling field
// values (e.g. ACME's DNS-provider fields only appear for the chosen provider).
function _sigApplyShowIf() {
  const wrap = document.getElementById("signing-provider-fields");
  if (!wrap) return;
  const val = k => { const el = wrap.querySelector(`[data-fkey="${k}"]`); return el ? el.value : ""; };
  wrap.querySelectorAll(".sigf-row[data-showif]").forEach(row => {
    let conds = [];
    try { conds = JSON.parse(row.getAttribute("data-showif")); } catch (e) { /* show by default */ }
    row.hidden = !conds.every(c => (c.in || []).includes(val(c.field)));
  });
}
document.getElementById("signing-cfg-backend")?.addEventListener("change", _signingRenderProvider);
// Re-evaluate conditional fields when any provider field changes (delegated).
document.getElementById("signing-provider-fields")?.addEventListener("change", _sigApplyShowIf);
document.getElementById("signing-provider-fields")?.addEventListener("input", _sigApplyShowIf);

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
  applyCommunityGating(document);   // Community: gray out paid CA backends
  // Never leave a gated (disabled) backend selected on Community — its
  // connection settings must not be shown; fall back to manual (ACME + manual
  // are the only selectable options).
  if (sel.selectedOptions[0] && sel.selectedOptions[0].disabled) sel.value = "manual";
  document.getElementById("signing-cfg-ttl").value = c.max_ttl || "";
  document.getElementById("signing-cfg-autorenew").checked = !!c.auto_renew_enabled;
  document.getElementById("signing-cfg-renewdays").value = c.auto_renew_before_days || 30;
  document.getElementById("signing-cfg-acmesrv").checked = !!c.acme_server_enabled;
  document.getElementById("signing-cfg-acmesrv-url").value = c.acme_server_base_url || "";
  document.getElementById("signing-cfg-acmesrv-eab").checked = !!c.acme_server_require_eab;
  loadEabKeys();
  // Private-key storage policy dropdown (server-generated keys).
  const ksSel = document.getElementById("signing-cfg-keystorage");
  if (ksSel) {
    const KS_LABELS = {
      vault: "Vault — key never stored on host (recommended)",
      return_once: "Return once — hand to requester, never stored",
      host: "Host keystore — legacy on-disk",
      sealed: "Encrypted keystore — built-in, no external vault (encrypted at rest)",
    };
    ksSel.innerHTML = (c.key_storage_options || ["vault", "return_once", "host", "sealed"])
      .map(k => `<option value="${k}">${escapeHtml(KS_LABELS[k] || k)}</option>`).join("");
    ksSel.value = c.key_storage || "vault";
  }
  const slEl = document.getElementById("signing-cfg-shortlived-ttl");
  if (slEl) slEl.value = c.key_return_once_max_ttl || 0;
  // FIPS 140-3 posture
  const f = c.fips || {};
  const fEl = document.getElementById("signing-fips-status");
  if (fEl) {
    const prov = f.openssl_provider || {};
    if (f.validated) {
      const std = f.standard ? ("FIPS " + f.standard) : "FIPS";
      const detail = (prov && prov.name)
        ? (" — " + escapeHtml(prov.name) + " " + escapeHtml(prov.version || ""))
        : (" — OpenSSL " + (f.openssl_major || "1.x") + " FIPS module (no provider model)");
      fEl.innerHTML = '<span style="color:#34d399;font-weight:600">✓ ' + std
        + ' validated module active</span>' + detail;
    } else if (f.kernel_fips) {
      fEl.innerHTML = '<span style="color:#fbbf24;font-weight:600">⚠ kernel FIPS on, but the OpenSSL FIPS provider was not detected</span>';
    } else {
      fEl.textContent = "Host is not in FIPS mode. Certheim bundles no crypto — all hashing, HMAC, TLS and RNG use the stdlib + system OpenSSL, so it runs on the validated module once the host is booted in FIPS mode.";
    }
    if (f.required && !f.validated) {
      fEl.innerHTML += ' <strong style="color:#ef4444">— FIPS is required here but not active.</strong>';
    }
  }
  const frEl = document.getElementById("signing-cfg-fips-required");
  if (frEl) frEl.checked = !!f.required;
  const asc = c.acme_server_capability || {};
  document.getElementById("signing-acmesrv-cap").textContent =
    asc.available === false ? "⚠ not entitled here" + (asc.reason ? " — " + asc.reason : "") : "";
  document.getElementById("signing-acmesrv-dir").innerHTML = (c.acme_server_enabled && c.acme_server_base_url)
    ? `Directory: <code>${escapeHtml(c.acme_server_base_url.replace(/\/$/, ""))}/directory</code>` : "";
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

document.getElementById("keystore-migrate-btn")?.addEventListener("click", async () => {
  const s = document.getElementById("keystore-migrate-status");
  if (!confirm("Move all on-disk private keys into the credential manager and shred the host copies?")) return;
  setStatus(s, "Migrating…");
  const r = await jsonReq("/admin/keys/migrate-to-vault", { method: "POST" });
  if (!r.ok) { setStatus(s, (r.body && r.body.error) || "Failed", "err"); return; }
  const b = r.body || {};
  setStatus(s, b.error ? b.error
    : `migrated ${b.migrated}, failed ${b.failed} (scanned ${b.scanned})`,
    b.error || b.failed ? "err" : "ok");
});

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
      acme_server_enabled: document.getElementById("signing-cfg-acmesrv").checked,
      acme_server_base_url: document.getElementById("signing-cfg-acmesrv-url").value.trim(),
      acme_server_require_eab: document.getElementById("signing-cfg-acmesrv-eab").checked,
      key_storage: document.getElementById("signing-cfg-keystorage").value,
      key_return_once_max_ttl:
        parseInt(document.getElementById("signing-cfg-shortlived-ttl").value, 10) || 0,
      fips_required: document.getElementById("signing-cfg-fips-required").checked,
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
  // License / expiry — surfaced here (admin-only) instead of the top bar.
  const lic = ((await jsonReq("/admin/license")).body) || {};
  const licEd = (lic.valid ? (lic.edition || "commercial") : "community");
  const licEdCap = licEd.charAt(0).toUpperCase() + licEd.slice(1);
  const licDays = (lic.valid && lic.expires)
    ? `${Math.max(0, Math.ceil((lic.expires * 1000 - Date.now()) / 86400000))} days`
    : (lic.valid ? "Perpetual" : "—");
  const licSub = lic.valid
    ? `${licEdCap}${lic.customer ? " · Licensed to " + escapeHtml(lic.customer) : ""}`
    : "unlicensed";
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
      <div class="label">Days remaining</div>
      <div class="value">${escapeHtml(licDays)}</div>
      <div class="sub">${licSub}</div>
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

// --- Admin: create a user (local mode = name+email+password; mtls = CAC DN) ---
allModalIds.push("user-create-modal");
document.getElementById("admin-users-create")?.addEventListener("click", () => {
  const local = !!(authInfo && authInfo.auth_mode === "local");
  document.getElementById("uc-local").hidden = !local;
  document.getElementById("uc-pw-row").hidden = !local;
  document.getElementById("uc-mtls").hidden = local;
  ["uc-first", "uc-last", "uc-email", "uc-password", "uc-dn"].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = "";
  });
  document.getElementById("uc-admin").checked = false;
  setStatus(document.getElementById("uc-status"), "");
  openModal("user-create-modal");
});
document.getElementById("uc-submit")?.addEventListener("click", async () => {
  const local = !!(authInfo && authInfo.auth_mode === "local");
  const st = document.getElementById("uc-status");
  const body = {
    is_admin: document.getElementById("uc-admin").checked,
    email: document.getElementById("uc-email").value.trim(),
  };
  if (local) {
    body.first_name = document.getElementById("uc-first").value.trim();
    body.last_name = document.getElementById("uc-last").value.trim();
    const pw = document.getElementById("uc-password").value.trim();
    if (pw) body.password = pw;
  } else {
    body.dn = document.getElementById("uc-dn").value.trim();
  }
  setStatus(st, "Creating…");
  const r = await jsonReq("/admin/users", { method: "POST", body: JSON.stringify(body) });
  if (!r.ok || !(r.body && r.body.ok)) {
    setStatus(st, (r.body && r.body.error) || "Create failed", "err");
    return;
  }
  let msg = "Created" + (r.body.username ? ` ${r.body.username}` : "") + ".";
  if (r.body.temp_password) {
    msg += ` Temporary password: ${r.body.temp_password} — copy it now (shown once).`;
  }
  setStatus(st, msg, "ok");
  refreshAdminUsers();   // modal stays open so a generated password can be copied
});

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
  // Multiple trusted domains supported; show them comma-separated.
  document.getElementById("admin-auth-domain").value =
    (s.trusted_email_domains && s.trusted_email_domains.length)
      ? s.trusted_email_domains.join(", ")
      : (s.trusted_email_domain || "");
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
  document.getElementById("admin-mtls-mode").value = s.mtls_mode || "off";
  document.getElementById("admin-mtls-bundle").value = s.mtls_ca_bundle_path || "";
  _bannerToggleCustom();
  _authToggleLocalOpts();
  _mtlsToggle();
  _gateCac();
  setStatus(status, "");
}

function _mtlsToggle() {
  document.getElementById("admin-mtls-bundle-row").hidden =
    document.getElementById("admin-mtls-mode").value !== "enforce";
}
document.getElementById("admin-mtls-mode")?.addEventListener("change", _mtlsToggle);

// CAC / mTLS is a licensed capability (Government edition, or a Commercial CAC
// add-on). When unavailable, disable the CAC auth-mode option + the client-cert
// controls and explain why.
function _gateCac() {
  const ok = capAvail("auth.cac");
  const mtlsOpt = document.querySelector('#admin-auth-mode option[value="mtls"]');
  if (mtlsOpt) {
    mtlsOpt.disabled = !ok;
    if (!ok && !/licensed/.test(mtlsOpt.textContent)) mtlsOpt.textContent += " — licensed";
  }
  ["admin-mtls-mode", "admin-mtls-bundle"].forEach(id => {
    const el = document.getElementById(id); if (el) el.disabled = !ok;
  });
  const note = document.getElementById("admin-mtls-status");
  if (note && !ok) setStatus(note,
    "CAC / mTLS is a licensed feature — Government edition, or a Commercial CAC add-on. Apply a license (Admin → License) to enable.", "");
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
    mtls_mode: document.getElementById("admin-mtls-mode").value,
    mtls_ca_bundle_path: document.getElementById("admin-mtls-bundle").value.trim(),
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
    // Surface the nginx mTLS apply result (best-effort on the backend).
    const ms = document.getElementById("admin-mtls-status");
    if (r.body && "mtls_applied" in r.body) {
      if (r.body.mtls_applied) setStatus(ms, "✓ nginx client-cert config applied (" + payload.mtls_mode + ")", "ok");
      else setStatus(ms, "⚠ saved, but applying to nginx failed: " + (r.body.mtls_apply_error || "unknown"), "err");
    }
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

// Support bundle: fetch as a blob so a server-side error (JSON) surfaces
// instead of downloading a broken zip.
// Health check: run the config self-checks (same battery the support bundle
// embeds) and render pass/warn/fail per check, worst first.
document.getElementById("admin-health-check-btn")?.addEventListener("click", async () => {
  const st = document.getElementById("admin-health-check-status");
  const out = document.getElementById("admin-health-check-out");
  setStatus(st, "Running checks…");
  const r = await jsonReq("/admin/diagnostics");
  if (!r.ok || !r.body || !r.body.checks) {
    setStatus(st, "Health check failed to run", "err");
    return;
  }
  const sev = { fail: 0, error: 1, warn: 2, ok: 3, skip: 4 };
  const icon = { ok: "✅", warn: "⚠️", fail: "❌", error: "❌", skip: "➖" };
  const checks = r.body.checks.slice().sort((a, b) =>
    (sev[a.status] ?? 5) - (sev[b.status] ?? 5));
  out.innerHTML = checks.map((c) => `
    <div class="diag-row diag-${escapeHtml(c.status)}">
      <span class="diag-icon">${icon[c.status] || "•"}</span>
      <span><strong>${escapeHtml(c.id)}</strong> — ${escapeHtml(c.summary)}
        ${c.hint ? `<div class="muted diag-hint">${escapeHtml(c.hint)}</div>` : ""}</span>
    </div>`).join("");
  out.hidden = false;
  const n = checks.filter((c) => c.status === "warn" || c.status === "fail"
                                  || c.status === "error").length;
  setStatus(st, n ? `${n} finding(s) — details above` : "All checks passed",
            r.body.overall === "ok" ? "ok" : (r.body.overall === "warn" ? "" : "err"));
});

document.getElementById("admin-support-bundle-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("admin-support-bundle-status");
  setStatus(status, "Building bundle…");
  try {
    const resp = await fetch(API + "/admin/support-bundle", { credentials: "same-origin" });
    if (!resp.ok) {
      let msg = resp.status;
      try { msg = (await resp.json()).error || msg; } catch (_) {}
      setStatus(status, "Failed: " + msg, "err");
      return;
    }
    const blob = await resp.blob();
    const cd = resp.headers.get("Content-Disposition") || "";
    const name = (cd.match(/filename=([^;]+)/) || [])[1] || "certheim-support-bundle.zip";
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = name.trim();
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    setStatus(status, "Downloaded " + name.trim() + " — review before sharing.", "ok");
  } catch (e) {
    setStatus(status, "Failed: " + e, "err");
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
    loadGroupPerms(grp.id);
  } else {
    divider.hidden = true; section.hidden = true;
    document.getElementById("group-perms-divider").hidden = true;
    document.getElementById("group-perms-section").hidden = true;
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

// --- per-group RBAC editor (Commercial; endpoints 402 when not entitled) ----
const GROUP_PERM_LABELS = {
  "fleet.view": "View fleet certs",
  "fleet.assign": "Assign certs",
  "fleet.unassign": "Unassign certs",
  "member.manage": "Manage members",
};
function _permLabel(p) { return GROUP_PERM_LABELS[p] || p; }

async function loadGroupPerms(groupId) {
  const divider = document.getElementById("group-perms-divider");
  const section = document.getElementById("group-perms-section");
  const note = document.getElementById("group-perms-note");
  const r = await jsonReq("/groups/" + groupId + "/permissions");
  if (!r.ok) {
    // 402 = RBAC not licensed (Community); 403 = not owner/admin. Hide quietly.
    divider.hidden = true; section.hidden = true;
    return;
  }
  divider.hidden = false; section.hidden = false;
  const c = r.body;
  const catalog = c.catalog || [];
  const base = new Set(c.default_member_perms || []);
  // base-permission checkboxes
  const baseWrap = document.getElementById("group-perms-base");
  baseWrap.innerHTML = catalog.map(p =>
    `<label class="status" style="display:inline-flex; gap:5px; align-items:center; cursor:pointer">
       <input type="checkbox" class="gp-base" value="${escapeHtml(p)}"${base.has(p) ? " checked" : ""}>
       ${escapeHtml(_permLabel(p))}</label>`).join("");
  document.getElementById("group-perms-base-save").dataset.groupId = groupId;
  setStatus(document.getElementById("group-perms-base-status"), "");
  // per-member grants
  const tbody = document.getElementById("group-perms-tbody");
  tbody.innerHTML = (c.members || []).map(m => {
    const has = new Set(m.grants || []);
    const boxes = catalog.map(p =>
      `<label class="status" style="display:inline-flex; gap:4px; align-items:center; margin-right:10px; cursor:pointer">
         <input type="checkbox" class="gp-member" data-dn="${escapeHtml(m.dn)}" value="${escapeHtml(p)}"${has.has(p) ? " checked" : ""}>
         ${escapeHtml(_permLabel(p))}</label>`).join("");
    return `<tr><td>${escapeHtml(m.cn)}</td><td>${escapeHtml(m.role)}</td><td>${boxes}</td></tr>`;
  }).join("") || '<tr><td colspan="3" class="status">No members.</td></tr>';
}

document.getElementById("group-perms-base-save")?.addEventListener("click", async (e) => {
  const gid = e.currentTarget.dataset.groupId;
  const st = document.getElementById("group-perms-base-status");
  const perms = Array.from(document.querySelectorAll(".gp-base:checked")).map(b => b.value);
  setStatus(st, "Saving…");
  const r = await jsonReq("/groups/" + gid + "/permissions", {
    method: "PUT", body: JSON.stringify({ default_member_perms: perms }) });
  setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Failed"), r.ok ? "ok" : "err");
});

// Per-member grant checkboxes save on change (delegated).
document.getElementById("group-perms-tbody")?.addEventListener("change", async (e) => {
  const box = e.target.closest(".gp-member");
  if (!box) return;
  const gid = document.getElementById("group-edit-modal").dataset.groupId;
  const dn = box.dataset.dn;
  const grants = Array.from(document.querySelectorAll(`.gp-member[data-dn="${CSS.escape(dn)}"]:checked`)).map(b => b.value);
  const r = await jsonReq("/groups/" + gid + "/members/permissions", {
    method: "PUT", body: JSON.stringify({ dn, grants }) });
  if (!r.ok) { box.checked = !box.checked; }   // revert on failure
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
    dynamic: "welcome",
    title: "Welcome to Certheim",
    // body is filled per-edition at render time (see EDITION_TOUR_COPY)
    body: "",
  },
  {
    target: "#certlist-section",
    title: "Stage your CSR requests",
    body: "One row per certificate — add as many requests as you need and they all generate in a single batch. Short names get your organization's configured domain appended automatically; entries that already contain a dot are used verbatim, and IPs in the SANs field are detected and encoded correctly.",
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
  {
    target: "#nav-guide",
    dynamic: "next",
    title: "What your edition adds",
    // body is filled per-edition at render time (see EDITION_TOUR_COPY)
    body: "",
    position: "bottom",
  },
];

// Per-edition copy for the dynamic tour steps. Keyed by the running edition
// (from /api/me); the tour names the edition the operator is actually on and
// summarises what that tier ships, so each demo box onboards to its own feature
// set rather than a generic walkthrough.
const EDITION_TOUR_COPY = {
  community: {
    welcome: "This quick tour shows you the key parts of the page — staging requests with templates, tracking jobs to issuance, and where to get help. You're on the Community edition, the free core. Replay this anytime from the Tour link in the header.",
    next: "You're on the Community edition — the free core for requesting, tracking and renewing certificates. Commercial and Government editions add single sign-on, a policy engine, signing backends, certificate inventory and more. Open the Guide anytime from the header for the full manual.",
  },
  commercial: {
    welcome: "This quick tour shows you the key parts of the page — staging requests with templates, tracking jobs to issuance, and where to get help. You're on the Commercial edition, so single sign-on, the policy engine, signing backends and certificate inventory are available to your admins. Replay this anytime from the Tour link in the header.",
    next: "Your Commercial edition adds single sign-on (OIDC/SAML/SCIM), a request policy engine, multiple signing backends (ACME, Windows CA, EJBCA, Venafi, AWS PCA), automated delivery, certificate inventory and CT monitoring, and team RBAC. Open the Guide from the header — its Administration section documents each of these.",
  },
  government: {
    welcome: "This quick tour shows you the key parts of the page — staging requests with templates, tracking jobs to issuance, and where to get help. You're on the Government edition, which adds the public-sector compliance, assurance and air-gap capabilities on top of everything in Commercial. Replay this anytime from the Tour link in the header.",
    next: "Your Government edition adds the public-sector suite on top of Commercial: CAC/PIV authentication, public-sector CSR profiles, tamper-evident (WORM) audit, FIPS/HSM key ceremonies, separation-of-duties and dual control, Federal PKI trust anchors, NIST 800-53 / OSCAL compliance evidence, and air-gapped CRL export. Open the Guide from the header — its Administration section walks through each.",
  },
};
function editionTourBody(which) {
  const ed = currentEdition();
  const copy = EDITION_TOUR_COPY[ed] || EDITION_TOUR_COPY.community;
  return copy[which] || "";
}

let tutorialIdx = 0;
let tourSteps = TUTORIAL_STEPS;   // active (edition/capability-filtered) subset

// Build the subset of steps that apply to the running edition. A step is kept
// unless it declares an `editions` allow-list it isn't in, or a `cap` that isn't
// available here (strict — dormant capabilities stay hidden).
function activeTourSteps() {
  const ed = currentEdition();
  return TUTORIAL_STEPS.filter((s) => {
    if (s.editions && s.editions.indexOf(ed) < 0) return false;
    if (s.cap && !capOn(s.cap)) return false;
    return true;
  });
}

function showTutorial() {
  const start = () => {
    tourSteps = activeTourSteps();
    tutorialIdx = 0;
    renderTutorialStep();
    document.getElementById("tutorial-overlay").hidden = false;
    document.getElementById("tutorial-tooltip").hidden = false;
  };
  // Admins: make sure capabilities are loaded so entitled premium steps show.
  // Non-admins can't reach /admin/capabilities (and don't get admin steps), so
  // they start immediately with cap-gated steps filtered out.
  if (typeof currentUser !== "undefined" && currentUser && currentUser.is_admin
      && _capCache === null) {
    loadCapabilities().then(start, start);
  } else {
    start();
  }
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

  const step = tourSteps[tutorialIdx];
  document.getElementById("tutorial-step-title").textContent = step.title;
  document.getElementById("tutorial-step-body").textContent =
    step.dynamic ? editionTourBody(step.dynamic) : step.body;
  document.getElementById("tutorial-progress").textContent =
    `Step ${tutorialIdx + 1} of ${tourSteps.length}`;

  const prevBtn = document.getElementById("tutorial-prev-btn");
  const nextBtn = document.getElementById("tutorial-next-btn");
  prevBtn.disabled = (tutorialIdx === 0);
  nextBtn.textContent = (tutorialIdx === tourSteps.length - 1) ? "Finish" : "Next";

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
  if (tutorialIdx < tourSteps.length - 1) {
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

function _csrSubjectCfg() {
  return {
    country: document.getElementById("csrsubject-c").value.trim(),
    state: document.getElementById("csrsubject-st").value.trim(),
    locality: document.getElementById("csrsubject-l").value.trim(),
    org: document.getElementById("csrsubject-o").value.trim(),
    // Only the chip <span> carries the OU - the delete <a> also has data-ou,
    // so a bare [data-ou] selector would read every OU twice (duplicate OUs).
    ous: [...document.querySelectorAll("#csrsubject-ou-chips span[data-ou]")].map(c => c.dataset.ou),
    domain_suffix: document.getElementById("csrsubject-domain").value.trim(),
    domain_suffixes: [...document.querySelectorAll("#csrsubject-domalt-chips span[data-v]")].map(c => c.dataset.v),
    extra_sans: [...document.querySelectorAll("#csrsubject-xsan-chips span[data-v]")].map(c => c.dataset.v),
    custom_dn: [...document.querySelectorAll("#csrsubject-xdn-rows .xdn-row")].map(r => ({
      field: r.querySelector(".xdn-field").value.trim(),
      value: r.querySelector(".xdn-value").value.trim(),
    })).filter(d => d.field && d.value),
  };
}

// Generic chip render for the simple string-list editors (domain alternates,
// extra SANs). delCls is the delete-link class wired in _csrSubjectWireChips.
function _csrChipRender(wrapId, items, delCls) {
  const wrap = document.getElementById(wrapId);
  if (!wrap) return;
  wrap.innerHTML = (items && items.length)
    ? items.map(v => `<span class="pill pill-blue" data-v="${escapeHtml(v)}">${escapeHtml(v)} <a href="#" class="${delCls}" data-v="${escapeHtml(v)}" style="text-decoration:none;font-weight:700">&times;</a></span>`).join("")
    : '<span class="status">none</span>';
  wrap.querySelectorAll("." + delCls).forEach(a => a.addEventListener("click", (e) => {
    e.preventDefault();
    const keep = [...wrap.querySelectorAll("span[data-v]")].map(c => c.dataset.v).filter(x => x !== a.dataset.v);
    _csrChipRender(wrapId, keep, delCls);
  }));
}

function _csrXdnAddRow(field, value) {
  const wrap = document.getElementById("csrsubject-xdn-rows");
  const row = document.createElement("div");
  row.className = "bulk-row xdn-row";
  row.style.marginBottom = "4px";
  row.innerHTML =
    `<input type="text" class="form-input xdn-field" style="max-width:200px" placeholder="attribute (e.g. DC)" value="${escapeHtml(field || "")}">`
    + `<input type="text" class="form-input xdn-value" style="max-width:240px" placeholder="value" value="${escapeHtml(value || "")}">`
    + `<a href="#" class="xdn-del" style="text-decoration:none;font-weight:700">&times;</a>`;
  wrap.appendChild(row);
  row.querySelector(".xdn-del").addEventListener("click", (e) => { e.preventDefault(); row.remove(); });
}

function _csrChipAdd(inputId, wrapId, delCls) {
  const inp = document.getElementById(inputId);
  const v = (inp.value || "").trim();
  if (!v) return;
  const cur = [...document.querySelectorAll(`#${wrapId} span[data-v]`)].map(c => c.dataset.v);
  if (!cur.some(x => x.toLowerCase() === v.toLowerCase())) {
    cur.push(v); _csrChipRender(wrapId, cur, delCls);
  }
  inp.value = "";
}

function _csrSubjectPreview() {
  const c = _csrSubjectCfg(), parts = [];
  if (c.country) parts.push("C=" + c.country);
  if (c.state) parts.push("ST=" + c.state);
  if (c.locality) parts.push("L=" + c.locality);
  if (c.org) parts.push("O=" + c.org);
  c.ous.forEach(ou => parts.push("OU=" + ou));
  (c.custom_dn || []).forEach(d => parts.push(d.field + "=" + d.value));
  // The domain suffix is appended to bare hostnames at generation, so show it
  // on the CN placeholder (e.g. CN=<hostname>.ac2.lan).
  const dom = c.domain_suffix ? "." + c.domain_suffix : "";
  parts.push("CN=<hostname>" + dom);
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

let _csrSavedProfiles = [];   // named subject profiles (distinct from org starters)

// Load a subject config dict into the Standard/Advanced editors.
function _csrLoadCfg(cfg) {
  cfg = cfg || {};
  document.getElementById("csrsubject-c").value = cfg.country || "";
  document.getElementById("csrsubject-st").value = cfg.state || "";
  document.getElementById("csrsubject-l").value = cfg.locality || "";
  document.getElementById("csrsubject-o").value = cfg.org || "";
  document.getElementById("csrsubject-domain").value = cfg.domain_suffix || "";
  _csrSubjectRenderOUs(cfg.ous || []);
  _csrChipRender("csrsubject-domalt-chips", cfg.domain_suffixes || [], "csrsubject-domalt-del");
  _csrChipRender("csrsubject-xsan-chips", cfg.extra_sans || [], "csrsubject-xsan-del");
  document.getElementById("csrsubject-xdn-rows").innerHTML = "";
  (cfg.custom_dn || []).forEach(d => _csrXdnAddRow(d.field, d.value));
  _csrSubjectPreview();
}

// Select a saved profile: load its config + name + default flag into the editor.
function _csrSelectProfile(slug) {
  const p = _csrSavedProfiles.find(x => x.slug === slug);
  if (!p) return;
  document.getElementById("csrsubject-prof-sel").value = slug;
  document.getElementById("csrsubject-prof-name").value = p.name || "";
  document.getElementById("csrsubject-prof-default").checked = !!p.is_default;
  _csrLoadCfg(p.config || {});
}

async function loadCsrSubject() {
  const r = await jsonReq("/admin/csr-subject");
  if (!r.ok) return;
  const b = r.body;
  _csrSubjectProfiles = b.profiles || [];          // org starters (DoD, etc.)
  _csrSavedProfiles = b.subject_profiles || [];    // named subject profiles
  const sel = document.getElementById("csrsubject-prof-sel");
  sel.innerHTML = _csrSavedProfiles.length
    ? _csrSavedProfiles.map(p => `<option value="${escapeHtml(p.slug)}">${escapeHtml(p.name)}${p.is_default ? " (default)" : ""}</option>`).join("")
    : '<option value="">(no profiles yet — create one)</option>';
  const cur = _csrSavedProfiles.find(p => p.is_default) || _csrSavedProfiles[0];
  if (cur) {
    _csrSelectProfile(cur.slug);
  } else {
    _csrLoadCfg(b.config || {});
    document.getElementById("csrsubject-prof-name").value = "";
    document.getElementById("csrsubject-prof-default").checked = true;
  }
  document.getElementById("csrsubject-profile").innerHTML =
    '<option value="">&mdash; choose a profile &mdash;</option>' +
    _csrSubjectProfiles.map(p => `<option value="${p.key}">${escapeHtml(p.label)}</option>`).join("");
  document.getElementById("csrsubject-ou-suggestions").innerHTML =
    (b.suggested_ous || []).map(o => `<option value="${escapeHtml(o)}">`).join("");
  const oobe = document.getElementById("csrsubject-oobe");
  oobe.hidden = !!b.configured;
  if (!b.configured) {
    oobe.textContent = "⚙ Initial setup: configure your organization subject and Save so new CSRs carry the correct subject.";
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

// Advanced-tag editors: domain alternates, custom DN rows, extra SANs.
document.getElementById("csrsubject-domalt-add-btn")?.addEventListener("click",
  () => _csrChipAdd("csrsubject-domalt-add", "csrsubject-domalt-chips", "csrsubject-domalt-del"));
document.getElementById("csrsubject-domalt-add")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); _csrChipAdd("csrsubject-domalt-add", "csrsubject-domalt-chips", "csrsubject-domalt-del"); }
});
document.getElementById("csrsubject-xsan-add-btn")?.addEventListener("click",
  () => _csrChipAdd("csrsubject-xsan-add", "csrsubject-xsan-chips", "csrsubject-xsan-del"));
document.getElementById("csrsubject-xsan-add")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); _csrChipAdd("csrsubject-xsan-add", "csrsubject-xsan-chips", "csrsubject-xsan-del"); }
});
document.getElementById("csrsubject-xdn-add-btn")?.addEventListener("click", () => _csrXdnAddRow("", ""));

// CSR Subject: Standard / Advanced sub-tab switch.
document.querySelectorAll("#csrsubject-subtabs .subtab").forEach(b => {
  b.addEventListener("click", () => {
    const name = b.dataset.subtab;
    document.querySelectorAll("#csrsubject-subtabs .subtab")
      .forEach(x => x.classList.toggle("active", x === b));
    document.querySelectorAll('[data-panel="csrsubject"] [data-subtabpanel]')
      .forEach(p => { p.hidden = (p.dataset.subtabpanel !== name); });
  });
});
["csrsubject-c", "csrsubject-st", "csrsubject-l", "csrsubject-o", "csrsubject-domain"].forEach(id =>
  document.getElementById(id)?.addEventListener("input", _csrSubjectPreview));

document.getElementById("csrsubject-save-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("csrsubject-status");
  const name = document.getElementById("csrsubject-prof-name").value.trim();
  if (!name) { setStatus(status, "Enter a profile name first (e.g. ac2.lan).", "err"); return; }
  setStatus(status, "Saving…");
  const r = await jsonReq("/admin/csr-subject/profile", {
    method: "PUT",
    body: JSON.stringify({
      name,
      is_default: document.getElementById("csrsubject-prof-default").checked,
      config: _csrSubjectCfg(),
    }),
  });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Save failed", "err"); return; }
  setStatus(status, "Saved — '" + name + "' profile updated.", "ok");
  await loadCsrSubject();
  // Live-refresh the request form so the new profile/domain is immediately
  // selectable without a page reload.
  if (typeof loadMe === "function") loadMe();
});

// Saved-profile selector / new / delete.
document.getElementById("csrsubject-prof-sel")?.addEventListener("change", (e) => _csrSelectProfile(e.target.value));
document.getElementById("csrsubject-prof-new")?.addEventListener("click", () => {
  document.getElementById("csrsubject-prof-name").value = "";
  document.getElementById("csrsubject-prof-default").checked = false;
  _csrLoadCfg({});
  document.getElementById("csrsubject-prof-name").focus();
});
document.getElementById("csrsubject-prof-delete")?.addEventListener("click", async () => {
  const slug = document.getElementById("csrsubject-prof-sel").value;
  if (!slug) return;
  if (!confirm("Delete the \"" + slug + "\" subject profile?")) return;
  const status = document.getElementById("csrsubject-status");
  const r = await jsonReq("/admin/csr-subject/profile/" + encodeURIComponent(slug), { method: "DELETE" });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Delete failed", "err"); return; }
  setStatus(status, "Deleted.", "ok");
  await loadCsrSubject();
  if (typeof loadMe === "function") loadMe();
});

// ===== Admin: Trust store =====
// Build a CA bundle from uploaded roots/intermediates and distribute it.
async function refreshTrustStore() {
  const rows = document.getElementById("ts-cert-rows");
  if (!rows) return;
  applyCapabilityHints();  // refresh cap-note-truststore + push gating
  const r = await jsonReq("/admin/truststore");
  if (!r.ok) { rows.innerHTML = '<tr><td colspan="6" class="hint">Failed to load.</td></tr>'; return; }
  _tsRenderCerts(r.body.certs || [], r.body.bundle || {});
  _tsRenderTargets(r.body.targets || []);
}

function _tsRenderCerts(certs, meta) {
  const rows = document.getElementById("ts-cert-rows");
  const m = document.getElementById("ts-bundle-meta");
  if (m) {
    m.textContent = meta.count
      ? `— bundle: ${meta.count} CA(s) (${meta.roots} root, ${meta.intermediates} intermediate), ${fmtBytes(meta.bytes || 0)}`
      : "— empty";
  }
  if (!certs.length) {
    rows.innerHTML = '<tr><td colspan="6" class="hint">No CAs uploaded yet.</td></tr>';
    return;
  }
  rows.innerHTML = certs.map(c => {
    const exp = c.expires_at ? new Date(c.expires_at * 1000).toISOString().slice(0, 10) : "—";
    const pill = c.status === "expired" ? '<span class="pill pill-mute">expired</span>'
      : c.status === "expiring" ? '<span class="pill pill-warn">expiring</span>' : "";
    return `<tr>
      <td>${escapeHtml(c.name || "—")}</td>
      <td>${escapeHtml(c.role || "")}</td>
      <td class="mono" title="${escapeHtml(c.subject || "")}">${escapeHtml((c.subject || "").slice(0, 60))}</td>
      <td>${exp} ${pill}</td>
      <td><input type="checkbox" class="ts-enabled" data-id="${c.id}" ${c.enabled ? "checked" : ""}></td>
      <td><button class="link-btn ts-del" data-id="${c.id}">Remove</button></td>
    </tr>`;
  }).join("");
  rows.querySelectorAll(".ts-enabled").forEach(cb => cb.addEventListener("change", async () => {
    await jsonReq(`/admin/truststore/${cb.dataset.id}/enabled`,
      { method: "POST", body: JSON.stringify({ enabled: cb.checked }) });
    refreshTrustStore();
  }));
  rows.querySelectorAll(".ts-del").forEach(b => b.addEventListener("click", async () => {
    if (!confirm("Remove this CA from the trust store?")) return;
    await jsonReq(`/admin/truststore/${b.dataset.id}`, { method: "DELETE" });
    refreshTrustStore();
  }));
}

function _tsRenderTargets(targets) {
  const rows = document.getElementById("ts-target-rows");
  if (!targets.length) {
    rows.innerHTML = '<tr><td colspan="5" class="hint">No targets.</td></tr>';
    return;
  }
  rows.innerHTML = targets.map(t => {
    const st = t.last_status === "ok" ? '<span class="pill pill-ok">ok</span>'
      : t.last_status === "error" ? `<span class="pill pill-mute" title="${escapeHtml(t.last_detail || "")}">error</span>` : "—";
    return `<tr>
      <td class="mono">${escapeHtml(t.host)}</td>
      <td>${escapeHtml(t.label || "—")}</td>
      <td>${fmtTime(t.last_pushed_at)}</td>
      <td>${st}</td>
      <td>
        <button class="link-btn ts-push-one" data-host="${escapeHtml(t.host)}">Push</button>
        <button class="link-btn ts-target-del" data-id="${t.id}">Remove</button>
      </td>
    </tr>`;
  }).join("");
  rows.querySelectorAll(".ts-push-one").forEach(b => b.addEventListener("click", () => _tsPush(b.dataset.host)));
  rows.querySelectorAll(".ts-target-del").forEach(b => b.addEventListener("click", async () => {
    await jsonReq(`/admin/truststore/targets/${b.dataset.id}`, { method: "DELETE" });
    refreshTrustStore();
  }));
}

async function _tsPush(host) {
  const status = document.getElementById("ts-target-status");
  setStatus(status, host ? `Pushing to ${host}…` : "Pushing to all targets…");
  const r = await jsonReq("/admin/truststore/push",
    { method: "POST", body: JSON.stringify(host ? { host } : {}) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Push failed", "err"); return; }
  const res = r.body.results || [];
  const ok = res.filter(x => x.ok).length;
  const fail = res.filter(x => !x.ok);
  setStatus(status, `Pushed: ${ok}/${res.length} ok` +
    (fail.length ? ` — failed: ${fail.map(f => f.host).join(", ")}` : ""), fail.length ? "err" : "ok");
  refreshTrustStore();
}

document.getElementById("ts-refresh-btn")?.addEventListener("click", refreshTrustStore);
document.getElementById("ts-upload-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("ts-upload-status");
  const pem = document.getElementById("ts-upload-pem").value.trim();
  if (!pem) { setStatus(status, "Paste a PEM certificate first", "err"); return; }
  setStatus(status, "Adding…");
  const r = await jsonReq("/admin/truststore/upload", {
    method: "POST",
    body: JSON.stringify({ pem, name: document.getElementById("ts-upload-name").value.trim() }),
  });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Upload failed", "err"); return; }
  const added = (r.body.added || []).length, dup = (r.body.duplicates || []).length;
  setStatus(status, `Added ${added}` + (dup ? `, ${dup} already present` : ""), "ok");
  document.getElementById("ts-upload-pem").value = "";
  document.getElementById("ts-upload-name").value = "";
  refreshTrustStore();
});
document.getElementById("ts-download-btn")?.addEventListener("click", () => {
  window.location = API + "/admin/truststore/bundle";
});
document.getElementById("ts-install-local-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("ts-action-status");
  if (!confirm("Install the current bundle into THIS host's OS trust store?")) return;
  setStatus(status, "Installing…");
  const r = await jsonReq("/admin/truststore/install-local", { method: "POST" });
  setStatus(status, r.ok ? "Installed on this host." : ((r.body && r.body.error) || "Install failed"),
    r.ok ? "ok" : "err");
});
document.getElementById("ts-script-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("ts-script-status");
  const out = document.getElementById("ts-script-out");
  setStatus(status, "Generating…");
  const r = await jsonReq("/admin/truststore/pull-token", { method: "POST" });
  if (!r.ok) { setStatus(status, "Failed", "err"); return; }
  out.style.display = "block";
  out.textContent = r.body.script || "";
  const days = Math.round((r.body.ttl || 0) / 86400);
  setStatus(status, `Token valid ${days || 1} day(s). Run this on each host:`, "ok");
});
document.getElementById("ts-target-add-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("ts-target-status");
  const host = document.getElementById("ts-target-host").value.trim();
  if (!host) { setStatus(status, "Enter a host", "err"); return; }
  const r = await jsonReq("/admin/truststore/targets", {
    method: "POST",
    body: JSON.stringify({ host, label: document.getElementById("ts-target-label").value.trim() }),
  });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Failed", "err"); return; }
  document.getElementById("ts-target-host").value = "";
  document.getElementById("ts-target-label").value = "";
  setStatus(status, "Target added", "ok");
  _tsRenderTargets(r.body.targets || []);
});
document.getElementById("ts-push-all-btn")?.addEventListener("click", () => _tsPush(null));

// ===== Certificate inventory (Phase C1 — unified visibility + risk) =====
function _invBadge(risk) {
  const lvl = (risk && risk.level) || "ok";
  const flags = (risk && risk.flags) || [];
  const title = flags.length ? flags.join(", ") : "no issues";
  return `<span class="risk-badge risk-${lvl}" title="${escapeHtml(title)}">${lvl}</span>`;
}
function _invKey(r) {
  if (!r.key_type) return "—";
  return escapeHtml(r.key_type + (r.key_bits ? " " + r.key_bits : ""));
}
async function refreshInventory() {
  const status = document.getElementById("inv-status");
  const tbody = document.getElementById("inv-tbody");
  const tiles = document.getElementById("inv-tiles");
  if (!tbody) return;
  // Licensed feature: if the build/license doesn't grant it, surface the upsell
  // note (via applyCapabilityHints) and don't bother hitting the API.
  if (!capAvail("visibility.inventory")) {
    applyCapabilityHints();
    tiles.innerHTML = ""; tbody.innerHTML = ""; setStatus(status, "", "");
    return;
  }
  setStatus(status, "Loading…", "");
  const s = await jsonReq("/inventory/summary");
  if (s.ok && s.body) {
    const lvl = s.body.by_level || {}, exp = s.body.expiry || {};
    tiles.innerHTML = [
      ["Total", s.body.total || 0, ""],
      ["Critical", lvl.critical || 0, "risk-critical"],
      ["High", lvl.high || 0, "risk-high"],
      ["Expired", exp.expired || 0, "risk-critical"],
      ["≤ 30 days", (exp.le_7d || 0) + (exp.le_30d || 0), "risk-high"],
    ].map(([label, val, cls]) =>
      `<div class="inv-tile ${cls}"><span class="inv-tile-n">${val}</span>`
      + `<span class="inv-tile-l">${label}</span></div>`).join("");
  }
  const params = new URLSearchParams();
  const q = document.getElementById("inv-q").value.trim();
  const src = document.getElementById("inv-source").value;
  const risk = document.getElementById("inv-risk").value;
  const within = document.getElementById("inv-expires").value;
  if (q) params.set("q", q);
  if (src) params.set("source", src);
  if (risk) params.set("risk", risk);
  if (within) params.set("expires_within", within);
  const qs = params.toString();
  const r = await jsonReq("/inventory" + (qs ? "?" + qs : ""));
  if (!r.ok) {
    setStatus(status, r.status === 402 ? "Inventory is a licensed feature."
      : ((r.body && r.body.error) || "Failed to load inventory"), "err");
    tbody.innerHTML = ""; return;
  }
  const items = (r.body && r.body.items) || [];
  _invItems = {};
  items.forEach((c) => { if (c.fingerprint) _invItems[c.fingerprint] = c; });
  // Load the assignable users/groups once so every row can render its pickers.
  if (!_invAssignable) {
    const ar = await jsonReq("/inventory/assignable");
    _invAssignable = (ar.ok && ar.body) ? ar.body : { users: [], groups: [] };
  }
  tbody.innerHTML = items.map((c) => {
    const exp = c.expires_at ? new Date(c.expires_at * 1000).toISOString().slice(0, 10) : "—";
    const rel = c.expires_at ? fmtRelTime(c.expires_at) : "";
    const locs = c.locations ? c.locations.join(", ") : (c.location || "—");
    const fp = c.fingerprint || "";
    // GitLab-style assignee control: a collapsed trigger showing current
    // assignees; clicking opens a searchable, multi-toggle dropdown (below).
    const assignCell = fp
      ? `<button type="button" class="inv-assign-trigger" data-fp="${fp}">`
        + `${_assigneeSummary(c.assigned_users || [], (c.assigned_groups || []).map(Number))}`
        + `<span class="inv-caret">▾</span></button>`
      : '<span class="muted">—</span>';
    const muteLabel = c.muted ? "Unmute" : "Mute";
    return `<tr class="${c.muted ? "inv-muted" : ""}">
      <td>${_invBadge(c.risk)}</td>
      <td>${escapeHtml(c.cn || "—")}</td>
      <td>${escapeHtml(c.source || "")}</td>
      <td>${escapeHtml(c.issuer || "—")}</td>
      <td>${exp} <span class="muted">${escapeHtml(rel)}</span></td>
      <td>${_invKey(c)}</td>
      <td>${escapeHtml(locs)}</td>
      <td class="inv-assign-cell">${assignCell}</td>
      <td class="inv-actions">
        <button class="link-btn" data-inv-mute="${fp}" data-muted="${c.muted ? 1 : 0}" ${fp ? "" : "disabled"}>${muteLabel}</button>
      </td>
    </tr>`;
  }).join("");
  setStatus(status, `${items.length} certificate${items.length === 1 ? "" : "s"}`, "ok");
}
document.getElementById("inv-refresh-btn")?.addEventListener("click", refreshInventory);
["inv-q", "inv-source", "inv-risk", "inv-expires"].forEach((id) => {
  const el = document.getElementById(id);
  if (!el) return;
  el.addEventListener(id === "inv-q" ? "input" : "change", () => {
    clearTimeout(refreshInventory._t);
    refreshInventory._t = setTimeout(refreshInventory, 250);
  });
});
let _invItems = {};         // fingerprint -> last-rendered inventory item
let _invAssignable = null;  // cached {users, groups} option lists

// ----- GitLab-style assignee dropdown (users + groups, multi-toggle) ---------
function _assigneeSummary(userDns, groupIds) {
  const um = {}, gm = {};
  ((_invAssignable && _invAssignable.users) || []).forEach((u) => { um[u.dn] = u.label; });
  ((_invAssignable && _invAssignable.groups) || []).forEach((g) => { gm[g.id] = g.name; });
  const pills = userDns.map((dn) => `<span class="pill">${escapeHtml(um[dn] || dn)}</span>`)
    .concat(groupIds.map((id) => `<span class="pill pill-blue">${escapeHtml(gm[id] || ("group " + id))}</span>`));
  return pills.length ? `<span class="inv-assign-pills">${pills.join("")}</span>`
    : '<span class="muted">Assign…</span>';
}

let _invPop = null, _invPopFp = null, _invPopSel = null, _invPopTrigger = null;

let _invCssDone = false;
function _invEnsureCss() {
  if (_invCssDone) return;
  _invCssDone = true;
  const style = document.createElement("style");
  style.textContent =
    ".inv-assign-trigger{display:inline-flex !important;align-items:center;gap:4px;flex-wrap:wrap;width:100%;min-width:130px;max-width:260px;padding:3px 8px;border:1px solid var(--border-input,var(--border));border-radius:6px;background:var(--bg-input) !important;color:var(--fg) !important;cursor:pointer;font-size:12px;font-weight:normal;text-align:left;box-shadow:none !important}"
    + ".inv-assign-trigger:hover{border-color:var(--accent)}"
    + ".inv-assign-pills{display:inline-flex;gap:3px;flex-wrap:wrap}"
    + ".inv-caret{margin-left:auto;opacity:.6}"
    + ".inv-pop{position:absolute;z-index:1000;width:260px;max-height:320px;display:flex;flex-direction:column;background:var(--bg-elevated,var(--modal-bg));border:1px solid var(--border);border-radius:8px;box-shadow:0 8px 24px rgba(0,0,0,.25);overflow:hidden}"
    + ".inv-pop-search{margin:8px;padding:6px 8px;border:1px solid var(--border-input);border-radius:6px;font-size:13px;background:var(--bg-input);color:var(--fg)}"
    + ".inv-pop-list{overflow:auto;padding:4px 0}"
    + ".inv-pop-h{padding:4px 12px;font-size:11px;text-transform:uppercase;letter-spacing:.04em;color:var(--fg-muted)}"
    + ".inv-pop-item{display:flex;align-items:center;gap:8px;padding:6px 12px;cursor:pointer;font-size:13px;color:var(--fg)}"
    + ".inv-pop-item:hover{background:var(--table-row-hover)}"
    + ".inv-pop-check{width:14px;text-align:center;color:var(--accent)}"
    + ".inv-pop-empty{padding:8px 12px;color:var(--fg-muted);font-size:12px}";
  document.head.appendChild(style);
}
_invEnsureCss();   // eager: neutral trigger style before the first render
function _invEnsurePop() {
  _invEnsureCss();
  if (_invPop) return _invPop;
  _invPop = document.createElement("div");
  _invPop.className = "inv-pop";
  _invPop.hidden = true;
  _invPop.innerHTML = '<input type="text" class="inv-pop-search" placeholder="Search users or groups…">'
    + '<div class="inv-pop-list"></div>';
  document.body.appendChild(_invPop);
  _invPop.querySelector(".inv-pop-search").addEventListener("input", (e) => _invRenderPopList(e.target.value));
  _invPop.querySelector(".inv-pop-list").addEventListener("click", (e) => {
    const it = e.target.closest(".inv-pop-item");
    if (!it) return;
    if (it.dataset.kind === "group") {
      const id = Number(it.dataset.id);
      if (_invPopSel.groups.has(id)) _invPopSel.groups.delete(id); else _invPopSel.groups.add(id);
    } else {
      const id = it.dataset.id;
      if (_invPopSel.users.has(id)) _invPopSel.users.delete(id); else _invPopSel.users.add(id);
    }
    _invRenderPopList(_invPop.querySelector(".inv-pop-search").value);
  });
  return _invPop;
}

function _invRenderPopList(filter) {
  const f = (filter || "").trim().toLowerCase();
  const list = _invPop.querySelector(".inv-pop-list");
  const users = ((_invAssignable && _invAssignable.users) || []).filter((u) => !f || (u.label || "").toLowerCase().includes(f));
  const groups = ((_invAssignable && _invAssignable.groups) || []).filter((g) => !f || (g.name || "").toLowerCase().includes(f));
  let html = "";
  if (users.length) {
    html += '<div class="inv-pop-h">Users</div>'
      + users.map((u) => `<div class="inv-pop-item" data-kind="user" data-id="${escapeHtml(u.dn)}">`
        + `<span class="inv-pop-check">${_invPopSel.users.has(u.dn) ? "✓" : ""}</span>${escapeHtml(u.label)}</div>`).join("");
  }
  if (groups.length) {
    html += '<div class="inv-pop-h">Groups</div>'
      + groups.map((g) => `<div class="inv-pop-item" data-kind="group" data-id="${g.id}">`
        + `<span class="inv-pop-check">${_invPopSel.groups.has(g.id) ? "✓" : ""}</span>${escapeHtml(g.name)}</div>`).join("");
  }
  list.innerHTML = html || '<div class="inv-pop-empty">No matches</div>';
}

async function _invOpenPop(fp, trigger) {
  if (!_invAssignable) {
    const ar = await jsonReq("/inventory/assignable");
    _invAssignable = (ar.ok && ar.body) ? ar.body : { users: [], groups: [] };
  }
  _invEnsurePop();
  const item = _invItems[fp] || {};
  _invPopFp = fp;
  _invPopTrigger = trigger;
  _invPopSel = { users: new Set(item.assigned_users || []), groups: new Set((item.assigned_groups || []).map(Number)) };
  const search = _invPop.querySelector(".inv-pop-search");
  search.value = "";
  _invRenderPopList("");
  const rect = trigger.getBoundingClientRect();
  _invPop.style.left = (window.scrollX + rect.left) + "px";
  _invPop.style.top = (window.scrollY + rect.bottom + 4) + "px";
  _invPop.hidden = false;
  search.focus();
}

async function _invClosePop() {
  if (!_invPop || _invPop.hidden) return;
  const fp = _invPopFp;
  const users = Array.from(_invPopSel.users);
  const groups = Array.from(_invPopSel.groups);
  _invPop.hidden = true;
  const item = _invItems[fp] || {};
  const prevU = (item.assigned_users || []).slice().sort().join(",");
  const prevG = (item.assigned_groups || []).map(Number).slice().sort().join(",");
  if (prevU === users.slice().sort().join(",") && prevG === groups.slice().sort().join(",")) return;
  await _invSaveAssign(fp, users, groups);
  if (_invPopTrigger) {
    _invPopTrigger.innerHTML = _assigneeSummary(users, groups) + '<span class="inv-caret">▾</span>';
  }
}

async function _invSaveAssign(fp, users, groups) {
  const st = document.getElementById("inv-status");
  const r = await jsonReq("/inventory/meta", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fingerprint: fp, assigned_users: users, assigned_groups: groups }),
  });
  if (!r.ok) { setStatus(st, (r.body && r.body.error) || "Save failed", "err"); return; }
  if (_invItems[fp]) { _invItems[fp].assigned_users = users; _invItems[fp].assigned_groups = groups; }
  setStatus(st, "Assignment saved", "ok");
}

async function _invSetMute(fp, muted) {
  const r = await jsonReq("/inventory/meta", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ fingerprint: fp, muted }),
  });
  if (!r.ok) {
    setStatus(document.getElementById("inv-status"), (r.body && r.body.error) || "Update failed", "err");
    return;
  }
  refreshInventory();
}

document.getElementById("inv-tbody")?.addEventListener("click", (e) => {
  const t = e.target.closest(".inv-assign-trigger");
  if (t) { e.stopPropagation(); _invOpenPop(t.dataset.fp, t); return; }
  const m = e.target.closest("[data-inv-mute]");
  if (m) _invSetMute(m.getAttribute("data-inv-mute"), m.getAttribute("data-muted") !== "1");
});
document.addEventListener("click", (e) => {
  if (_invPop && !_invPop.hidden && !_invPop.contains(e.target)
      && !e.target.closest(".inv-assign-trigger")) _invClosePop();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && _invPop && !_invPop.hidden) _invClosePop();
});

// ----- Alerting / digest config (C2.2/C2.3) -----
async function _invLoadAlertConfig() {
  if (!document.getElementById("ac-save")) return;
  if (!capAvail("visibility.inventory")) return;
  const r = await jsonReq("/inventory/alert-config");
  if (!r.ok || !r.body) return;
  const c = r.body;
  document.getElementById("ac-alerts-enabled").checked = !!c.alerts_enabled;
  document.getElementById("ac-thresholds").value = c.alert_thresholds || "";
  document.getElementById("ac-recipients").value = c.alert_default_recipients || "";
  document.getElementById("ac-digest-enabled").checked = !!c.digest_enabled;
  document.getElementById("ac-digest-days").value = c.digest_interval_days || 7;
  document.getElementById("ac-ct-enabled").checked = !!c.ct_enabled;
  document.getElementById("ac-ct-domains").value = c.ct_domains || "";
  document.getElementById("ac-ct-hours").value = c.ct_poll_hours || 12;
}
document.getElementById("ac-save")?.addEventListener("click", async () => {
  const st = document.getElementById("ac-status");
  const r = await jsonReq("/inventory/alert-config", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      alerts_enabled: document.getElementById("ac-alerts-enabled").checked,
      alert_thresholds: document.getElementById("ac-thresholds").value,
      alert_default_recipients: document.getElementById("ac-recipients").value,
      digest_enabled: document.getElementById("ac-digest-enabled").checked,
      digest_interval_days: document.getElementById("ac-digest-days").value,
      ct_enabled: document.getElementById("ac-ct-enabled").checked,
      ct_domains: document.getElementById("ac-ct-domains").value,
      ct_poll_hours: document.getElementById("ac-ct-hours").value,
    }),
  });
  setStatus(st, r.ok ? "Saved" : "Save failed", r.ok ? "ok" : "err");
  if (r.ok) _invLoadAlertConfig();
});
document.getElementById("ac-ct-poll")?.addEventListener("click", async () => {
  const st = document.getElementById("ac-status");
  setStatus(st, "Polling CT logs…", "");
  const r = await jsonReq("/inventory/ct-poll", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  });
  if (r.ok && r.body) {
    setStatus(st, `Polled ${r.body.domains} domain(s), ${r.body.observed} cert(s) seen`, "ok");
    refreshInventory();
  } else {
    setStatus(st, (r.body && r.body.error) || "Poll failed", "err");
  }
});

// ===== Roles & access (RBAC — tabbed manager, R3.1) =====
let _rbacCatalog = [];
let _rbacRoles = [];
let _rbacGroups = [];
let _rbacUsers = [];
let _rbacEditing = null;

async function refreshRoles() {
  const note = document.getElementById("cap-note-roles");
  const ui = document.getElementById("rbac-ui");
  if (!ui) return;
  if (!capAvail("governance.rbac")) {
    if (note) {
      const c = _capCache && _capCache["governance.rbac"];
      note.textContent = "⚠ " + ((c && c.desc) || "Role-based access control")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    ui.hidden = true;
    return;
  }
  if (note) note.hidden = true;
  ui.hidden = false;
  await Promise.all([_rbacLoadCatalog(), _rbacLoadRoles(), _rbacLoadGroups(), _rbacLoadUsers()]);
}

// ---- sub-tab switching ----
function _rbacShowTab(name) {
  document.querySelectorAll(".rbac-tab").forEach((b) =>
    b.classList.toggle("active", b.dataset.rtab === name));
  document.querySelectorAll(".rbac-pane").forEach((p) =>
    p.hidden = (p.dataset.rpane !== name));
  if (name === "catalog") _rbacRenderCatalog();
}
document.querySelectorAll(".rbac-tab").forEach((b) =>
  b.addEventListener("click", () => _rbacShowTab(b.dataset.rtab)));

// ---- loaders ----
async function _rbacLoadCatalog() {
  const r = await jsonReq("/admin/rbac/permissions");
  if (r.ok && r.body) _rbacCatalog = r.body.catalog || [];
}

async function _rbacLoadRoles() {
  const r = await jsonReq("/admin/rbac/roles");
  if (!r.ok || !r.body) {
    setStatus(document.getElementById("rbac-roles-status"),
      r.status === 402 ? "RBAC is a licensed feature." : "Failed to load roles", "err");
    return;
  }
  _rbacRoles = r.body.roles || [];
  const box = document.getElementById("rbac-roles-cards");
  if (box) box.innerHTML = _rbacRoles.map((role) => {
    const perms = role.builtin && role.slug === "admin"
      ? '<span class="muted">all permissions</span>'
      : (role.perms.length
          ? role.perms.map((p) => `<span class="pill">${escapeHtml(p)}</span>`).join(" ")
          : '<span class="muted">no permissions</span>');
    const badge = role.builtin ? '<span class="pill pill-muted">built-in</span>' : "";
    const canDelete = !role.builtin && !role.used_by_users && !role.used_by_groups;
    return `<div class="rbac-role-card">
      <div class="rbac-role-top">
        <div><strong>${escapeHtml(role.name)}</strong> ${badge}
          <div class="muted rbac-role-desc">${escapeHtml(role.description || "")}</div></div>
        <div class="rbac-role-actions">
          <button class="link-btn rbac-edit" data-id="${role.id}">Edit</button>
          <button class="link-btn rbac-clone" data-id="${role.id}">Clone</button>
          ${canDelete ? `<button class="link-btn danger rbac-del" data-id="${role.id}">Delete</button>` : ""}
        </div>
      </div>
      <div class="rbac-role-perms">${perms}</div>
      <div class="muted rbac-role-used">Assigned to ${role.used_by_users} user(s), ${role.used_by_groups} group(s)</div>
    </div>`;
  }).join("");
  _rbacRenderGroupChecks();
}

async function _rbacLoadGroups() {
  const r = await jsonReq("/admin/groups");
  if (r.ok && r.body) {
    _rbacGroups = (r.body.groups || []).map((g) => ({ id: g.id, name: g.name }));
    const sel = document.getElementById("rbac-group-picker");
    if (sel) {
      sel.innerHTML = _rbacGroups.map((g) =>
        `<option value="${g.id}">${escapeHtml(g.name)}</option>`).join("");
      _rbacLoadGroupRoles();
    }
  }
}

async function _rbacLoadUsers() {
  const r = await jsonReq("/admin/roles");   // legacy endpoint = users list + active flag
  if (!r.ok || !r.body) return;
  _rbacUsers = r.body.users || [];
  const active = document.getElementById("roles-active");
  if (active) active.textContent = r.body.active
    ? "Role enforcement is active."
    : "Roles are assignable; enforcement is rolling out endpoint by endpoint.";
  _rbacRenderUsers();
}

// ---- role editor ----
function _rbacPermMatrix(selected) {
  const cats = {};
  _rbacCatalog.filter((e) => e.scope === "global").forEach((e) =>
    (cats[e.category] = cats[e.category] || []).push(e));
  return Object.keys(cats).map((cat) => `
    <fieldset class="rbac-cat">
      <legend>${escapeHtml(cat)}</legend>
      ${cats[cat].map((e) => `
        <label class="checkbox-row" title="${escapeHtml(e.description)}">
          <input type="checkbox" class="rbac-perm-cb" value="${escapeHtml(e.key)}"
                 ${selected.has(e.key) ? "checked" : ""}>
          <span>${escapeHtml(e.label)} <code class="muted">${escapeHtml(e.key)}</code></span>
        </label>`).join("")}
    </fieldset>`).join("");
}
function _rbacOpenEditor(role) {
  _rbacEditing = role;
  const isAdminRole = role && role.builtin && role.slug === "admin";
  document.getElementById("rbac-editor-title").textContent = role ? "Edit role: " + role.name : "New role";
  document.getElementById("rbac-role-name").value = role ? role.name : "";
  document.getElementById("rbac-role-name").disabled = !!(role && role.builtin);
  document.getElementById("rbac-role-desc").value = role ? (role.description || "") : "";
  const note = document.getElementById("rbac-editor-note");
  if (role && role.builtin) {
    note.hidden = false;
    note.textContent = isAdminRole
      ? "The admin role always holds every permission and can't be changed here."
      : "Built-in role: the name is fixed, but you can reshape its permissions.";
  } else note.hidden = true;
  const selected = new Set(role ? role.perms : []);
  const mtx = document.getElementById("rbac-perm-matrix");
  mtx.innerHTML = _rbacPermMatrix(selected);
  mtx.querySelectorAll(".rbac-perm-cb").forEach((cb) => { cb.disabled = isAdminRole; });
  document.getElementById("rbac-save-role").disabled = isAdminRole;
  setStatus(document.getElementById("rbac-editor-status"), "", "");
  document.getElementById("rbac-editor").hidden = false;
  document.getElementById("rbac-editor").scrollIntoView({ behavior: "smooth", block: "nearest" });
}
async function _rbacSaveRole() {
  const st = document.getElementById("rbac-editor-status");
  const name = document.getElementById("rbac-role-name").value.trim();
  const description = document.getElementById("rbac-role-desc").value.trim();
  const perms = Array.from(document.querySelectorAll("#rbac-perm-matrix .rbac-perm-cb:checked")).map((cb) => cb.value);
  let r;
  if (_rbacEditing) {
    const body = { description };
    if (!_rbacEditing.builtin) body.name = name;
    if (!(_rbacEditing.builtin && _rbacEditing.slug === "admin")) body.perms = perms;
    r = await jsonReq("/admin/rbac/roles/" + _rbacEditing.id, {
      method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  } else {
    if (!name) { setStatus(st, "Name required", "err"); return; }
    r = await jsonReq("/admin/rbac/roles", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, description, perms }) });
  }
  if (r.ok) {
    document.getElementById("rbac-editor").hidden = true;
    await _rbacLoadRoles(); _rbacRenderUsers();
    setStatus(document.getElementById("rbac-roles-status"), "Saved", "ok");
  } else setStatus(st, (r.body && r.body.error) || "Save failed", "err");
}

// ---- group attachment ----
function _rbacRenderGroupChecks(attachedIds) {
  const box = document.getElementById("rbac-group-roles");
  if (!box) return;
  if (attachedIds) box.dataset.attached = JSON.stringify(attachedIds);
  const set = new Set(JSON.parse(box.dataset.attached || "[]"));
  box.innerHTML = _rbacRoles.map((role) => `
    <label class="checkbox-row">
      <input type="checkbox" class="rbac-grp-role-cb" value="${role.id}" ${set.has(role.id) ? "checked" : ""}>
      <span>${escapeHtml(role.name)}${role.builtin ? ' <span class="muted">(built-in)</span>' : ""}</span>
    </label>`).join("") || '<span class="muted">No roles defined yet.</span>';
}
async function _rbacLoadGroupRoles() {
  const sel = document.getElementById("rbac-group-picker");
  if (!sel || !sel.value) return;
  const r = await jsonReq("/admin/rbac/groups/" + sel.value + "/roles");
  const ids = (r.ok && r.body) ? (r.body.roles || []).map((x) => x.id) : [];
  _rbacRenderGroupChecks(ids);
}
async function _rbacSaveGroupRoles() {
  const sel = document.getElementById("rbac-group-picker");
  const ids = Array.from(document.querySelectorAll(".rbac-grp-role-cb:checked")).map((cb) => parseInt(cb.value, 10));
  const r = await jsonReq("/admin/rbac/groups/" + sel.value + "/roles", {
    method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ role_ids: ids }) });
  setStatus(document.getElementById("rbac-group-roles-status"),
    r.ok ? "Saved" : ((r.body && r.body.error) || "Save failed"), r.ok ? "ok" : "err");
  if (r.ok) _rbacLoadRoles();
}

// ---- user role assignment + effective-perms ----
function _rbacRenderUsers() {
  const tbody = document.getElementById("roles-tbody");
  const effSel = document.getElementById("rbac-eff-user");
  const slugs = _rbacRoles.map((x) => x.slug);
  if (tbody) tbody.innerHTML = _rbacUsers.map((u) => {
    const opts = slugs.map((slug) => {
      const rl = _rbacRoles.find((x) => x.slug === slug);
      return `<option value="${escapeHtml(slug)}" ${u.role === slug ? "selected" : ""}>${escapeHtml(rl ? rl.name : slug)}</option>`;
    }).join("");
    const sel = u.is_admin ? '<span class="pill">admin (flag)</span>'
      : `<select class="form-input" data-role-dn="${escapeHtml(u.dn)}">${opts}</select>`;
    return `<tr><td>${escapeHtml(u.cn || u.dn)}</td><td>${escapeHtml(u.email || "—")}</td><td>${sel}</td></tr>`;
  }).join("");
  if (effSel) effSel.innerHTML = _rbacUsers.map((u) =>
    `<option value="${escapeHtml(u.dn)}">${escapeHtml(u.cn || u.dn)}${u.is_admin ? " (admin)" : ""}</option>`).join("");
}
async function _rbacEffLookup() {
  const dn = document.getElementById("rbac-eff-user").value;
  const out = document.getElementById("rbac-eff-out");
  if (!dn) return;
  const r = await jsonReq("/admin/rbac/effective-perms?dn=" + encodeURIComponent(dn));
  if (!r.ok || !r.body) { out.innerHTML = '<span class="muted">Lookup failed.</span>'; return; }
  const d = r.body;
  if (d.is_admin) { out.innerHTML = '<p class="pill">admin (flag)</p><p class="muted">Holds every permission.</p>'; return; }
  const rows = (d.effective || []).map((p) => {
    const via = (d.sources[p] || []).map((s) => s.via === "direct"
      ? `own role <code>${escapeHtml(s.role)}</code>`
      : `group <strong>${escapeHtml(s.group)}</strong> → <code>${escapeHtml(s.role)}</code>`).join(", ");
    return `<tr><td><code>${escapeHtml(p)}</code></td><td class="muted">${via}</td></tr>`;
  }).join("");
  out.innerHTML = `<p class="muted">Own role: <code>${escapeHtml(d.role)}</code></p>
    <div class="table-wrap"><table class="data-table"><thead><tr><th>Permission</th><th>Granted via</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="2" class="muted">No permissions.</td></tr>'}</tbody></table></div>`;
}

// ---- permissions catalog (read-only reference) ----
function _rbacRenderCatalog() {
  const out = document.getElementById("rbac-catalog-out");
  if (!out) return;
  const cats = {};
  _rbacCatalog.forEach((e) => (cats[e.category] = cats[e.category] || []).push(e));
  out.innerHTML = Object.keys(cats).map((cat) => `
    <h4 class="rbac-h4">${escapeHtml(cat)}</h4>
    <div class="table-wrap"><table class="data-table"><tbody>
      ${cats[cat].map((e) => `<tr><td><code>${escapeHtml(e.key)}</code></td>
        <td><strong>${escapeHtml(e.label)}</strong><br><span class="muted">${escapeHtml(e.description)}</span></td></tr>`).join("")}
    </tbody></table></div>`).join("");
}

// ---- events ----
document.getElementById("roles-refresh")?.addEventListener("click", refreshRoles);
document.getElementById("rbac-new-role")?.addEventListener("click", () => _rbacOpenEditor(null));
document.getElementById("rbac-cancel-role")?.addEventListener("click", () => { document.getElementById("rbac-editor").hidden = true; });
document.getElementById("rbac-save-role")?.addEventListener("click", _rbacSaveRole);
document.getElementById("rbac-roles-cards")?.addEventListener("click", async (e) => {
  const btn = e.target.closest("button"); if (!btn) return;
  const id = parseInt(btn.dataset.id, 10);
  const role = _rbacRoles.find((x) => x.id === id);
  if (btn.classList.contains("rbac-edit")) _rbacOpenEditor(role);
  else if (btn.classList.contains("rbac-clone")) {
    const name = prompt("Name for the cloned role:", (role ? role.name : "") + " Copy");
    if (!name) return;
    const r = await jsonReq("/admin/rbac/roles/" + id + "/clone", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
    if (r.ok) { _rbacLoadRoles(); setStatus(document.getElementById("rbac-roles-status"), "Cloned", "ok"); }
    else setStatus(document.getElementById("rbac-roles-status"), (r.body && r.body.error) || "Clone failed", "err");
  } else if (btn.classList.contains("rbac-del")) {
    if (!confirm("Delete role \"" + (role ? role.name : "") + "\"?")) return;
    const r = await jsonReq("/admin/rbac/roles/" + id, { method: "DELETE" });
    if (r.ok) { _rbacLoadRoles(); _rbacRenderUsers(); setStatus(document.getElementById("rbac-roles-status"), "Deleted", "ok"); }
    else setStatus(document.getElementById("rbac-roles-status"), (r.body && r.body.error) || "Delete failed", "err");
  }
});
document.getElementById("rbac-group-picker")?.addEventListener("change", _rbacLoadGroupRoles);
document.getElementById("rbac-save-group-roles")?.addEventListener("click", _rbacSaveGroupRoles);
document.getElementById("rbac-eff-lookup")?.addEventListener("click", _rbacEffLookup);
document.getElementById("roles-tbody")?.addEventListener("change", async (e) => {
  const sel = e.target.closest("[data-role-dn]"); if (!sel) return;
  const r = await jsonReq("/admin/users/role", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dn: sel.getAttribute("data-role-dn"), role: sel.value }) });
  setStatus(document.getElementById("roles-status"), r.ok ? "Role updated" : "Update failed", r.ok ? "ok" : "err");
  if (r.ok) _rbacLoadRoles();
});

// ===== Tenants (multi-tenancy, Phase C3.2) =====
async function refreshTenants() {
  const tbody = document.getElementById("tenants-tbody");
  if (!tbody) return;
  const note = document.getElementById("cap-note-tenants");
  if (!capAvail("governance.multitenancy")) {
    if (note) {
      const c = _capCache && _capCache["governance.multitenancy"];
      note.textContent = "⚠ " + ((c && c.desc) || "Multi-tenant isolation")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    tbody.innerHTML = "";
    return;
  }
  if (note) note.hidden = true;
  const r = await jsonReq("/admin/tenants");
  if (!r.ok || !r.body) {
    setStatus(document.getElementById("tenants-status"),
      r.status === 402 ? "Multi-tenancy is a licensed feature." : "Failed to load tenants", "err");
    return;
  }
  tbody.innerHTML = (r.body.tenants || []).map((t) => `<tr>
      <td>${escapeHtml(t.name)}</td>
      <td><code>${escapeHtml(t.slug)}</code></td>
      <td class="muted">${escapeHtml(t.store || "")}</td>
      <td>${t.active ? "✓" : "—"}</td>
      <td><button class="link-btn" data-tenant-toggle="${escapeHtml(t.slug)}" data-active="${t.active ? 1 : 0}">${t.active ? "Deactivate" : "Activate"}</button></td>
    </tr>`).join("");
  _loadTenantUsers();
}
async function _loadTenantUsers() {
  const tbody = document.getElementById("tenant-users-tbody");
  if (!tbody || !capAvail("governance.multitenancy")) return;
  const r = await jsonReq("/admin/tenant-users");
  if (!r.ok || !r.body) return;
  const tenants = r.body.tenants || ["default"];
  tbody.innerHTML = (r.body.users || []).map((u) => {
    const opts = tenants.map((t) =>
      `<option value="${escapeHtml(t)}" ${u.tenant_id === t ? "selected" : ""}>${escapeHtml(t)}</option>`).join("");
    return `<tr>
      <td>${escapeHtml(u.cn || u.dn)}</td>
      <td>${escapeHtml(u.email || "—")}</td>
      <td>${u.is_admin ? "✓" : ""}</td>
      <td><select class="form-input" data-utenant-dn="${escapeHtml(u.dn)}">${opts}</select></td>
    </tr>`;
  }).join("");
}
document.getElementById("tenant-users-tbody")?.addEventListener("change", async (e) => {
  const sel = e.target.closest("[data-utenant-dn]");
  if (!sel) return;
  const r = await jsonReq("/admin/users/tenant", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ dn: sel.getAttribute("data-utenant-dn"), tenant: sel.value }),
  });
  setStatus(document.getElementById("tenant-users-status"),
    r.ok ? "Assignment updated" : ((r.body && r.body.error) || "Update failed"),
    r.ok ? "ok" : "err");
});
document.getElementById("tenant-create")?.addEventListener("click", async () => {
  const name = document.getElementById("tenant-name").value.trim();
  if (!name) return;
  const r = await jsonReq("/admin/tenants", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  const st = document.getElementById("tenants-status");
  if (r.ok) {
    document.getElementById("tenant-name").value = "";
    setStatus(st, "Created", "ok"); refreshTenants();
  } else {
    setStatus(st, (r.body && r.body.error) || "Create failed", "err");
  }
});
document.getElementById("tenants-tbody")?.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-tenant-toggle]");
  if (!b) return;
  const r = await jsonReq("/admin/tenants/active", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ slug: b.getAttribute("data-tenant-toggle"),
                           active: b.getAttribute("data-active") !== "1" }),
  });
  setStatus(document.getElementById("tenants-status"),
    r.ok ? "Updated" : "Update failed", r.ok ? "ok" : "err");
  if (r.ok) refreshTenants();
});
document.getElementById("tenants-refresh")?.addEventListener("click", refreshTenants);

// ===== Single sign-on (OIDC, Phase C3.3) =====
function _ssoSet(id, v) { const el = document.getElementById(id); if (el) el.value = v == null ? "" : v; }
function _ssoGet(id) { const el = document.getElementById(id); return el ? el.value.trim() : ""; }

async function refreshSso() {
  const note = document.getElementById("cap-note-sso");
  if (!capAvail("governance.sso")) {
    if (note) {
      const c = _capCache && _capCache["governance.sso"];
      note.textContent = "⚠ " + ((c && c.desc) || "Enterprise SSO")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    return;
  }
  if (note) note.hidden = true;
  const r = await jsonReq("/admin/sso-config");
  if (!r.ok || !r.body) {
    setStatus(document.getElementById("sso-status"),
      r.status === 402 ? "SSO is a licensed feature." : "Failed to load SSO config", "err");
    return;
  }
  const c = r.body;
  document.getElementById("sso-enabled").checked = !!c.enabled;
  _ssoSet("sso-issuer", c.issuer);
  _ssoSet("sso-client-id", c.client_id);
  document.getElementById("sso-client-secret").value = "";   // never echoed
  _ssoSet("sso-redirect-uri", c.redirect_uri);
  _ssoSet("sso-scopes", c.scopes);
  _ssoSet("sso-username-claim", c.username_claim);
  _ssoSet("sso-email-claim", c.email_claim);
  _ssoSet("sso-name-claim", c.name_claim);
  _ssoSet("sso-role-claim", c.role_claim);
  _ssoSet("sso-tenant-claim", c.tenant_claim);
  _ssoSet("sso-role-map", JSON.stringify(c.role_map || {}, null, 0));
  _ssoSet("sso-tenant-map", JSON.stringify(c.tenant_map || {}, null, 0));
  document.getElementById("sso-secret-note").textContent =
    c.client_secret_set ? "A client secret is stored. Leave blank to keep it." : "No client secret set yet.";
  const rn = document.getElementById("sso-ready-note");
  rn.textContent = c.ready ? "✓ SSO is configured; the login button is live."
                           : "Fill in issuer, client ID, secret and redirect URI, then enable.";
  rn.style.color = c.ready ? "var(--ok, #2a7)" : "var(--fg-muted)";
}

document.getElementById("sso-save")?.addEventListener("click", async () => {
  const st = document.getElementById("sso-status");
  const payload = {
    enabled: document.getElementById("sso-enabled").checked,
    issuer: _ssoGet("sso-issuer"), client_id: _ssoGet("sso-client-id"),
    redirect_uri: _ssoGet("sso-redirect-uri"), scopes: _ssoGet("sso-scopes"),
    username_claim: _ssoGet("sso-username-claim"), email_claim: _ssoGet("sso-email-claim"),
    name_claim: _ssoGet("sso-name-claim"), role_claim: _ssoGet("sso-role-claim"),
    tenant_claim: _ssoGet("sso-tenant-claim"),
  };
  const sec = document.getElementById("sso-client-secret").value;
  if (sec) payload.client_secret = sec;                 // only send when changed
  for (const [k, id] of [["role_map", "sso-role-map"], ["tenant_map", "sso-tenant-map"]]) {
    const raw = _ssoGet(id);
    if (raw) {
      try { JSON.parse(raw); } catch (e) {
        setStatus(st, `${k} is not valid JSON`, "err"); return;
      }
    }
    payload[k] = raw || "{}";
  }
  const r = await jsonReq("/admin/sso-config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (r.ok) { setStatus(st, "Saved", "ok"); refreshSso(); }
  else setStatus(st, (r.body && r.body.error) || "Save failed", "err");
});
// The Single sign-on panel hosts OIDC + SAML as sub-tabs; load both when opened.
function _refreshSsoPanel() { refreshSso(); refreshSaml(); }
document.getElementById("sso-refresh")?.addEventListener("click", _refreshSsoPanel);
document.querySelector('#admin-nav button[data-panel="sso"]')
  ?.addEventListener("click", _refreshSsoPanel);
// OIDC / SAML sub-tab switch within the Single sign-on panel.
document.querySelectorAll("#sso-subtabs .subtab").forEach(b => {
  b.addEventListener("click", () => {
    const name = b.dataset.subtab;
    document.querySelectorAll("#sso-subtabs .subtab")
      .forEach(x => x.classList.toggle("active", x === b));
    document.querySelectorAll('[data-panel="sso"] [data-subtabpanel]')
      .forEach(p => { p.hidden = (p.dataset.subtabpanel !== name); });
  });
});

// ===== Provisioning (SCIM 2.0, Phase C3.4) =====
function _scimShowToken(tok) {
  const wrap = document.getElementById("scim-token-show");
  document.getElementById("scim-token-value").value = tok;
  wrap.hidden = false;
  document.getElementById("scim-token-once").hidden = false;
}

async function refreshScim() {
  const note = document.getElementById("cap-note-scim");
  if (!capAvail("governance.scim")) {
    if (note) {
      const c = _capCache && _capCache["governance.scim"];
      note.textContent = "⚠ " + ((c && c.desc) || "SCIM provisioning")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    return;
  }
  if (note) note.hidden = true;
  // hide any token revealed from a prior generate
  document.getElementById("scim-token-show").hidden = true;
  document.getElementById("scim-token-once").hidden = true;
  const r = await jsonReq("/admin/scim-config");
  if (!r.ok || !r.body) {
    setStatus(document.getElementById("scim-status"),
      r.status === 402 ? "SCIM is a licensed feature." : "Failed to load SCIM config", "err");
    return;
  }
  const c = r.body;
  document.getElementById("scim-enabled").checked = !!c.enabled;
  document.getElementById("scim-base-url").value = c.base_url || "";
  document.getElementById("scim-token-state").textContent = c.token_set
    ? "A bearer token is set. Generate a new one to rotate it (the old one stops working)."
    : "No token yet — generate one to connect your IdP.";
  document.getElementById("scim-revoke-token").disabled = !c.token_set;
}

document.getElementById("scim-enabled")?.addEventListener("change", async (e) => {
  const r = await jsonReq("/admin/scim-config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: e.target.checked }),
  });
  setStatus(document.getElementById("scim-status"),
    r.ok ? (e.target.checked ? "SCIM enabled" : "SCIM disabled") : "Update failed",
    r.ok ? "ok" : "err");
});

document.getElementById("scim-gen-token")?.addEventListener("click", async () => {
  const st = document.getElementById("scim-status");
  if (!confirm("Generate a new SCIM token? Any existing token will immediately stop working."))
    return;
  const r = await jsonReq("/admin/scim-token", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  });
  if (r.ok && r.body && r.body.token) {
    _scimShowToken(r.body.token);                 // shown once, in place
    document.getElementById("scim-token-state").textContent =
      "A bearer token is set. Generate a new one to rotate it (the old one stops working).";
    document.getElementById("scim-revoke-token").disabled = false;
    setStatus(st, "New token generated", "ok");
  } else {
    setStatus(st, (r.body && r.body.error) || "Failed to generate token", "err");
  }
});

document.getElementById("scim-revoke-token")?.addEventListener("click", async () => {
  const st = document.getElementById("scim-status");
  if (!confirm("Revoke the SCIM token and disable provisioning?")) return;
  const r = await jsonReq("/admin/scim-token", { method: "DELETE" });
  if (r.ok) { setStatus(st, "Token revoked; SCIM disabled", "ok"); refreshScim(); }
  else setStatus(st, (r.body && r.body.error) || "Revoke failed", "err");
});

function _copyFrom(id, btnId) {
  const el = document.getElementById(id);
  if (!el || !el.value) return;
  navigator.clipboard?.writeText(el.value);
  const b = document.getElementById(btnId);
  if (b) { const t = b.textContent; b.textContent = "Copied"; setTimeout(() => b.textContent = t, 1200); }
}
document.getElementById("scim-copy-url")?.addEventListener("click", () => _copyFrom("scim-base-url", "scim-copy-url"));
document.getElementById("scim-copy-token")?.addEventListener("click", () => _copyFrom("scim-token-value", "scim-copy-token"));
document.getElementById("scim-refresh")?.addEventListener("click", refreshScim);

// ===== SAML 2.0 SSO (Phase C3.3b) =====
function _samlSet(id, v) { const el = document.getElementById(id); if (el) el.value = v == null ? "" : v; }
function _samlGet(id) { const el = document.getElementById(id); return el ? el.value.trim() : ""; }

async function refreshSaml() {
  const note = document.getElementById("cap-note-saml");
  if (!capAvail("governance.saml")) {
    if (note) {
      const c = _capCache && _capCache["governance.saml"];
      // governance.saml's env req (saml_lib) surfaces here too - the reason text
      // already explains "needs saml_lib" when the library isn't installed.
      note.textContent = "⚠ " + ((c && c.desc) || "SAML SSO")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
  } else if (note) {
    note.hidden = true;
  }
  // Admin config is reachable whenever entitled (license), even if the library
  // isn't installed yet - so try to load it regardless of capAvail (which also
  // factors the env lib). A 402 means truly not licensed.
  const r = await jsonReq("/admin/saml-config");
  if (!r.ok || !r.body) {
    if (r.status === 402) return;     // not licensed; cap-note already shown
    setStatus(document.getElementById("saml-status"), "Failed to load SAML config", "err");
    return;
  }
  const c = r.body;
  const libNote = document.getElementById("saml-lib-note");
  if (!c.lib_available) {
    libNote.textContent = "⚠ The SAML library is not installed on the server. "
      + "You can configure SAML now; install python3-saml to activate it.";
    libNote.style.color = "var(--warning)";
    libNote.hidden = false;
  } else {
    libNote.hidden = true;
  }
  document.getElementById("saml-enabled").checked = !!c.enabled;
  _samlSet("saml-idp-entity-id", c.idp_entity_id);
  _samlSet("saml-idp-sso-url", c.idp_sso_url);
  _samlSet("saml-idp-slo-url", c.idp_slo_url);
  _samlSet("saml-idp-x509cert", c.idp_x509cert);
  _samlSet("saml-sp-entity-id", c.sp_entity_id || c.sp_entity_id_suggested || "");
  _samlSet("saml-acs-url", c.acs_url || c.acs_url_suggested || "");
  _samlSet("saml-username-attr", c.username_attr);
  _samlSet("saml-email-attr", c.email_attr);
  _samlSet("saml-name-attr", c.name_attr);
  _samlSet("saml-role-attr", c.role_attr);
  _samlSet("saml-tenant-attr", c.tenant_attr);
  _samlSet("saml-role-map", JSON.stringify(c.role_map || {}, null, 0));
  _samlSet("saml-tenant-map", JSON.stringify(c.tenant_map || {}, null, 0));
  const link = document.getElementById("saml-metadata-link");
  if (link) link.href = "/csr/api/auth/saml/metadata";
  const rn = document.getElementById("saml-ready-note");
  rn.textContent = c.ready ? "✓ SAML is configured and active; the login button is live."
    : (c.lib_available ? "Fill in the IdP details and SP URLs, then enable."
                       : "Install the SAML library on the server to activate.");
  rn.style.color = c.ready ? "var(--ok, #2a7)" : "var(--fg-muted)";
}

document.getElementById("saml-save")?.addEventListener("click", async () => {
  const st = document.getElementById("saml-status");
  const payload = {
    enabled: document.getElementById("saml-enabled").checked,
    idp_entity_id: _samlGet("saml-idp-entity-id"), idp_sso_url: _samlGet("saml-idp-sso-url"),
    idp_slo_url: _samlGet("saml-idp-slo-url"), idp_x509cert: _samlGet("saml-idp-x509cert"),
    sp_entity_id: _samlGet("saml-sp-entity-id"), acs_url: _samlGet("saml-acs-url"),
    username_attr: _samlGet("saml-username-attr"), email_attr: _samlGet("saml-email-attr"),
    name_attr: _samlGet("saml-name-attr"), role_attr: _samlGet("saml-role-attr"),
    tenant_attr: _samlGet("saml-tenant-attr"),
  };
  for (const [k, id] of [["role_map", "saml-role-map"], ["tenant_map", "saml-tenant-map"]]) {
    const raw = _samlGet(id);
    if (raw) {
      try { JSON.parse(raw); } catch (e) {
        setStatus(st, `${k} is not valid JSON`, "err"); return;
      }
    }
    payload[k] = raw || "{}";
  }
  const r = await jsonReq("/admin/saml-config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (r.ok) { setStatus(st, "Saved", "ok"); refreshSaml(); }
  else setStatus(st, (r.body && r.body.error) || "Save failed", "err");
});
document.getElementById("saml-refresh")?.addEventListener("click", refreshSaml);

// ===== Issuance policy (Phase C4.1) =====
function _polFmt(obj) { return JSON.stringify(obj || {}, null, 2); }

async function refreshPolicy() {
  const note = document.getElementById("cap-note-policy");
  if (!capAvail("policy.engine")) {
    if (note) {
      const c = _capCache && _capCache["policy.engine"];
      note.textContent = "⚠ " + ((c && c.desc) || "Issuance policy engine")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    return;
  }
  if (note) note.hidden = true;
  const r = await jsonReq("/admin/policy/global");
  if (!r.ok || !r.body) {
    setStatus(document.getElementById("policy-global-status"),
      r.status === 402 ? "Policy engine is a licensed feature." : "Failed to load policy", "err");
    return;
  }
  document.getElementById("policy-global").value = _polFmt(r.body.policy);
  const kk = document.getElementById("policy-known-keys");
  if (kk) kk.textContent = (r.body.known_keys || []).join(", ");
  const sr = await jsonReq("/admin/policy/settings");
  if (sr.ok && sr.body) document.getElementById("policy-block-request").checked = !!sr.body.block_at_request;
  // Tenant layer only when multi-tenancy is licensed; populate the selector.
  const tw = document.getElementById("policy-tenant-wrap");
  if (capAvail("governance.multitenancy")) {
    tw.hidden = false;
    const tr = await jsonReq("/admin/tenants");
    const sel = document.getElementById("policy-tenant-select");
    if (tr.ok && tr.body && sel) {
      sel.innerHTML = (tr.body.tenants || []).filter(t => t.slug !== "default")
        .map(t => `<option value="${escapeHtml(t.slug)}">${escapeHtml(t.name)} (${escapeHtml(t.slug)})</option>`).join("")
        || '<option value="">(no tenants yet)</option>';
    }
  } else {
    tw.hidden = true;
  }
}

function _policySaveDoc(textId, statusId, url) {
  const st = document.getElementById(statusId);
  const raw = document.getElementById(textId).value.trim();
  let doc;
  try { doc = raw ? JSON.parse(raw) : {}; }
  catch (e) { setStatus(st, "Not valid JSON: " + e.message, "err"); return Promise.resolve(); }
  return jsonReq(url, {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ policy: doc }),
  }).then(r => setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Save failed"),
                         r.ok ? "ok" : "err"));
}

document.getElementById("policy-global-save")?.addEventListener("click", () =>
  _policySaveDoc("policy-global", "policy-global-status", "/admin/policy/global"));

document.getElementById("policy-block-request")?.addEventListener("change", async (e) => {
  const r = await jsonReq("/admin/policy/settings", {
    method: "PUT", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ block_at_request: e.target.checked }),
  });
  setStatus(document.getElementById("policy-global-status"),
    r.ok ? "Saved" : "Update failed", r.ok ? "ok" : "err");
});

document.getElementById("policy-tenant-load")?.addEventListener("click", async () => {
  const slug = document.getElementById("policy-tenant-select").value;
  if (!slug) return;
  const r = await jsonReq("/admin/policy/tenant/" + encodeURIComponent(slug));
  if (r.ok && r.body) document.getElementById("policy-tenant").value = _polFmt(r.body.policy);
});
document.getElementById("policy-tenant-save")?.addEventListener("click", () => {
  const slug = document.getElementById("policy-tenant-select").value;
  if (!slug) return;
  _policySaveDoc("policy-tenant", "policy-tenant-status", "/admin/policy/tenant/" + encodeURIComponent(slug));
});

document.getElementById("policy-preview-run")?.addEventListener("click", async () => {
  const st = document.getElementById("policy-preview-status");
  const csr = document.getElementById("policy-preview-csr").value.trim();
  if (csr.indexOf("REQUEST") < 0) { setStatus(st, "Paste a PEM CSR first", "err"); return; }
  const body = { csr_pem: csr };
  const tid = document.getElementById("policy-preview-template").value.trim();
  const ct = document.getElementById("policy-preview-certtype").value.trim();
  if (tid) body.template_id = tid;
  if (ct) body.cert_type = ct;
  setStatus(st, "Testing…");
  const r = await jsonReq("/admin/policy/preview", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
  });
  if (!r.ok || !r.body) { setStatus(st, (r.body && r.body.error) || "Preview failed", "err"); return; }
  setStatus(st, "");
  const wrap = document.getElementById("policy-preview-result");
  wrap.hidden = false;
  const verdict = document.getElementById("policy-preview-verdict");
  verdict.textContent = r.body.allowed ? "✓ This request would be PERMITTED" : "✗ This request would be REFUSED";
  verdict.style.color = r.body.allowed ? "var(--ok)" : "var(--danger)";
  document.getElementById("policy-preview-violations").innerHTML =
    (r.body.violations || []).map(v => `<li>${escapeHtml(v.detail)}</li>`).join("");
  document.getElementById("policy-preview-detail").textContent =
    "Effective policy:\n" + _polFmt(r.body.effective) + "\n\nParsed request:\n" + _polFmt(r.body.attributes);
});

document.getElementById("policy-refresh")?.addEventListener("click", refreshPolicy);

// ===== Observability / Prometheus metrics (Phase C6.1) =====
function _metricsShowToken(tok) {
  document.getElementById("metrics-token-value").value = tok;
  document.getElementById("metrics-token-show").hidden = false;
  document.getElementById("metrics-token-once").hidden = false;
}

async function refreshMetrics() {
  const note = document.getElementById("cap-note-metrics");
  if (!capAvail("integrations.metrics")) {
    if (note) {
      const c = _capCache && _capCache["integrations.metrics"];
      note.textContent = "⚠ " + ((c && c.desc) || "Prometheus metrics")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    return;
  }
  if (note) note.hidden = true;
  document.getElementById("metrics-token-show").hidden = true;
  document.getElementById("metrics-token-once").hidden = true;
  const r = await jsonReq("/admin/metrics-config");
  if (!r.ok || !r.body) {
    setStatus(document.getElementById("metrics-status"),
      r.status === 402 ? "Metrics is a licensed feature." : "Failed to load", "err");
    return;
  }
  document.getElementById("metrics-enabled").checked = !!r.body.enabled;
  document.getElementById("metrics-url").value = r.body.scrape_url || "";
  document.getElementById("metrics-token-state").textContent = r.body.token_set
    ? "A scrape token is set. Generate a new one to rotate it."
    : "No token yet — generate one for your Prometheus scraper.";
  document.getElementById("metrics-revoke-token").disabled = !r.body.token_set;
}

document.getElementById("metrics-enabled")?.addEventListener("change", async (e) => {
  const r = await jsonReq("/admin/metrics-config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled: e.target.checked }),
  });
  setStatus(document.getElementById("metrics-status"),
    r.ok ? (e.target.checked ? "Metrics enabled" : "Metrics disabled") : "Update failed",
    r.ok ? "ok" : "err");
});
document.getElementById("metrics-gen-token")?.addEventListener("click", async () => {
  const st = document.getElementById("metrics-status");
  if (!confirm("Generate a new scrape token? Any existing token stops working.")) return;
  const r = await jsonReq("/admin/metrics-token", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  });
  if (r.ok && r.body && r.body.token) {
    _metricsShowToken(r.body.token);
    document.getElementById("metrics-token-state").textContent =
      "A scrape token is set. Generate a new one to rotate it.";
    document.getElementById("metrics-revoke-token").disabled = false;
    setStatus(st, "Token generated", "ok");
  } else setStatus(st, (r.body && r.body.error) || "Failed", "err");
});
document.getElementById("metrics-revoke-token")?.addEventListener("click", async () => {
  const st = document.getElementById("metrics-status");
  if (!confirm("Revoke the scrape token and disable /metrics?")) return;
  const r = await jsonReq("/admin/metrics-token", { method: "DELETE" });
  if (r.ok) { setStatus(st, "Revoked; metrics disabled", "ok"); refreshMetrics(); }
  else setStatus(st, "Revoke failed", "err");
});
document.getElementById("metrics-copy-url")?.addEventListener("click", () => _copyFrom("metrics-url", "metrics-copy-url"));
document.getElementById("metrics-copy-token")?.addEventListener("click", () => _copyFrom("metrics-token-value", "metrics-copy-token"));
document.getElementById("metrics-refresh")?.addEventListener("click", () => { refreshMetrics(); refreshSiem(); });
document.querySelector('#admin-nav button[data-panel="observability"]')
  ?.addEventListener("click", () => { refreshMetrics(); refreshSiem(); });

// SIEM / CEF forwarder (Phase C6.2)
async function refreshSiem() {
  if (!capAvail("integrations.siem")) return;
  const r = await jsonReq("/admin/siem-config");
  if (!r.ok || !r.body) return;
  document.getElementById("siem-enabled").checked = !!r.body.enabled;
  document.getElementById("siem-host").value = r.body.host || "";
  document.getElementById("siem-port").value = r.body.port || 514;
  document.getElementById("siem-proto").value = r.body.proto || "udp";
  document.getElementById("siem-hostname").value = r.body.hostname || "";
}
function _siemPayload() {
  return {
    enabled: document.getElementById("siem-enabled").checked,
    host: document.getElementById("siem-host").value.trim(),
    port: document.getElementById("siem-port").value.trim() || 514,
    proto: document.getElementById("siem-proto").value,
    hostname: document.getElementById("siem-hostname").value.trim(),
  };
}
document.getElementById("siem-save")?.addEventListener("click", async () => {
  const st = document.getElementById("siem-status");
  const r = await jsonReq("/admin/siem-config", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(_siemPayload()),
  });
  setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Save failed"), r.ok ? "ok" : "err");
});
document.getElementById("siem-test")?.addEventListener("click", async () => {
  const st = document.getElementById("siem-status");
  setStatus(st, "Sending…");
  await jsonReq("/admin/siem-config", {           // save current form first
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(_siemPayload()),
  });
  const r = await jsonReq("/admin/siem-test", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
  });
  const ok = r.body && r.body.ok;
  setStatus(st, ok ? "Test event sent ✓"
    : ("Test failed: " + ((r.body && r.body.reason) || "unknown")), ok ? "ok" : "err");
});

// ===== Automation API tokens (Phase C6.3) =====
async function refreshApiTokens() {
  const note = document.getElementById("cap-note-apitok");
  if (!capAvail("integrations.api")) {
    if (note) {
      const c = _capCache && _capCache["integrations.api"];
      note.textContent = "⚠ " + ((c && c.desc) || "Automation API")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    return;
  }
  if (note) note.hidden = true;
  document.getElementById("apitok-new-wrap").hidden = true;
  document.getElementById("apitok-once").hidden = true;
  const r = await jsonReq("/admin/api-tokens");
  const tb = document.getElementById("apitok-tbody");
  if (!r.ok || !r.body) { tb.innerHTML = ""; return; }
  tb.innerHTML = (r.body.tokens || []).map(t => `<tr>
      <td>${escapeHtml(t.name)}</td>
      <td class="muted">${escapeHtml(t.template_ids || "any")}</td>
      <td class="muted">${t.last_used_at ? new Date(t.last_used_at * 1000).toLocaleString() : "never"}</td>
      <td><button class="link-btn" data-apitok-del="${escapeHtml(t.id)}" style="color:var(--danger)">Revoke</button></td>
    </tr>`).join("") || '<tr><td colspan="4" class="status">No tokens yet.</td></tr>';
}
document.getElementById("apitok-create")?.addEventListener("click", async () => {
  const st = document.getElementById("apitok-status");
  const name = document.getElementById("apitok-name").value.trim();
  if (!name) { setStatus(st, "Name is required", "err"); return; }
  const tids = document.getElementById("apitok-templates").value.trim();
  const r = await jsonReq("/admin/api-tokens", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, template_ids: tids || undefined }),
  });
  if (r.ok && r.body && r.body.token) {
    await refreshApiTokens();
    document.getElementById("apitok-new-value").value = r.body.token;  // after refresh (it hides it)
    document.getElementById("apitok-new-wrap").hidden = false;
    document.getElementById("apitok-once").hidden = false;
    document.getElementById("apitok-name").value = "";
    document.getElementById("apitok-templates").value = "";
    setStatus(st, "Created", "ok");
  } else setStatus(st, (r.body && r.body.error) || "Create failed", "err");
});
document.getElementById("apitok-tbody")?.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-apitok-del]");
  if (!b) return;
  if (!confirm("Revoke this API token? Callers using it will stop working.")) return;
  const r = await jsonReq("/admin/api-tokens/" + encodeURIComponent(b.getAttribute("data-apitok-del")),
    { method: "DELETE" });
  setStatus(document.getElementById("apitok-status"), r.ok ? "Revoked" : "Revoke failed", r.ok ? "ok" : "err");
  if (r.ok) refreshApiTokens();
});
document.getElementById("apitok-copy")?.addEventListener("click", () => _copyFrom("apitok-new-value", "apitok-copy"));
document.getElementById("apitok-refresh")?.addEventListener("click", refreshApiTokens);
document.querySelector('#admin-nav button[data-panel="apitokens"]')
  ?.addEventListener("click", refreshApiTokens);

// ===== Crypto posture — CBOM & PQC readiness (Phase C7.1) =====
async function refreshCbom() {
  const note = document.getElementById("cap-note-cbom");
  if (!capAvail("crypto.cbom")) {
    if (note) {
      const c = _capCache && _capCache["crypto.cbom"];
      note.textContent = "⚠ " + ((c && c.desc) || "Crypto posture (CBOM)")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    return;
  }
  if (note) note.hidden = true;
  const r = await jsonReq("/admin/cbom");
  if (!r.ok || !r.body) return;
  const b = r.body;
  const stat = (label, val) =>
    `<div class="stat-tile"><div class="value">${val}</div>
       <div class="label">${label}</div></div>`;
  document.getElementById("cbom-stats").innerHTML =
    stat("Total certs", b.total) +
    stat("Quantum-vulnerable", b.quantum_vulnerable) +
    stat("Deprecated", b.deprecated) +
    stat("PQC-ready", b.pqc_ready);
  document.getElementById("cbom-algos").innerHTML =
    Object.entries(b.by_algorithm || {}).sort((a, c) => c[1] - a[1])
      .map(([k, v]) => `<tr><td>${escapeHtml(k)}</td><td>${v}</td></tr>`).join("")
    || '<tr><td colspan="2" class="status">No certificates in inventory.</td></tr>';
  document.getElementById("cbom-worklist").innerHTML =
    (b.migration_worklist || []).map(w => `<tr>
        <td>${escapeHtml(w.cn || "—")}</td>
        <td>${escapeHtml(w.algorithm || "")}</td>
        <td class="muted">${escapeHtml(w.expires_at || "—")}</td>
        <td class="muted">${escapeHtml((w.reasons || []).join("; "))}</td>
      </tr>`).join("")
    || '<tr><td colspan="4" class="status">Nothing to migrate — clean posture.</td></tr>';
}
document.getElementById("cbom-refresh")?.addEventListener("click", refreshCbom);
document.querySelector('#admin-nav button[data-panel="cbom"]')
  ?.addEventListener("click", refreshCbom);

// ===== SSH certificate authority (Phase C7.2) =====
async function refreshSshCa() {
  const note = document.getElementById("cap-note-sshca");
  if (!capAvail("crypto.ssh_ca")) {
    if (note) {
      const c = _capCache && _capCache["crypto.ssh_ca"];
      note.textContent = "⚠ " + ((c && c.desc) || "SSH certificate authority")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    return;
  }
  if (note) note.hidden = true;
  const r = await jsonReq("/admin/ssh-ca");
  if (r.ok && r.body) {
    const cs = document.getElementById("sshca-castatus");
    cs.textContent = r.body.configured ? ("CA: " + (r.body.fingerprint || "configured")) : "CA: not configured";
    document.getElementById("sshca-capub").value = r.body.public_key || "";
  }
  const lr = await jsonReq("/admin/ssh-ca/certs");
  const tb = document.getElementById("sshca-certs");
  if (lr.ok && lr.body) {
    tb.innerHTML = (lr.body.certs || []).map(c => `<tr>
        <td>${escapeHtml(c.key_id)}</td>
        <td>${escapeHtml(c.kind)}</td>
        <td class="muted">${c.serial ?? "—"}</td>
        <td class="muted">${escapeHtml(c.principals || "")}</td>
        <td class="muted">${escapeHtml(c.valid_to || "—")}</td>
        <td>${c.revoked ? '<span class="pill pill-pending">revoked</span>' : '<span class="pill pill-blue">active</span>'}</td>
        <td>${c.revoked ? "" : `<button class="link-btn" data-sshca-revoke="${escapeHtml(c.id)}" style="color:var(--danger)">Revoke</button>`}</td>
      </tr>`).join("") || '<tr><td colspan="7" class="status">No certificates issued yet.</td></tr>';
  }
}
document.getElementById("sshca-generate")?.addEventListener("click", async () => {
  const st = document.getElementById("sshca-status");
  if (!confirm("Generate a new SSH CA key? If one exists it will be replaced and existing certs become untrusted.")) return;
  let r = await jsonReq("/admin/ssh-ca/generate", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  if (r.status === 409 && confirm("A CA key already exists. Replace it?")) {
    r = await jsonReq("/admin/ssh-ca/generate", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ force: true }) });
  }
  setStatus(st, r.ok ? "CA generated" : ((r.body && r.body.detail) || "Failed"), r.ok ? "ok" : "err");
  if (r.ok) refreshSshCa();
});
document.getElementById("sshca-sign")?.addEventListener("click", async () => {
  const st = document.getElementById("sshca-status");
  const body = {
    public_key: document.getElementById("sshca-pubkey").value.trim(),
    kind: document.getElementById("sshca-kind").value,
    key_id: document.getElementById("sshca-keyid").value.trim(),
    principals: document.getElementById("sshca-principals").value.trim(),
    validity_days: parseInt(document.getElementById("sshca-days").value, 10) || 365,
  };
  if (!body.public_key || !body.key_id || !body.principals) {
    setStatus(st, "Public key, key ID and principals are required", "err"); return;
  }
  const r = await jsonReq("/admin/ssh-ca/sign", {
    method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  if (r.ok && r.body && r.body.certificate) {
    document.getElementById("sshca-result").value = r.body.certificate;
    document.getElementById("sshca-result-wrap").hidden = false;
    setStatus(st, "Signed (serial " + r.body.serial + ")", "ok");
    refreshSshCa();
  } else setStatus(st, (r.body && r.body.detail) || "Sign failed", "err");
});
document.getElementById("sshca-certs")?.addEventListener("click", async (e) => {
  const b = e.target.closest("[data-sshca-revoke]");
  if (!b) return;
  if (!confirm("Revoke this SSH certificate? It will be added to the KRL.")) return;
  const r = await jsonReq("/admin/ssh-ca/certs/" + encodeURIComponent(b.getAttribute("data-sshca-revoke")) + "/revoke",
    { method: "POST" });
  setStatus(document.getElementById("sshca-status"), r.ok ? "Revoked" : "Revoke failed", r.ok ? "ok" : "err");
  if (r.ok) refreshSshCa();
});
document.getElementById("sshca-copy")?.addEventListener("click", () => _copyFrom("sshca-result", "sshca-copy"));
document.getElementById("sshca-refresh")?.addEventListener("click", refreshSshCa);
document.querySelector('#admin-nav button[data-panel="sshca"]')
  ?.addEventListener("click", refreshSshCa);

// ===== Admin: NetScaler DNSSEC key rollover (crypto.dnssec) =====
async function refreshDnssec() {
  const note = document.getElementById("cap-note-dnssec");
  const tb = document.getElementById("dnssec-zones");
  if (!capAvail("crypto.dnssec")) {
    if (note) {
      const c = _capCache && _capCache["crypto.dnssec"];
      note.textContent = "⚠ " + ((c && c.desc) || "DNSSEC key-lifecycle automation")
        + ((c && c.reason) ? " — " + c.reason : " — not licensed");
      note.hidden = false;
    }
    if (tb) tb.innerHTML = '<tr><td colspan="8" class="status">Not available in this edition.</td></tr>';
    return;
  }
  if (note) note.hidden = true;
  // automatic-rollover schedule
  const sch = await jsonReq("/admin/dnssec/schedule");
  if (sch.ok && sch.body && sch.body.schedule) {
    const s = sch.body.schedule;
    const en = document.getElementById("dnssec-sched-enabled");
    const iv = document.getElementById("dnssec-sched-interval");
    const info = document.getElementById("dnssec-sched-info");
    if (en) en.checked = !!s.enabled;
    if (iv) iv.value = String(s.interval_min || 360);
    if (info) info.textContent = s.enabled
      ? (s.next_run_at ? "Next check ~ " + new Date(s.next_run_at * 1000).toLocaleString()
         : "Enabled — first check shortly")
      : "Automatic rollover is off";
  }
  const r = await jsonReq("/admin/dnssec/zones");
  if (!tb) return;
  if (!r.ok) { tb.innerHTML = '<tr><td colspan="8" class="status err">Failed to load.</td></tr>'; return; }
  const zones = (r.body && r.body.zones) || [];
  const roleCell = (ro, role) => {
    const s = (ro && ro[role]) || {};
    return `<span class="pill pill-blue">${escapeHtml(s.phase || "—")}</span>`
      + (s.active_key ? `<div class="status" style="font-size:11px">${escapeHtml(s.active_key)}</div>` : "");
  };
  tb.innerHTML = zones.map(z => `<tr>
      <td>${escapeHtml(z.netscaler_host)}</td>
      <td>${escapeHtml(z.zone)}</td>
      <td>${roleCell(z.rollover, "KSK")}</td>
      <td>${roleCell(z.rollover, "ZSK")}</td>
      <td>${z.dry_run ? '<span class="pill pill-pending">dry-run</span>' : '<span class="pill pill-ok">live</span>'}${z.enabled ? "" : ' <span class="pill">disabled</span>'}</td>
      <td>${z.last_status === "error"
            ? `<span class="pill pill-pending" title="${escapeHtml(z.last_error || "")}">error</span>`
            : (z.last_run_at ? '<span class="pill pill-ok">ok</span>' : '<span class="status">—</span>')}</td>
      <td class="status">${z.last_run_at ? new Date(z.last_run_at * 1000).toLocaleString() : "—"}</td>
      <td>
        <button class="link-btn" data-dnssec-run="${z.id}">Run now</button>
        <button class="link-btn" data-dnssec-live="${z.id}" data-dry="${z.dry_run ? 1 : 0}">${z.dry_run ? "Go live" : "Dry-run"}</button>
        <button class="link-btn" data-dnssec-en="${z.id}" data-en="${z.enabled ? 1 : 0}">${z.enabled ? "Disable" : "Enable"}</button>
        <button class="link-btn" data-dnssec-del="${z.id}" style="color:var(--danger)">Delete</button>
      </td>
    </tr>`).join("") || '<tr><td colspan="8" class="status">No managed zones yet.</td></tr>';
}

document.getElementById("dnssec-add")?.addEventListener("click", async () => {
  const status = document.getElementById("dnssec-add-status");
  const g = id => document.getElementById(id);
  const body = {
    netscaler_host: g("dnssec-host").value.trim(), zone: g("dnssec-zone").value.trim(),
    algorithm: g("dnssec-alg").value, keysize: parseInt(g("dnssec-keysize").value) || 2048,
    ttl_seconds: parseInt(g("dnssec-ttl").value) || 3600,
    zsk_rollover_days: parseInt(g("dnssec-zsk").value) || 21,
    ksk_rollover_days: parseInt(g("dnssec-ksk").value) || 30,
    cds_auto: g("dnssec-cds").checked,
  };
  if (!body.netscaler_host || !body.zone) { setStatus(status, "host and zone are required", "err"); return; }
  setStatus(status, "Adding…");
  const r = await jsonReq("/admin/dnssec/zones", { method: "POST", body: JSON.stringify(body) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Failed", "err"); return; }
  setStatus(status, "Added — starts in dry-run", "ok");
  g("dnssec-host").value = ""; g("dnssec-zone").value = "";
  refreshDnssec();
});

document.getElementById("dnssec-zones")?.addEventListener("click", async (e) => {
  const t = e.target.closest("button"); if (!t) return;
  const d = t.dataset;
  if (d.dnssecRun) {
    t.disabled = true; t.textContent = "Running…";
    await jsonReq(`/admin/dnssec/zones/${d.dnssecRun}/run`, { method: "POST" });
    refreshDnssec();
  } else if (d.dnssecLive) {
    await jsonReq(`/admin/dnssec/zones/${d.dnssecLive}`, { method: "PUT",
      body: JSON.stringify({ dry_run: d.dry !== "1" }) });   // toggle
    refreshDnssec();
  } else if (d.dnssecEn) {
    await jsonReq(`/admin/dnssec/zones/${d.dnssecEn}`, { method: "PUT",
      body: JSON.stringify({ enabled: d.en !== "1" }) });
    refreshDnssec();
  } else if (d.dnssecDel) {
    if (!confirm("Remove this managed zone from Certheim? (does not touch the appliance)")) return;
    await jsonReq(`/admin/dnssec/zones/${d.dnssecDel}`, { method: "DELETE" });
    refreshDnssec();
  }
});

document.getElementById("dnssec-sched-save")?.addEventListener("click", async () => {
  const info = document.getElementById("dnssec-sched-info");
  const body = {
    enabled: document.getElementById("dnssec-sched-enabled").checked,
    interval_min: parseInt(document.getElementById("dnssec-sched-interval").value) || 360,
  };
  setStatus(info, "Saving…");
  const r = await jsonReq("/admin/dnssec/schedule", { method: "PUT", body: JSON.stringify(body) });
  setStatus(info, r.ok ? "Saved" : ((r.body && r.body.error) || "Failed"), r.ok ? "ok" : "err");
  if (r.ok) refreshDnssec();
});

document.getElementById("dnssec-refresh")?.addEventListener("click", refreshDnssec);
document.querySelector('#admin-nav button[data-panel="dnssec"]')
  ?.addEventListener("click", refreshDnssec);

// ===== Admin: Encrypted keystore (built-in, no external vault) =====
// Envelope-encrypted secret store with a seal/unseal lifecycle. The one-time
// material (recovery code / Shamir shares) is shown once and never re-fetched.
function _skShow(id, show) {
  const el = document.getElementById(id);
  if (el) el.hidden = !show;
}

async function refreshSealedKeystore() {
  const banner = document.getElementById("sk-status-banner");
  if (!banner) return;
  const r = await jsonReq("/admin/sealed-keystore");
  if (!r.ok) { banner.textContent = "Failed to load keystore status."; return; }
  const s = r.body;
  _skRenderStatus(s);
}

function _skRenderStatus(s) {
  const banner = document.getElementById("sk-status-banner");
  // hide everything, then reveal the cards for the current state
  ["sk-init-card", "sk-unseal-card", "sk-unsealed-card"].forEach(id => _skShow(id, false));
  if (!s.initialized) {
    banner.innerHTML = '<span class="pill pill-mute">Not initialized</span> ' +
      "Choose a protection model and cipher below to create the keystore.";
    _skShow("sk-init-card", true);
    _skPopulateCiphers(s.ciphers || []);
    _skSyncInitMode();
    return;
  }
  if (s.sealed) {
    const modeTxt = s.mode === "shamir" ? `Shamir (${s.k}-of-${s.n})` : "passphrase";
    banner.innerHTML = '<span class="pill pill-warn">Sealed</span> ' +
      `Protection: ${modeTxt}. Provide the unseal material to unlock stored secrets.`;
    _skShow("sk-unseal-card", true);
    _skShow("sk-unseal-passphrase", s.mode === "passphrase");
    _skShow("sk-unseal-recovery", s.mode === "passphrase");
    _skShow("sk-unseal-shamir", s.mode === "shamir");
    return;
  }
  const cipherLbl = (s.ciphers || []).find(c => c.name === s.cipher);
  banner.innerHTML = '<span class="pill pill-ok">Unsealed</span> ' +
    "The keystore is unlocked. Store secrets or route generated keys here " +
    "(Signing / CA → key storage → Encrypted keystore)." +
    (cipherLbl ? ` <span class="hint">Cipher: ${escapeHtml(cipherLbl.label)}.</span>` : "");
  _skShow("sk-unsealed-card", true);
  _skLoadSecrets();
}

// Populate the init cipher dropdown from the security scale (highest first).
// Unavailable tiers (their optional library isn't installed) are disabled.
function _skPopulateCiphers(ciphers) {
  const sel = document.getElementById("sk-init-cipher");
  if (!sel || !ciphers.length) return;
  sel.innerHTML = ciphers.map((c, i) => {
    const scale = "★".repeat(c.rank) + "☆".repeat(3 - c.rank);
    const tail = c.available ? "" : " — requires the cryptography package (not installed)";
    return `<option value="${c.name}"${c.available ? "" : " disabled"}${i === 0 && c.available ? " selected" : ""}>` +
      `${scale}  ${escapeHtml(c.label)}${tail}</option>`;
  }).join("");
  // default selection = highest available tier
  const firstAvail = ciphers.find(c => c.available);
  if (firstAvail) sel.value = firstAvail.name;
  _skCipherNote();
}
function _skCipherNote() {
  const sel = document.getElementById("sk-init-cipher");
  const note = document.getElementById("sk-init-cipher-note");
  if (!sel || !note) return;
  const opt = sel.options[sel.selectedIndex];
  note.textContent = opt ? opt.textContent.replace(/^[★☆]+\s*/, "Selected: ") : "";
}
document.getElementById("sk-init-cipher")?.addEventListener("change", _skCipherNote);

function _skSyncInitMode() {
  const mode = (document.getElementById("sk-init-mode") || {}).value || "passphrase";
  _skShow("sk-init-passphrase", mode === "passphrase");
  _skShow("sk-init-shamir", mode === "shamir");
}
document.getElementById("sk-init-mode")?.addEventListener("change", _skSyncInitMode);
document.getElementById("sk-refresh-btn")?.addEventListener("click", refreshSealedKeystore);

document.getElementById("sk-init-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("sk-init-status");
  const mode = document.getElementById("sk-init-mode").value;
  const cipher = (document.getElementById("sk-init-cipher") || {}).value || undefined;
  const payload = { mode, cipher };
  if (mode === "passphrase") {
    const p1 = document.getElementById("sk-init-pass1").value;
    const p2 = document.getElementById("sk-init-pass2").value;
    if (p1.length < 8) { setStatus(status, "Passphrase must be at least 8 characters", "err"); return; }
    if (p1 !== p2) { setStatus(status, "Passphrases do not match", "err"); return; }
    payload.passphrase = p1;
  } else {
    payload.n = parseInt(document.getElementById("sk-init-n").value, 10);
    payload.k = parseInt(document.getElementById("sk-init-k").value, 10);
    if (!(payload.k >= 2 && payload.k <= payload.n && payload.n <= 16)) {
      setStatus(status, "Require 2 ≤ K ≤ N ≤ 16", "err"); return;
    }
  }
  setStatus(status, "Initializing…");
  const r = await jsonReq("/admin/sealed-keystore/init", { method: "POST", body: JSON.stringify(payload) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Init failed", "err"); return; }
  setStatus(status, "");
  // clear entered secrets
  ["sk-init-pass1", "sk-init-pass2"].forEach(id => { const e = document.getElementById(id); if (e) e.value = ""; });
  _skShowMaterial(r.body);
});

function _skShowMaterial(body) {
  const out = document.getElementById("sk-material-out");
  if (body.mode === "passphrase") {
    out.textContent = "RECOVERY CODE (unlocks the keystore if the passphrase is lost):\n\n  " +
      body.recovery_code + "\n";
  } else {
    out.textContent = "UNSEAL SHARES — distribute to separate trusted holders.\n" +
      "Any K of these reconstruct the master key; fewer reveal nothing.\n\n" +
      (body.shares || []).map((s, i) => `  Share ${i + 1}: ${s}`).join("\n") + "\n";
  }
  _skShow("sk-init-card", false);
  _skShow("sk-material-card", true);
}
document.getElementById("sk-material-copy")?.addEventListener("click", () => {
  const t = document.getElementById("sk-material-out").textContent;
  navigator.clipboard?.writeText(t);
});
document.getElementById("sk-material-done")?.addEventListener("click", () => {
  document.getElementById("sk-material-out").textContent = "";
  _skShow("sk-material-card", false);
  refreshSealedKeystore();
});

document.getElementById("sk-unseal-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("sk-unseal-status");
  const payload = {};
  const pass = (document.getElementById("sk-unseal-pass") || {}).value || "";
  const rec = (document.getElementById("sk-unseal-rec") || {}).value || "";
  const sharesRaw = (document.getElementById("sk-unseal-shares") || {}).value || "";
  if (sharesRaw.trim()) payload.shares = sharesRaw.split("\n").map(s => s.trim()).filter(Boolean);
  else if (rec.trim()) payload.recovery_code = rec.trim();
  else if (pass) payload.passphrase = pass;
  else { setStatus(status, "Enter the unseal material", "err"); return; }
  setStatus(status, "Unsealing…");
  const r = await jsonReq("/admin/sealed-keystore/unseal", { method: "POST", body: JSON.stringify(payload) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Unseal failed", "err"); return; }
  ["sk-unseal-pass", "sk-unseal-rec", "sk-unseal-shares"].forEach(id => { const e = document.getElementById(id); if (e) e.value = ""; });
  setStatus(status, "");
  _skRenderStatus(r.body);
});

document.getElementById("sk-seal-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("sk-seal-status");
  if (!confirm("Seal the keystore? Stored secrets become unreadable until you unseal again.")) return;
  const r = await jsonReq("/admin/sealed-keystore/seal", { method: "POST" });
  if (!r.ok) { setStatus(status, "Seal failed", "err"); return; }
  _skRenderStatus(r.body);
});

async function _skLoadSecrets() {
  const rows = document.getElementById("sk-secret-rows");
  if (!rows) return;
  const r = await jsonReq("/admin/sealed-keystore/secrets");
  if (!r.ok || r.body.sealed) { rows.innerHTML = '<tr><td colspan="3" class="hint">Unavailable.</td></tr>'; return; }
  const list = r.body.secrets || [];
  if (!list.length) { rows.innerHTML = '<tr><td colspan="3" class="hint">None yet.</td></tr>'; return; }
  rows.innerHTML = list.map(s => `<tr>
      <td class="mono">${escapeHtml(s.name)}</td>
      <td>${escapeHtml(s.updated_at || "—")}</td>
      <td><button class="link-btn sk-del" data-name="${escapeHtml(s.name)}">Delete</button></td>
    </tr>`).join("");
  rows.querySelectorAll(".sk-del").forEach(b => b.addEventListener("click", async () => {
    if (!confirm(`Delete secret "${b.dataset.name}"?`)) return;
    await jsonReq("/admin/sealed-keystore/secrets/" + encodeURIComponent(b.dataset.name), { method: "DELETE" });
    _skLoadSecrets();
  }));
}

document.getElementById("sk-secret-add-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("sk-secret-status");
  const name = document.getElementById("sk-secret-name").value.trim();
  const value = document.getElementById("sk-secret-value").value;
  if (!name || !value) { setStatus(status, "Name and value required", "err"); return; }
  const r = await jsonReq("/admin/sealed-keystore/secrets", { method: "POST", body: JSON.stringify({ name, value }) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Failed", "err"); return; }
  document.getElementById("sk-secret-name").value = "";
  document.getElementById("sk-secret-value").value = "";
  setStatus(status, "Stored", "ok");
  _skLoadSecrets();
});

document.getElementById("sk-backup-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("sk-backup-status");
  const pass = document.getElementById("sk-backup-pass").value;
  if (pass.length < 8) { setStatus(status, "Backup passphrase must be at least 8 characters", "err"); return; }
  setStatus(status, "Exporting…");
  const r = await jsonReq("/admin/sealed-keystore/backup", { method: "POST", body: JSON.stringify({ passphrase: pass }) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Export failed", "err"); return; }
  const blob = new Blob([r.body.bundle], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "certinel-keystore-backup.json";
  a.click();
  setStatus(status, "Backup downloaded. Store it offline.", "ok");
});

document.getElementById("sk-restore-btn")?.addEventListener("click", async () => {
  const status = document.getElementById("sk-backup-status");
  const ta = document.getElementById("sk-backup-out");
  if (ta.style.display === "none") {
    ta.style.display = "block";
    setStatus(status, "Paste a backup bundle above, enter its passphrase, then click Restore again.");
    return;
  }
  const bundle = ta.value.trim();
  const pass = document.getElementById("sk-backup-pass").value;
  if (!bundle) { setStatus(status, "Paste a backup bundle first", "err"); return; }
  setStatus(status, "Restoring…");
  const r = await jsonReq("/admin/sealed-keystore/restore", { method: "POST", body: JSON.stringify({ bundle, passphrase: pass }) });
  if (!r.ok) { setStatus(status, (r.body && r.body.error) || "Restore failed", "err"); return; }
  setStatus(status, `Restored ${r.body.restored}, skipped ${r.body.skipped}.`, "ok");
  ta.value = ""; ta.style.display = "none";
  _skLoadSecrets();
});

// ===== Admin: Enrollment (EST) + software signing (code-sign / RFC 3161 TSA) =====
async function refreshEnrollSign() {
  if (!document.getElementById("est-enabled")) return;
  const note = document.getElementById("cap-note-enrollsign");
  const est = await jsonReq("/admin/est");
  if (est.ok && est.body) {
    document.getElementById("est-enabled").checked = !!est.body.enabled;
    document.getElementById("est-user").value = est.body.auth_user || "";
    const bits = [];
    if (est.body.auth_secret_set) bits.push("secret set");
    if (est.body.ca_chain_present) bits.push("CA chain cached");
    document.getElementById("est-info").textContent =
      "Endpoint: /.well-known/est/ · " + (bits.join(" · ") || "not configured");
    if (note && est.body.capability && !est.body.capability.available) {
      note.textContent = "⚠ " + (est.body.capability.reason || "requires a Commercial license");
      note.hidden = false;
    } else if (note) { note.hidden = true; }
  }
  const cs = await jsonReq("/admin/codesign");
  if (cs.ok && cs.body) {
    document.getElementById("cs-enabled").checked = !!cs.body.enabled;
    document.getElementById("cs-keyref").value = cs.body.key_ref || "";
  }
  const t = await jsonReq("/admin/tsa");
  if (t.ok && t.body) {
    document.getElementById("tsa-enabled").checked = !!t.body.enabled;
    document.getElementById("tsa-keyref").value = t.body.key_ref || "";
    document.getElementById("tsa-policy").value = t.body.policy_oid || "";
    document.getElementById("tsa-info").textContent =
      "Endpoint: POST /tsa · " + (t.body.signer_ready ? "signer ready" : "signer not configured")
      + " · serial " + (t.body.serial || 0);
  }
  const sc = await jsonReq("/admin/scep");
  if (sc.ok && sc.body) {
    document.getElementById("scep-enabled").checked = !!sc.body.enabled;
    document.getElementById("scep-keyref").value = sc.body.key_ref || "";
    document.getElementById("scep-asn1-warn").hidden = !!sc.body.asn1_available;
    document.getElementById("scep-info").textContent =
      "Endpoint: /scep · " + (sc.body.ra_ready ? "RA ready" : "RA not configured")
      + (sc.body.challenge_set ? " · challenge set" : "");
  }
  const cm = await jsonReq("/admin/cmp");
  if (cm.ok && cm.body) {
    document.getElementById("cmp-enabled").checked = !!cm.body.enabled;
    document.getElementById("cmp-asn1-warn").hidden = !!cm.body.asn1crypto;
    document.getElementById("cmp-info").textContent =
      "Endpoint: POST /cmp · " + (cm.body.secret_set ? "shared secret set" : "no shared secret");
  }
  const sm = await jsonReq("/admin/smime");
  const smNote = document.getElementById("smime-note");
  if (sm.ok && sm.body) {
    const cap = sm.body.capability || {};
    let msg = "";
    if (!cap.available) msg = "⚠ " + (cap.reason || "requires a Commercial license");
    else if (!sm.body.local_ca_configured) msg = "⚠ configure a Local CA (Signing / CA) first";
    else if (!sm.body.sealed_ready) msg = "⚠ unseal the encrypted keystore first";
    smNote.textContent = msg; smNote.hidden = !msg;
  }
}
document.getElementById("esn-refresh-btn")?.addEventListener("click", refreshEnrollSign);

document.getElementById("est-save")?.addEventListener("click", async () => {
  const st = document.getElementById("est-status");
  const body = { enabled: document.getElementById("est-enabled").checked,
    auth_user: document.getElementById("est-user").value.trim() };
  const sec = document.getElementById("est-secret").value;
  if (sec) body.auth_secret = sec;
  const r = await jsonReq("/admin/est", { method: "PUT", body: JSON.stringify(body) });
  setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Failed"), r.ok ? "ok" : "err");
  document.getElementById("est-secret").value = "";
  refreshEnrollSign();
});

document.getElementById("cs-save")?.addEventListener("click", async () => {
  const st = document.getElementById("cs-status");
  const body = { enabled: document.getElementById("cs-enabled").checked,
    key_ref: document.getElementById("cs-keyref").value.trim(),
    cert_pem: document.getElementById("cs-cert").value.trim() };
  const r = await jsonReq("/admin/codesign", { method: "PUT", body: JSON.stringify(body) });
  setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Failed"), r.ok ? "ok" : "err");
});

document.getElementById("cs-sign")?.addEventListener("click", async () => {
  const st = document.getElementById("cs-sign-status");
  const f = document.getElementById("cs-artifact").files[0];
  if (!f) { setStatus(st, "Choose a file first", "err"); return; }
  setStatus(st, "Signing…");
  const fd = new FormData(); fd.append("artifact", f);
  const r = await fetch(API + "/admin/codesign/sign", {
    method: "POST", credentials: "same-origin", headers: CSRF, body: fd });
  if (!r.ok) { let e = ""; try { e = (await r.json()).error; } catch (_) {} setStatus(st, e || "Sign failed", "err"); return; }
  const blob = await r.blob();
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = f.name + ".p7s"; a.click();
  setStatus(st, "Signed → " + f.name + ".p7s", "ok");
});

document.getElementById("tsa-save")?.addEventListener("click", async () => {
  const st = document.getElementById("tsa-status");
  const body = { enabled: document.getElementById("tsa-enabled").checked,
    key_ref: document.getElementById("tsa-keyref").value.trim(),
    policy_oid: document.getElementById("tsa-policy").value.trim(),
    cert_pem: document.getElementById("tsa-cert").value.trim() };
  const r = await jsonReq("/admin/tsa", { method: "PUT", body: JSON.stringify(body) });
  setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Failed"), r.ok ? "ok" : "err");
  refreshEnrollSign();
});

document.getElementById("scep-genra")?.addEventListener("click", async () => {
  const st = document.getElementById("scep-status");
  if (!confirm("Generate a new SCEP RA keypair? Devices will encrypt enrollment to this RA.")) return;
  setStatus(st, "Generating…");
  const r = await jsonReq("/admin/scep/generate-ra", { method: "POST" });
  if (!r.ok) { setStatus(st, (r.body && r.body.error) || "Failed", "err"); return; }
  setStatus(st, "RA generated" + (r.body.key_in_keystore ? " (key in encrypted keystore)" : ""), "ok");
  refreshEnrollSign();
});

document.getElementById("scep-save")?.addEventListener("click", async () => {
  const st = document.getElementById("scep-status");
  const body = { enabled: document.getElementById("scep-enabled").checked,
    ra_key_ref: document.getElementById("scep-keyref").value.trim() };
  const ch = document.getElementById("scep-challenge").value;
  if (ch) body.challenge = ch;
  const r = await jsonReq("/admin/scep", { method: "PUT", body: JSON.stringify(body) });
  setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Failed"), r.ok ? "ok" : "err");
  document.getElementById("scep-challenge").value = "";
  refreshEnrollSign();
});

document.getElementById("cmp-save")?.addEventListener("click", async () => {
  const st = document.getElementById("cmp-status");
  const body = { enabled: document.getElementById("cmp-enabled").checked };
  const sec = document.getElementById("cmp-secret").value;
  if (sec) body.shared_secret = sec;
  const r = await jsonReq("/admin/cmp", { method: "PUT", body: JSON.stringify(body) });
  setStatus(st, r.ok ? "Saved" : ((r.body && r.body.error) || "Failed"), r.ok ? "ok" : "err");
  document.getElementById("cmp-secret").value = "";
  refreshEnrollSign();
});

document.getElementById("smime-issue")?.addEventListener("click", async () => {
  const st = document.getElementById("smime-status");
  const payload = {
    name: document.getElementById("smime-name").value.trim(),
    email: document.getElementById("smime-email").value.trim(),
    days: parseInt(document.getElementById("smime-days").value, 10) || 365,
    passphrase: document.getElementById("smime-pass").value,
  };
  if (!payload.name || !payload.email) { setStatus(st, "Name and email required", "err"); return; }
  if ((payload.passphrase || "").length < 8) { setStatus(st, "Passphrase must be 8+ chars", "err"); return; }
  setStatus(st, "Issuing…");
  const resp = await fetch(API + "/admin/smime/issue", {
    method: "POST", credentials: "same-origin",
    headers: { ...CSRF, "Content-Type": "application/json" },
    body: JSON.stringify(payload) });
  if (!resp.ok) {
    let e = resp.status; try { e = (await resp.json()).error || e; } catch (_) {}
    setStatus(st, "Failed: " + e, "err"); return;
  }
  const blob = await resp.blob();
  const cd = resp.headers.get("Content-Disposition") || "";
  const name = (cd.match(/filename=([^;]+)/) || [])[1] || "smime.p12";
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob); a.download = name.trim(); a.click();
  URL.revokeObjectURL(a.href);
  document.getElementById("smime-pass").value = "";
  setStatus(st, "Issued " + name.trim() + " — deliver it + the passphrase out of band.", "ok");
});
