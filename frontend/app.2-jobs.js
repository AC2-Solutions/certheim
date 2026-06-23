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
  if (job.can_revoke) {
    actions.push(`<button class="btn secondary" data-action="revoke" data-id="${job.id}" data-host="${escapeHtml(job.target_host)}" style="color:var(--danger)">Revoke</button>`);
  }
  if (job.status === "issued" || job.status === "expired") {
    actions.push(`<button class="btn" data-action="renew" data-id="${job.id}" data-host="${escapeHtml(job.target_host)}">Renew</button>`);
  }
  if (job.status === "pending") {
    if (job.can_sign) {
      actions.push(`<button class="btn" data-action="sign" data-id="${job.id}" data-host="${escapeHtml(job.target_host)}">Approve &amp; sign</button>`);
    }
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
      else if (b.dataset.action === "sign") signJob(id, host);
      else if (b.dataset.action === "revoke") revokeJob(id, host);
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

// ===== Approve & sign (v2 in-UI signing) =====
// The button is shown only when the server says job.can_sign (this user may
// sign + an automated backend is configured/usable). POST /jobs/<id>/sign
// issues the cert via the CA backend, then we re-render and offer the chain.
allModalIds.push("sign-modal");

// Issuance-time validity control (short-lived certs). _signCtx holds the
// current job + its TTL bounds (seconds); the unit/number/slider stay in sync.
let _signCtx = null;

function _humanizeDur(s) {
  if (s % 86400 === 0) return (s / 86400) + (s / 86400 === 1 ? " day" : " days");
  if (s % 3600 === 0) return (s / 3600) + (s / 3600 === 1 ? " hour" : " hours");
  return Math.round(s / 60) + " minutes";
}

// Reflect _signCtx.secs into the unit/number/slider + the expiry preview.
function _signSync() {
  const ctx = _signCtx; if (!ctx) return;
  const unit = Number(document.getElementById("sign-ttl-unit").value) || 60;
  const range = document.getElementById("sign-ttl-range");
  const num = document.getElementById("sign-ttl-num");
  const umin = Math.max(1, Math.ceil(ctx.min / unit));
  const umax = Math.max(umin, Math.floor(ctx.max / unit));
  let uval = Math.max(umin, Math.min(umax, Math.round(ctx.secs / unit)));
  ctx.secs = Math.max(ctx.min, Math.min(ctx.max, uval * unit));
  range.min = num.min = String(umin);
  range.max = num.max = String(umax);
  range.value = num.value = String(uval);
  const exp = new Date(Date.now() + ctx.secs * 1000);
  document.getElementById("sign-ttl-preview").textContent =
    `Valid for ${_humanizeDur(ctx.secs)} · expires ${exp.toLocaleString()}`;
}
function _signSetSecs(secs) {
  if (!_signCtx) return;
  _signCtx.secs = Math.max(_signCtx.min, Math.min(_signCtx.max, Math.round(secs)));
  _signSync();
}

(function () {
  const unit = document.getElementById("sign-ttl-unit");
  const num = document.getElementById("sign-ttl-num");
  const range = document.getElementById("sign-ttl-range");
  if (!unit || !num || !range) return;
  unit.addEventListener("change", _signSync);
  num.addEventListener("input", () => _signSetSecs((Number(num.value) || 0) * (Number(unit.value) || 60)));
  range.addEventListener("input", () => _signSetSecs((Number(range.value) || 0) * (Number(unit.value) || 60)));
  const cbtn = document.getElementById("sign-confirm-btn");
  if (cbtn) cbtn.addEventListener("click", _doSignConfirm);
})();

async function signJob(jobId, targetHost) {
  const opt = await jsonReq(`/jobs/${jobId}/sign-options`);
  const o = (opt.ok && opt.body) ? opt.body : null;
  if (!o || !o.supports_ttl) {
    // This backend issues at its own/template validity — keep the simple confirm.
    if (!confirm(`Approve and sign the request for ${targetHost}?\n\n`
               + "This issues the certificate via the configured CA backend "
               + "and marks the job issued.")) return;
    return _postSign(jobId, targetHost, null);
  }
  _signCtx = { jobId, host: targetHost, min: o.ttl_min, max: o.ttl_max, secs: o.ttl_default };
  document.getElementById("sign-modal-host").textContent = targetHost;
  setStatus(document.getElementById("sign-modal-status"), "");
  document.getElementById("sign-ttl-unit").value =
    (o.ttl_default % 86400 === 0 && o.ttl_default >= 86400) ? "86400"
      : (o.ttl_default % 3600 === 0 && o.ttl_default >= 3600) ? "3600" : "60";
  document.getElementById("sign-ttl-bounds").textContent =
    `Allowed range: ${_humanizeDur(o.ttl_min)} to ${_humanizeDur(o.ttl_max)}.`;
  _signSync();
  openModal("sign-modal");
}

async function _doSignConfirm() {
  const ctx = _signCtx; if (!ctx) return;
  const btn = document.getElementById("sign-confirm-btn");
  btn.disabled = true;
  setStatus(document.getElementById("sign-modal-status"), "Issuing…");
  // On success _postSign swaps to the detail modal; on failure we stay here.
  await _postSign(ctx.jobId, ctx.host, ctx.secs, document.getElementById("sign-modal-status"));
  btn.disabled = false;
}

async function _postSign(jobId, targetHost, ttlSecs, statusEl) {
  const body = ttlSecs ? JSON.stringify({ ttl: ttlSecs }) : "{}";
  const r = await jsonReq(`/jobs/${jobId}/sign`, { method: "POST", body });
  if (!r.ok || !(r.body && r.body.ok)) {
    const msg = "Sign failed: " + ((r.body && r.body.error) || "unknown");
    if (statusEl) setStatus(statusEl, msg, "err"); else alert(msg);
    return false;
  }
  const warns = r.body.warnings || [];
  let msg = `Issued for ${r.body.target_host} via ${r.body.signed_via}`;
  if (r.body.validity_seconds) msg += ` · valid ${_humanizeDur(r.body.validity_seconds)}`;
  msg += ".";
  if (warns.length) msg += "\n\nWarnings:\n• " + warns.join("\n• ");
  alert(msg);
  if (r.body.chain_pem) downloadChainPem(r.body.target_host || jobId, r.body.chain_pem);
  await openDetailModal(jobId);   // re-render: it's now "issued" (swaps modal)
  refreshJobs();
  return true;
}

// Revoke an issued cert via its CA backend (signer/admin; shown when can_revoke).
async function revokeJob(jobId, targetHost) {
  if (!confirm(`Revoke the certificate for ${targetHost}?\n\n`
             + "This revokes it at the CA (OpenBao) and marks the job revoked. "
             + "This cannot be undone.")) return;
  const r = await jsonReq(`/jobs/${jobId}/revoke`, { method: "POST", body: "{}" });
  if (!r.ok || !(r.body && r.body.ok)) {
    alert("Revoke failed: " + ((r.body && r.body.error) || "unknown"));
    return;
  }
  alert(`Revoked ${targetHost} (serial ${r.body.serial}).`);
  await openDetailModal(jobId);   // re-render: it's now "revoked"
  refreshJobs();
}

// Client-side blob download for the returned cert chain.
function downloadChainPem(name, pem) {
  const blob = new Blob([pem], { type: "application/x-pem-file" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${name}-chain.pem`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ===== Upload cert =====
// Holds a base64-encoded file when the user picks a binary cert (DER .cer /
// PKCS#7 .p7b). Pasted PEM goes through the textarea (cert_pem) instead.
let _uploadCertB64 = null;

function openUploadCert(jobId, targetHost) {
  const t = document.getElementById("upload-job-target");
  t.textContent = targetHost;
  t.dataset.id = jobId;
  _uploadCertB64 = null;
  document.getElementById("upload-cert-text").value = "";
  document.getElementById("upload-cert-file").value = "";
  setStatus(document.getElementById("upload-cert-status"), "");
  openModal("upload-cert-modal");
}

document.getElementById("upload-cert-file").addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) { _uploadCertB64 = null; return; }
  const textArea = document.getElementById("upload-cert-text");
  // Read as base64 so binary DER/PKCS#7 survives intact (readAsText would
  // corrupt it). If the file is actually PEM text, show it and let the paste
  // path handle it; if it's binary, show a placeholder instead of garbage.
  const reader = new FileReader();
  reader.onload = () => {
    const dataUrl = reader.result;                 // "data:...;base64,XXXX"
    const b64 = dataUrl.substring(dataUrl.indexOf(",") + 1);
    _uploadCertB64 = b64;
    let looksPem = false;
    try {
      const decoded = atob(b64);
      looksPem = decoded.includes("-----BEGIN CERTIFICATE-----");
      if (looksPem) { textArea.value = decoded; _uploadCertB64 = null; }
    } catch (_) { /* binary - keep b64 */ }
    if (!looksPem) {
      textArea.value = `[binary certificate file selected: ${file.name}]\n`
                     + "It will be converted on upload (DER/.cer or PKCS#7/.p7b).";
    }
  };
  reader.readAsDataURL(file);
});

document.getElementById("upload-cert-submit-btn").addEventListener("click", async () => {
  const jobId = document.getElementById("upload-job-target").dataset.id;
  const pasted = document.getElementById("upload-cert-text").value;
  const status = document.getElementById("upload-cert-status");
  // Prefer a selected binary file (b64); otherwise use pasted PEM text.
  const body = {};
  if (_uploadCertB64) {
    body.cert_b64 = _uploadCertB64;
  } else if (pasted && !pasted.startsWith("[binary certificate file selected")) {
    body.cert_pem = pasted;
  } else {
    setStatus(status, "Cert content required.", "err");
    return;
  }
  setStatus(status, "Uploading…");
  const r = await jsonReq(`/jobs/${jobId}/upload-cert`, {
    method: "POST",
    body: JSON.stringify(body),
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
  if (typeof applyConfiguredDomain === "function") {
    applyConfiguredDomain(currentUser.domain_suffix);
  }
  // Request-form domain-suffix picker: only shown when an admin has configured
  // more than one selectable suffix (values are domain-charset, HTML-safe).
  const _dsfx = currentUser.domain_suffixes || [];
  const _dsel = document.getElementById("generate-domain");
  const _dfield = document.getElementById("generate-domain-field");
  if (_dsel && _dfield) {
    if (_dsfx.length > 1) {
      _dsel.innerHTML = _dsfx.map((d, i) => `<option value="${d}"${i === 0 ? " selected" : ""}>${d}</option>`).join("");
      _dfield.hidden = false;
    } else {
      _dfield.hidden = true;
    }
  }
  // Subject-profile picker: shown when an admin saved more than one profile so
  // the requester can switch (e.g. ac2.lan vs aj.com).
  const _profs = currentUser.subject_profiles || [];
  const _psel = document.getElementById("generate-profile");
  const _pfield = document.getElementById("generate-profile-field");
  if (_psel && _pfield) {
    if (_profs.length > 1) {
      _psel.innerHTML = _profs.map(p =>
        `<option value="${p.slug}"${p.is_default ? " selected" : ""}>${p.name}</option>`).join("");
      _pfield.hidden = false;
    } else {
      _pfield.hidden = true;
    }
  }
  if (currentUser.is_admin) {
    document.body.classList.add("is-admin");
  }
  if (currentUser.email) {
    const notifyEl = document.getElementById("notify-email");
    if (notifyEl && !notifyEl.value) notifyEl.value = currentUser.email;
  }
  const sqBtn = document.getElementById("main-nav-signing");
  if (sqBtn) sqBtn.hidden = !(currentUser && (currentUser.is_signer || currentUser.is_admin));
  _licenseNotice = currentUser ? (currentUser.license_notice || null) : null;
  updateLicenseBanner();
  updateEditionBadge();
}

// ===== Edition / license watermark =====
// A persistent badge in the header: the edition, and - when licensed - the
// customer the license was issued to. Surfacing the licensee makes a copied
// license self-identifying. A host-binding mismatch (license_warnings) flips
// the badge to a warning style.
function updateEditionBadge() {
  const el = document.getElementById("edition-badge");
  if (!el) return;
  const ed = (currentUser && currentUser.edition) || "community";
  const who = currentUser && currentUser.licensed_to;
  const warns = (currentUser && currentUser.license_warnings) || [];
  const label = ed.charAt(0).toUpperCase() + ed.slice(1);
  el.textContent = who ? `${label} · Licensed to ${who}` : label;
  el.classList.toggle("edition-badge-licensed", !!who);
  el.classList.toggle("edition-badge-warn", warns.length > 0);
  el.title = warns.length ? warns.join(" ") : `${label} edition`;
  el.hidden = false;
}

// ===== License-renewal banner =====
// The server (/api/me) only sends `license_notice` within the relevant window
// (60 days for admins, 30 for everyone else). We additionally gate by the
// *current view*, so the earlier 60-day warning stays on the Admin UI while the
// main dashboard only warns inside 30 days. Dismiss is per browser session.
let _licenseNotice = null;
const _LICENSE_DISMISS_KEY = "csr-license-banner-dismissed";

function updateLicenseBanner() {
  const el = document.getElementById("license-banner");
  if (!el) return;
  const n = _licenseNotice;
  if (!n || sessionStorage.getItem(_LICENSE_DISMISS_KEY) === "1") {
    el.hidden = true;
    return;
  }
  // Admin view active => 60-day window; main dashboard => 30 days.
  const threshold = (adminView && !adminView.hidden) ? 60 : 30;
  if (n.days_left > threshold) { el.hidden = true; return; }
  const days = n.days_left;
  const when = days <= 0 ? "today" : days === 1 ? "in 1 day" : `in ${days} days`;
  const edition = n.edition ? n.edition.charAt(0).toUpperCase() + n.edition.slice(1) : "";
  const cust = n.customer ? ` (${n.customer})` : "";
  document.getElementById("license-banner-msg").textContent =
    `Your ${edition} license${cust} expires ${when}. Renew it before it lapses `
    + `to keep your licensed features — contact your vendor to obtain a new license.`;
  el.hidden = false;
}

document.getElementById("license-banner-dismiss")?.addEventListener("click", () => {
  sessionStorage.setItem(_LICENSE_DISMISS_KEY, "1");
  const el = document.getElementById("license-banner");
  if (el) el.hidden = true;
});

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

// Return `name` if it's a real panel button in that nav, else the fallback.
function _routePanel(navId, name, fallback) {
  return (name && document.querySelector(`#${navId} button[data-panel="${name}"]`))
    ? name : fallback;
}

function applyRoute() {
  const raw = (location.hash || "").replace(/^#/, "");
  // Deep link from a chat notification: #job-<id> opens that job's detail.
  if (raw.startsWith("job-")) {
    mainView.hidden = false;
    adminView.hidden = true;
    navDashBtn.classList.add("active");
    navAdminBtn.classList.remove("active");
    const jobId = decodeURIComponent(raw.slice(4));
    if (jobId) openDetailModal(jobId);
    updateLicenseBanner();
    return;
  }
  // Section routing so a refresh restores the same place: "#admin" /
  // "#admin/<panel>" for the admin UI; "#<panel>" (jobs/fleet/...) for the
  // dashboard; empty -> dashboard default.
  const isAdminRoute = raw === "admin" || raw.startsWith("admin/");
  const wantAdmin = isAdminRoute && currentUser && currentUser.is_admin;
  if (wantAdmin) {
    const entering = adminView.hidden;
    mainView.hidden = true;
    adminView.hidden = false;
    navDashBtn.classList.remove("active");
    navAdminBtn.classList.add("active");
    showAdminPanel(_routePanel("admin-nav", raw.split("/")[1], "overview"));
    if (entering) refreshAdminView();   // (re)load admin data only when entering
  } else {
    mainView.hidden = false;
    adminView.hidden = true;
    navDashBtn.classList.add("active");
    navAdminBtn.classList.remove("active");
    showMainPanel(_routePanel("main-nav", isAdminRoute ? "" : raw, "create"));
    if (isAdminRoute) location.hash = "";   // non-admin hit #admin -> bounce home
  }
  updateLicenseBanner();
}
navDashBtn.addEventListener("click", () => { location.hash = ""; });
navAdminBtn.addEventListener("click", () => { location.hash = "#admin"; });
window.addEventListener("hashchange", applyRoute);

