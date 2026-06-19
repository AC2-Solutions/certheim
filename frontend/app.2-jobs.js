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
async function signJob(jobId, targetHost) {
  if (!confirm(`Approve and sign the request for ${targetHost}?\n\n`
             + "This issues the certificate via the configured CA backend "
             + "and marks the job issued.")) return;
  const r = await jsonReq(`/jobs/${jobId}/sign`, { method: "POST", body: "{}" });
  if (!r.ok || !(r.body && r.body.ok)) {
    alert("Sign failed: " + ((r.body && r.body.error) || "unknown"));
    return;
  }
  const warns = r.body.warnings || [];
  let msg = `Issued for ${r.body.target_host} via ${r.body.signed_via}.`;
  if (warns.length) msg += "\n\nWarnings:\n• " + warns.join("\n• ");
  alert(msg);
  if (r.body.chain_pem) downloadChainPem(r.body.target_host || jobId, r.body.chain_pem);
  await openDetailModal(jobId);   // re-render: it's now "issued"
  refreshJobs();
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
  _licenseNotice = currentUser ? (currentUser.license_notice || null) : null;
  updateLicenseBanner();
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

function applyRoute() {
  // Deep link from a chat notification: #job-<id> opens that job's detail.
  if ((location.hash || "").startsWith("#job-")) {
    mainView.hidden = false;
    adminView.hidden = true;
    navDashBtn.classList.add("active");
    navAdminBtn.classList.remove("active");
    const jobId = decodeURIComponent(location.hash.slice(5));
    if (jobId) openDetailModal(jobId);
    updateLicenseBanner();
    return;
  }
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
  updateLicenseBanner();
}
navDashBtn.addEventListener("click", () => { location.hash = ""; });
navAdminBtn.addEventListener("click", () => { location.hash = "#admin"; });
window.addEventListener("hashchange", applyRoute);

