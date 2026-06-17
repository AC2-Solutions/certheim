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
  // Show the Sign out button only for password (local session) logins. A CAC
  // user can't truly "sign out" - the cert is re-presented on every request -
  // so the button would just bounce them back in. Base this on HOW the user
  // actually authenticated (currentUser.via), not the server's auth mode.
  if (currentUser && currentUser.via === "local") {
    const lo = document.getElementById("nav-logout");
    if (lo) lo.hidden = false;
  }
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

// Boot: always show the login gate first; it decides CAC vs password and
// runs init() once the user is authenticated.
bootstrapAuth();
