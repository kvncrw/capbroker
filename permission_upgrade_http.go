// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
)

// HTTP review surface for permission-upgrade requests.
//
//   GET  /u/                — list pending upgrade requests (HTML)
//   GET  /u/{id}            — render approval form for a single request (HTML)
//   GET  /u/{id}/diff       — text/plain diff that "permanent" would apply
//   POST /u/{id}            — form-encoded decision; body fields:
//                                mode = once|session|permanent|deny
//                                message = optional operator note
//   POST /v1/upgrades/{id}/decide — JSON API mirror of POST /u/{id}
//
// Auth model: these endpoints assume they sit behind a Cloudflare Access
// (or equivalent) policy that authenticates the operator. The daemon
// reads a configurable trusted header (default Cf-Access-Authenticated-User-
// Email) to record operator identity in the audit. Without that header
// the operator is recorded as "anonymous-http"; the decision is still
// applied. Hardening (JWT verification) is a follow-up.

// operatorIdent extracts the operator identity from a Cloudflare Access
// trusted header, falling back to "anonymous-http". Header name comes from
// the daemon config; empty means use the default. Empty/absent value =
// anonymous (only accepted when cfg.Remote.AllowAnonymousUpgrade is true;
// see authorizeUpgradeOperator).
func operatorIdent(r *http.Request) string {
	if v := r.Header.Get("Cf-Access-Authenticated-User-Email"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-User"); v != "" {
		return v
	}
	return "anonymous-http"
}

// authorizeUpgradeOperator gates the upgrade decision path on the daemon
// side. Codex review on PR #12 caught that handleUpgradeAPI applied
// decisions immediately from request body+headers with no daemon-side
// auth check — Cloudflare Access in front was the only gate. If anything
// bypassed CF Access (direct tailnet hit, misconfigured ingress), an
// attacker who knew a pending upgrade id could POST {"mode":"permanent"}
// and write permanent allowlist grants.
//
// Fail-closed model:
//   - If cfg.Remote.UpgradeApprovers is non-empty, the operator from the
//     trusted header MUST be in the list (case-insensitive). Otherwise
//     reject with 403 + audit.
//   - If cfg.Remote.UpgradeApprovers is empty AND AllowAnonymousUpgrade is
//     true, accept anyone (dev/test mode). The audit still records the
//     header-supplied identity, which is "anonymous-http" if absent.
//   - If cfg.Remote.UpgradeApprovers is empty AND AllowAnonymousUpgrade is
//     false, reject ALL decisions. This is the safe production default
//     for a freshly-installed daemon — operator must opt in by
//     populating the list.
//
// Returns the validated operator identity (to record in audit + grant)
// or an error suitable for 403.
func (s *capbrokerServer) authorizeUpgradeOperator(r *http.Request) (string, error) {
	op := operatorIdent(r)
	if len(s.cfg.Remote.UpgradeApprovers) == 0 {
		if s.cfg.Remote.AllowAnonymousUpgrade {
			return op, nil
		}
		return "", fmt.Errorf("upgrade decisions are disabled: configure remote.upgrade_approvers (or set remote.allow_anonymous_upgrade for dev)")
	}
	if op == "anonymous-http" {
		return "", fmt.Errorf("upgrade decisions require an authenticated operator (no trusted-header identity present)")
	}
	wanted := strings.ToLower(strings.TrimSpace(op))
	for _, allowed := range s.cfg.Remote.UpgradeApprovers {
		if strings.ToLower(strings.TrimSpace(allowed)) == wanted {
			return op, nil
		}
	}
	return "", fmt.Errorf("operator %q is not in remote.upgrade_approvers", op)
}

// recordUnauthorizedUpgrade audits a rejected decision attempt so the
// operator has a record of attempted self-approvals. Best-effort — audit
// failures don't block the rejection.
func (s *capbrokerServer) recordUnauthorizedUpgrade(requestID, attempted string, r *http.Request, reason error) {
	denied := false
	_ = appendAudit(s.stateDir, AuditEvent{
		Event:    "permission_upgrade_unauthorized",
		GrantID:  requestID,
		Approved: &denied,
		Message: fmt.Sprintf("attempted-mode=%s attempted-operator=%q remote=%s reason=%s",
			attempted, operatorIdent(r), r.RemoteAddr, reason.Error()),
	})
}

// upgradeUIRouter dispatches /u/... requests. Registered as a single
// HandleFunc("/u/") so the daemon mux can stay flat.
func (s *capbrokerServer) handleUpgradeUI(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/u/")
	if rest == "" {
		s.handleUpgradeList(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	id := parts[0]
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.handleUpgradeShow(w, r, id)
		case http.MethodPost:
			s.handleUpgradeDecideForm(w, r, id)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 2 && parts[1] == "diff" && r.Method == http.MethodGet {
		s.handleUpgradeDiff(w, r, id)
		return
	}
	http.NotFound(w, r)
}

// handleUpgradeAPI handles POST /v1/upgrades/{id}/decide as JSON.
// Mirrors the form-encoded endpoint at POST /u/{id}.
func (s *capbrokerServer) handleUpgradeAPI(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/v1/upgrades/")
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[1] != "decide" || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	id := parts[0]
	var body struct {
		Mode    string `json:"mode"`
		Message string `json:"message,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	op, err := s.authorizeUpgradeOperator(r)
	if err != nil {
		s.recordUnauthorizedUpgrade(id, body.Mode, r, err)
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	updated, err := s.decidePermissionUpgrade(id, upgradeDecision{
		Mode:     body.Mode,
		Operator: op,
		Message:  body.Message,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *capbrokerServer) handleUpgradeList(w http.ResponseWriter, r *http.Request) {
	requests, err := s.store.list()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pending := make([]RemoteRequest, 0, len(requests))
	for _, req := range requests {
		if req.Kind == requestKindPermissionUpgrade && req.Status == remoteStatusPending {
			pending = append(pending, req)
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := upgradeListTemplate.Execute(w, pending); err != nil {
		fmt.Fprintf(w, "<!-- template error: %v -->", err)
	}
}

func (s *capbrokerServer) handleUpgradeShow(w http.ResponseWriter, r *http.Request, id string) {
	req, ok, err := s.store.get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || req.Kind != requestKindPermissionUpgrade {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		R       RemoteRequest
		Now     time.Time
		Decided bool
	}{R: req, Now: time.Now().UTC(), Decided: req.Status != remoteStatusPending}
	if err := upgradeFormTemplate.Execute(w, data); err != nil {
		fmt.Fprintf(w, "<!-- template error: %v -->", err)
	}
}

func (s *capbrokerServer) handleUpgradeDiff(w http.ResponseWriter, r *http.Request, id string) {
	req, ok, err := s.store.get(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !ok || req.Kind != requestKindPermissionUpgrade {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	// Show what each grant mode would change. The "permanent" diff is the
	// concrete one-line addition to permanent-grants.jsonl that
	// applyUpgradeApproval will write — operator can mentally verify
	// the exact value before approving.
	fmt.Fprintf(w, "Permission upgrade request %s\n", req.ID)
	fmt.Fprintf(w, "  agent:           %s\n", req.Agent)
	fmt.Fprintf(w, "  target_profile:  %s\n", req.TargetProfile)
	fmt.Fprintf(w, "  target_resource: %s\n", req.TargetResource)
	fmt.Fprintf(w, "  requested_mode:  %s\n", req.GrantMode)
	fmt.Fprintf(w, "  reason:          %s\n", req.Reason)
	if req.OriginalRequestID != "" {
		fmt.Fprintf(w, "  original_request: %s\n", req.OriginalRequestID)
	}
	fmt.Fprintf(w, "\nWhat each grant mode would do:\n\n")
	fmt.Fprintf(w, "  once       → add to %s/temporal-grants.jsonl with %s expiry\n", s.stateDir, onceTTL)
	max := time.Duration(s.cfg.Defaults.MaxSessionSeconds) * time.Second
	fmt.Fprintf(w, "  session    → add to %s/temporal-grants.jsonl with %s expiry\n", s.stateDir, max)
	fmt.Fprintf(w, "  permanent  → append to %s/permanent-grants.jsonl:\n", s.stateDir)
	preview := permissionGrant{
		TargetProfile:  req.TargetProfile,
		TargetResource: req.TargetResource,
		GrantMode:      grantModePermanent,
		GrantedAt:      time.Now().UTC().Truncate(time.Second),
		GrantedBy:      operatorIdent(r),
		RequestID:      req.ID,
		Reason:         req.Reason,
	}
	previewJSON, _ := json.Marshal(preview)
	fmt.Fprintf(w, "    + %s\n", previewJSON)
	fmt.Fprintf(w, "  deny       → record denial; no grant written\n")
}

func (s *capbrokerServer) handleUpgradeDecideForm(w http.ResponseWriter, r *http.Request, id string) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	mode := strings.TrimSpace(r.PostFormValue("mode"))
	message := strings.TrimSpace(r.PostFormValue("message"))
	op, err := s.authorizeUpgradeOperator(r)
	if err != nil {
		s.recordUnauthorizedUpgrade(id, mode, r, err)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintf(w, "<!doctype html><meta name=\"viewport\" content=\"width=device-width\">"+
			"<style>body{font-family:system-ui;padding:1.5em;max-width:40em}"+
			".err{color:#a00;border:1px solid #a00;padding:.8em;border-radius:.4em}</style>"+
			"<h1>Not authorized</h1><div class=err>%s</div>"+
			"<p><a href=\"/u/%s\">← back</a></p>",
			template.HTMLEscapeString(err.Error()),
			template.HTMLEscapeString(id))
		return
	}
	updated, err := s.decidePermissionUpgrade(id, upgradeDecision{
		Mode:     mode,
		Operator: op,
		Message:  message,
	})
	if err != nil {
		// Render the form again with the error visible. Simpler than
		// flash-redirect for a no-JS phone-friendly form.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "<!doctype html><meta name=\"viewport\" content=\"width=device-width\">"+
			"<style>body{font-family:system-ui;padding:1.5em;max-width:40em}"+
			".err{color:#a00;border:1px solid #a00;padding:.8em;border-radius:.4em}</style>"+
			"<h1>Decision failed</h1><div class=err>%s</div>"+
			"<p><a href=\"/u/%s\">← back</a></p>",
			template.HTMLEscapeString(err.Error()),
			template.HTMLEscapeString(id))
		return
	}
	// Success — render a compact confirmation page (no redirect chain).
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "<!doctype html><meta name=\"viewport\" content=\"width=device-width\">"+
		"<style>body{font-family:system-ui;padding:1.5em;max-width:40em}"+
		".ok{color:#070;border:1px solid #070;padding:.8em;border-radius:.4em}</style>"+
		"<h1>Decision applied</h1>"+
		"<div class=ok>%s • %s</div>"+
		"<p>Request <code>%s</code> is now <strong>%s</strong>.</p>"+
		"<p><a href=\"/u/\">← all pending</a></p>",
		template.HTMLEscapeString(mode),
		template.HTMLEscapeString(op),
		template.HTMLEscapeString(updated.ID),
		template.HTMLEscapeString(updated.Status))
}

// upgradeListTemplate is the index page at /u/. Plain HTML5, viewport
// meta, no JS; works in any browser including phone webviews.
var upgradeListTemplate = template.Must(template.New("list").Parse(`<!doctype html>
<html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>capbroker — pending upgrades</title>
<style>
  body { font-family: system-ui, sans-serif; padding: 1.5em; max-width: 50em; margin: 0 auto; }
  h1 { margin-top: 0; }
  .req { border: 1px solid #ccc; border-radius: .5em; padding: 1em; margin-bottom: 1em; }
  .req h2 { margin: 0 0 .3em 0; font-size: 1.05em; }
  .meta { color: #666; font-size: .9em; }
  .reason { margin: .5em 0; font-style: italic; }
  a.btn { display: inline-block; padding: .4em .8em; border: 1px solid #06c; border-radius: .3em; text-decoration: none; color: #06c; }
  .empty { color: #888; font-style: italic; }
</style>
</head><body>
<h1>Pending permission upgrades</h1>
{{if not .}}<p class="empty">no requests pending.</p>{{end}}
{{range .}}
<div class="req">
  <h2>{{.Agent}} → {{.TargetProfile}} += <code>{{.TargetResource}}</code></h2>
  <div class="meta">id <code>{{.ID}}</code> • requested {{.GrantMode}} • created {{.CreatedAt.Format "2026-01-02 15:04 MST"}}</div>
  <div class="reason">"{{.Reason}}"</div>
  <p><a class="btn" href="/u/{{.ID}}">decide →</a> <a class="btn" href="/u/{{.ID}}/diff">diff</a></p>
</div>
{{end}}
</body></html>
`))

// upgradeFormTemplate is the per-request decision page with four big
// buttons (once / session / permanent / deny). Each button is its own
// <button name="mode" value=...> in the same form so clicking
// dispatches the corresponding mode.
var upgradeFormTemplate = template.Must(template.New("form").Parse(`<!doctype html>
<html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.R.Agent}} → {{.R.TargetProfile}} += {{.R.TargetResource}}</title>
<style>
  body { font-family: system-ui, sans-serif; padding: 1.5em; max-width: 40em; margin: 0 auto; }
  h1 { font-size: 1.2em; }
  .meta { color: #666; font-size: .9em; }
  .reason { background: #f4f4f4; padding: .8em; border-radius: .4em; margin: 1em 0; font-style: italic; }
  fieldset { border: none; padding: 0; }
  textarea { width: 100%; box-sizing: border-box; padding: .5em; font-family: inherit; }
  button { width: 100%; padding: 1em; margin: .4em 0; font-size: 1em; border-radius: .4em; border: 1px solid #ccc; background: #fff; cursor: pointer; }
  button.once { background: #dff7df; border-color: #070; color: #070; }
  button.session { background: #e0e8ff; border-color: #06c; color: #06c; }
  button.permanent { background: #ffe8d0; border-color: #a60; color: #a60; }
  button.deny { background: #ffe0e0; border-color: #a00; color: #a00; }
  .decided { background: #fff4d0; padding: 1em; border-radius: .4em; }
</style>
</head><body>
<h1>{{.R.Agent}} wants {{.R.TargetProfile}} +=
  <code>{{.R.TargetResource}}</code></h1>
<div class="meta">
  request <code>{{.R.ID}}</code> •
  agent requested <strong>{{.R.GrantMode}}</strong> •
  created {{.R.CreatedAt.Format "2026-01-02 15:04 MST"}}
  {{if .R.OriginalRequestID}}• original: <code>{{.R.OriginalRequestID}}</code>{{end}}
</div>
<div class="reason">"{{.R.Reason}}"</div>

{{if .Decided}}
  <div class="decided">
    Already <strong>{{.R.Status}}</strong>. {{if .R.Message}}<br>note: {{.R.Message}}{{end}}
  </div>
  <p><a href="/u/{{.R.ID}}/diff">view diff</a> • <a href="/u/">← all pending</a></p>
{{else}}
  <p><a href="/u/{{.R.ID}}/diff">view exact diff this would apply →</a></p>
  <form method="post" action="/u/{{.R.ID}}">
    <fieldset>
      <label>note (optional) — included in audit:</label>
      <textarea name="message" rows="2" placeholder="e.g. ok for this mission only"></textarea>
    </fieldset>
    <button class="once" type="submit" name="mode" value="once">once · 24h</button>
    <button class="session" type="submit" name="mode" value="session">session</button>
    <button class="permanent" type="submit" name="mode" value="permanent">permanent</button>
    <button class="deny" type="submit" name="mode" value="deny">deny</button>
  </form>
  <p><a href="/u/">← all pending</a></p>
{{end}}
</body></html>
`))
