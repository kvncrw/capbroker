// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// httpUpgradeServer wires the same fixture as upgradeTestServer (the
// pending request, profiles, stateDir) onto a real httptest.Server with
// the /u/ + /v1/upgrades/ routes mounted, mirroring StartRemoteServer.
//
// The fixture pre-populates cfg.Remote.UpgradeApprovers with the email
// values the existing tests send via Cf-Access-Authenticated-User-Email,
// so the auth gate added in response to Codex P1 lets them through.
// Auth-gate behavior itself is exercised by the dedicated tests below
// that build their own server fixture with custom config.
func httpUpgradeServer(t *testing.T) (*httptest.Server, *capbrokerServer, RemoteRequest) {
	t.Helper()
	server, req := upgradeTestServer(t)
	server.cfg.Remote.UpgradeApprovers = []string{"kcrawley@web", "kcrawley@cli"}
	mux := http.NewServeMux()
	mux.HandleFunc("/u/", server.handleUpgradeUI)
	mux.HandleFunc("/v1/upgrades/", server.handleUpgradeAPI)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, server, req
}

// httpUpgradeServerWithAuthMode lets a test build a fresh server with
// its own UpgradeApprovers list and AllowAnonymousUpgrade flag — used
// by the auth-gate tests below.
func httpUpgradeServerWithAuthMode(t *testing.T, approvers []string, allowAnonymous bool) (*httptest.Server, *capbrokerServer, RemoteRequest) {
	t.Helper()
	server, req := upgradeTestServer(t)
	server.cfg.Remote.UpgradeApprovers = approvers
	server.cfg.Remote.AllowAnonymousUpgrade = allowAnonymous
	mux := http.NewServeMux()
	mux.HandleFunc("/u/", server.handleUpgradeUI)
	mux.HandleFunc("/v1/upgrades/", server.handleUpgradeAPI)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts, server, req
}

func TestUpgradeUIListShowsPending(t *testing.T) {
	t.Parallel()
	ts, _, req := httpUpgradeServer(t)
	resp, err := http.Get(ts.URL + "/u/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, req.ID) {
		t.Fatalf("list missing request id %q in: %s", req.ID, body)
	}
	if !strings.Contains(body, "namespace/basilisk") {
		t.Fatalf("list missing target_resource: %s", body)
	}
}

func TestUpgradeUIShowRendersForm(t *testing.T) {
	t.Parallel()
	ts, _, req := httpUpgradeServer(t)
	resp, err := http.Get(ts.URL + "/u/" + req.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	for _, want := range []string{
		`name="mode" value="once"`,
		`name="mode" value="session"`,
		`name="mode" value="permanent"`,
		`name="mode" value="deny"`,
		req.Reason,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("form missing %q in: %s", want, body)
		}
	}
}

func TestUpgradeUIShow404OnUnknown(t *testing.T) {
	t.Parallel()
	ts, _, _ := httpUpgradeServer(t)
	resp, err := http.Get(ts.URL + "/u/req_does_not_exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestUpgradeUIDiffShowsPermanentLine(t *testing.T) {
	t.Parallel()
	ts, _, req := httpUpgradeServer(t)
	resp, err := http.Get(ts.URL + "/u/" + req.ID + "/diff")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "permanent-grants.jsonl") {
		t.Fatalf("diff missing permanent file mention: %s", body)
	}
	if !strings.Contains(body, "namespace/basilisk") {
		t.Fatalf("diff missing target_resource: %s", body)
	}
}

func TestUpgradeUIFormPostApprovesAndPersistsGrant(t *testing.T) {
	t.Parallel()
	ts, server, req := httpUpgradeServer(t)
	form := url.Values{"mode": {"once"}, "message": {"ok for this mission"}}
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/u/"+req.ID, strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body=%s", resp.StatusCode, readBody(t, resp))
	}
	updated, ok, err := server.store.get(req.ID)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if updated.Status != remoteStatusApproved {
		t.Fatalf("status %s", updated.Status)
	}
	if updated.Message != "ok for this mission" {
		t.Fatalf("message %q", updated.Message)
	}
	grants, err := loadGrantsJSONL(temporalGrantsPath(server.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 temporal grant, got %d", len(grants))
	}
	if grants[0].GrantedBy != "kcrawley@web" {
		t.Fatalf("operator from CF header lost: %+v", grants[0])
	}
}

func TestUpgradeUIFormPostDenyMarksDenied(t *testing.T) {
	t.Parallel()
	ts, server, req := httpUpgradeServer(t)
	form := url.Values{"mode": {"deny"}, "message": {"scope too broad"}}
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/u/"+req.ID, strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	updated, _, _ := server.store.get(req.ID)
	if updated.Status != remoteStatusDenied {
		t.Fatalf("status %s", updated.Status)
	}
}

func TestUpgradeUIFormPostBadModeShowsErrorPage(t *testing.T) {
	t.Parallel()
	ts, _, req := httpUpgradeServer(t)
	form := url.Values{"mode": {"forever"}}
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/u/"+req.ID, strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "Decision failed") {
		t.Fatalf("error page missing heading: %s", body)
	}
}

func TestUpgradeAPIDecideJSONApproves(t *testing.T) {
	t.Parallel()
	ts, server, req := httpUpgradeServer(t)
	body := strings.NewReader(`{"mode":"permanent","message":"ok"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@cli")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d body=%s", resp.StatusCode, readBody(t, resp))
	}
	var got RemoteRequest
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if got.Status != remoteStatusApproved {
		t.Fatalf("status %s", got.Status)
	}
	grants, _ := loadGrantsJSONL(permanentGrantsPath(server.stateDir))
	if len(grants) != 1 {
		t.Fatalf("expected 1 permanent grant, got %d", len(grants))
	}
	if grants[0].GrantedBy != "kcrawley@cli" {
		t.Fatalf("operator: %+v", grants[0])
	}
}

func TestUpgradeAPIDecideJSONRejectsWrongMethod(t *testing.T) {
	t.Parallel()
	ts, _, req := httpUpgradeServer(t)
	resp, err := http.Get(ts.URL + "/v1/upgrades/" + req.ID + "/decide")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: %d", resp.StatusCode)
	}
}

func TestUpgradeUIShowAfterDecideRendersDecidedBanner(t *testing.T) {
	t.Parallel()
	ts, server, req := httpUpgradeServer(t)
	if _, err := server.decidePermissionUpgrade(req.ID, upgradeDecision{
		Mode: grantModeOnce, Operator: "kcrawley",
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(ts.URL + "/u/" + req.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body := readBody(t, resp)
	if !strings.Contains(body, "Already") {
		t.Fatalf("decided banner missing: %s", body)
	}
	if strings.Contains(body, `name="mode"`) {
		t.Fatalf("form should be hidden after decision: %s", body)
	}
}

// --- Auth-gate tests (Codex P1 on PR #12) ---
//
// The decide path MUST refuse decisions whose operator identity is not
// in cfg.Remote.UpgradeApprovers, so that anyone who reaches the daemon
// (e.g. via a misconfigured ingress that bypasses Cloudflare Access)
// can't POST {"mode":"permanent"} and self-approve a grant.

func TestUpgradeAPIRejectsEmptyApproverList(t *testing.T) {
	t.Parallel()
	// Default config: no UpgradeApprovers, AllowAnonymousUpgrade=false.
	// All decision attempts must be rejected (fail-closed).
	ts, server, req := httpUpgradeServerWithAuthMode(t, nil, false)
	body := strings.NewReader(`{"mode":"permanent"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "attacker@evil")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (body=%s)", resp.StatusCode, readBody(t, resp))
	}
	got, _, _ := server.store.get(req.ID)
	if got.Status != remoteStatusPending {
		t.Fatalf("rejected decision should leave status pending, got %s", got.Status)
	}
	grants, _ := loadGrantsJSONL(permanentGrantsPath(server.stateDir))
	if len(grants) != 0 {
		t.Fatalf("rejected decision wrote a grant: %+v", grants)
	}
}

func TestUpgradeAPIRejectsNonAllowlistedOperator(t *testing.T) {
	t.Parallel()
	ts, server, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	body := strings.NewReader(`{"mode":"permanent"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "attacker@evil")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	got, _, _ := server.store.get(req.ID)
	if got.Status != remoteStatusPending {
		t.Fatalf("rejected decision should leave status pending, got %s", got.Status)
	}
}

func TestUpgradeAPIRejectsMissingHeaderWhenAllowlistConfigured(t *testing.T) {
	t.Parallel()
	ts, _, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	body := strings.NewReader(`{"mode":"once"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	// no CF header — daemon must refuse rather than tag as anonymous.
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for missing header, got %d", resp.StatusCode)
	}
}

func TestUpgradeAPIAcceptsAllowlistedOperatorCaseInsensitive(t *testing.T) {
	t.Parallel()
	// Allowlist value is lowercase, header value is mixed-case — must match.
	ts, server, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	body := strings.NewReader(`{"mode":"once"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "KCrawley@Web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%s)", resp.StatusCode, readBody(t, resp))
	}
	got, _, _ := server.store.get(req.ID)
	if got.Status != remoteStatusApproved {
		t.Fatalf("status %s", got.Status)
	}
}

func TestUpgradeAPIAllowAnonymousModeAcceptsMissingHeader(t *testing.T) {
	t.Parallel()
	// Dev-mode escape hatch: empty allowlist + AllowAnonymousUpgrade=true.
	ts, server, req := httpUpgradeServerWithAuthMode(t, nil, true)
	body := strings.NewReader(`{"mode":"once"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 in anonymous mode, got %d", resp.StatusCode)
	}
	got, _, _ := server.store.get(req.ID)
	if got.Status != remoteStatusApproved {
		t.Fatalf("status %s", got.Status)
	}
	// Audit attribution should still record "anonymous-http" so the
	// operator can grep for self-attributed decisions.
	grants, _ := loadGrantsJSONL(temporalGrantsPath(server.stateDir))
	if len(grants) != 1 || grants[0].GrantedBy != "anonymous-http" {
		t.Fatalf("anonymous mode should tag grant as anonymous-http, got %+v", grants)
	}
}

func TestUpgradeUIFormPostRejectsUnauthorizedOperator(t *testing.T) {
	t.Parallel()
	ts, _, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	form := url.Values{"mode": {"once"}}
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/u/"+req.ID, strings.NewReader(form.Encode()))
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "attacker@evil")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	if body := readBody(t, resp); !strings.Contains(body, "Not authorized") {
		t.Fatalf("error page missing 'Not authorized' heading: %s", body)
	}
}

// --- Source-IP allowlist tests ---
//
// Codex's earlier review correctly noted that the trusted-identity
// headers can be forged by anything that reaches the daemon directly.
// UpgradeAllowedSources is the structural fix: even with a perfectly
// crafted forged header, a request from outside the CIDR list is
// dropped before the email-allowlist check ever runs.

func TestUpgradeAPIRejectsSourceOutsideAllowlist(t *testing.T) {
	t.Parallel()
	ts, server, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	// Restrict to a network that httptest's loopback dialer will NEVER
	// fall under. httptest.NewServer binds to 127.0.0.1 so we pick a
	// disjoint RFC1918 block.
	server.cfg.Remote.UpgradeAllowedSources = []string{"10.255.255.0/24"}

	body := strings.NewReader(`{"mode":"permanent"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for off-net source, got %d", resp.StatusCode)
	}
	got, _, _ := server.store.get(req.ID)
	if got.Status != remoteStatusPending {
		t.Fatalf("rejected decision should leave status pending, got %s", got.Status)
	}
}

func TestUpgradeAPIAcceptsSourceInsideAllowlist(t *testing.T) {
	t.Parallel()
	ts, server, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	// httptest binds to 127.0.0.1 — match it via a /8 to be robust to the
	// dialer picking a different loopback alias.
	server.cfg.Remote.UpgradeAllowedSources = []string{"127.0.0.0/8"}

	body := strings.NewReader(`{"mode":"once"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for on-net source, got %d", resp.StatusCode)
	}
}

func TestUpgradeAPIBareIPInAllowlist(t *testing.T) {
	t.Parallel()
	// Operator ergonomic: bare IPs without /32 should also work.
	ts, server, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	server.cfg.Remote.UpgradeAllowedSources = []string{"127.0.0.1"}

	body := strings.NewReader(`{"mode":"once"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestUpgradeAPIEmptyAllowlistSkipsSourceCheck(t *testing.T) {
	t.Parallel()
	// Default behavior: when UpgradeAllowedSources is empty, source IP
	// is not checked. Back-compat with laptop-local single-user
	// deployments that bind to 127.0.0.1 only.
	ts, server, req := httpUpgradeServerWithAuthMode(t, []string{"kcrawley@web"}, false)
	if len(server.cfg.Remote.UpgradeAllowedSources) != 0 {
		t.Fatal("default fixture must leave UpgradeAllowedSources empty")
	}

	body := strings.NewReader(`{"mode":"once"}`)
	httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/upgrades/"+req.ID+"/decide", body)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Cf-Access-Authenticated-User-Email", "kcrawley@web")
	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with empty allowlist, got %d", resp.StatusCode)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}
	return string(buf)
}
