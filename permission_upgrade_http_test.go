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
func httpUpgradeServer(t *testing.T) (*httptest.Server, *capbrokerServer, RemoteRequest) {
	t.Helper()
	server, req := upgradeTestServer(t)
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
