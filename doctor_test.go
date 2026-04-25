// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import "testing"

func TestDoctorProfileChecksConfiguredSecrets(t *testing.T) {
	t.Setenv("CAPBROKER_DOCTOR_TEST_SECRET", "secret")
	cfg := &Config{
		SecretSources: map[string]SecretSource{
			"ok":      {Type: "env", Env: "CAPBROKER_DOCTOR_TEST_SECRET"},
			"missing": {Type: "env", Env: "CAPBROKER_DOCTOR_TEST_MISSING", Hint: "set it"},
		},
	}

	if !doctorProfile(cfg, "ok-profile", Profile{Env: map[string]string{"TOKEN": "ok"}}) {
		t.Fatal("expected ok profile to pass")
	}
	if doctorProfile(cfg, "missing-profile", Profile{Env: map[string]string{"TOKEN": "missing"}}) {
		t.Fatal("expected missing secret to fail")
	}
	if doctorProfile(cfg, "unknown-profile", Profile{Env: map[string]string{"TOKEN": "unknown"}}) {
		t.Fatal("expected unknown source to fail")
	}
}
