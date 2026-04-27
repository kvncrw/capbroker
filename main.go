// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "request":
		cmdRequest(os.Args[2:])
	case "session":
		cmdSession(os.Args[2:])
	case "run":
		cmdRun(os.Args[2:])
	case "remote-run":
		cmdRemoteRun(os.Args[2:])
	case "vault-fetch":
		cmdVaultFetch(os.Args[2:])
	case "request-upgrade":
		cmdRequestUpgrade(os.Args[2:])
	case "review-upgrades":
		cmdReviewUpgrades(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "approve":
		cmdApprove(os.Args[2:])
	case "doctor":
		cmdDoctor(os.Args[2:])
	case "grants":
		cmdGrants(os.Args[2:])
	case "revoke":
		cmdRevoke(os.Args[2:])
	case "auto-approve":
		cmdAutoApprove(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
}

func cmdAutoApprove(args []string) {
	if len(args) == 0 {
		die(fmt.Errorf("auto-approve requires enable, disable, or status"))
	}
	switch args[0] {
	case "enable":
		cmdAutoApproveEnable(args[1:])
	case "disable":
		cmdAutoApproveDisable(args[1:])
	case "status":
		cmdAutoApproveStatus(args[1:])
	default:
		die(fmt.Errorf("unknown auto-approve command %q", args[0]))
	}
}

func cmdAutoApproveEnable(args []string) {
	fs := flag.NewFlagSet("auto-approve enable", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "state directory")
	ttlValue := fs.String("ttl", "30m", fmt.Sprintf("absolute hard ceiling on lease lifetime, capped at %s", MaxAutoApproveTTL))
	idleValue := fs.String("idle-window", DefaultAutoApproveIdleWindow.String(), "idle expiry window — each approved request bumps expiry to now+window, capped by --ttl")
	reason := fs.String("reason", "", "human-readable why (logged to audit and stored in the lease)")
	_ = fs.Parse(args)
	ttl, err := time.ParseDuration(*ttlValue)
	die(err)
	idle, err := time.ParseDuration(*idleValue)
	die(err)
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	lease, err := enableAutoApproveWithIdle(dir, ttl, idle, *reason)
	die(err)
	_ = appendAudit(dir, AuditEvent{
		Event:  "auto_approve_lease_enabled",
		Reason: *reason,
		Message: fmt.Sprintf("auto-approve lease active until %s (idle %s, max %s)",
			lease.ExpiresAt.Format(time.RFC3339), lease.IdleWindow, lease.MaxExpiresAt.Format(time.RFC3339)),
	})
	printJSON(lease)
}

func cmdAutoApproveDisable(args []string) {
	fs := flag.NewFlagSet("auto-approve disable", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "state directory")
	_ = fs.Parse(args)
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	die(disableAutoApprove(dir))
	_ = appendAudit(dir, AuditEvent{Event: "auto_approve_lease_disabled"})
	fmt.Println("ok")
}

func cmdAutoApproveStatus(args []string) {
	fs := flag.NewFlagSet("auto-approve status", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "state directory")
	_ = fs.Parse(args)
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	lease, active := readAutoApproveLease(dir, time.Now())
	out := struct {
		Active bool             `json:"active"`
		Lease  AutoApproveLease `json:"lease"`
	}{Active: active, Lease: lease}
	printJSON(out)
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	name := fs.String("name", "", "approver name")
	out := fs.String("out", "", "private key output path")
	_ = fs.Parse(args)
	if *out == "" {
		die(fmt.Errorf("keygen requires --out"))
	}
	keyFile, err := writeApproverKey(*name, *out)
	die(err)
	publicOnly := struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}{
		Name:      keyFile.Name,
		PublicKey: keyFile.PublicKey,
	}
	printJSON(publicOnly)
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	configPath := fs.String("config", "", "config path")
	_ = fs.Parse(args)
	if err := writeDefaultConfig(*configPath); err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		os.Exit(1)
	}
	path := *configPath
	if path == "" {
		path = defaultConfigPath()
	}
	fmt.Println(path)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := fs.String("config", "", "config path")
	addr := fs.String("addr", "127.0.0.1:8787", "listen address")
	stateDir := fs.String("state-dir", "", "state directory")
	allowUnsigned := fs.Bool("allow-unsigned-decisions", false, "allow unsigned approval decisions when no approver keys are configured")
	localApprove := fs.Bool("local-approve", false, "prompt and resolve leases inside this daemon")
	_ = fs.Parse(args)
	cfg := mustLoadConfig(*configPath)
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	fmt.Fprintf(os.Stderr, "capbroker: serving on %s\n", *addr)
	die(runRemoteServer(cfg, dir, *addr, *allowUnsigned, *localApprove))
}

func cmdApprove(args []string) {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	configPath := fs.String("config", "", "config path")
	server := fs.String("server", "", "capbrokerd server URL (or CAPBROKER_SERVER)")
	keyPath := fs.String("key", "", "approver private key path")
	watch := fs.Bool("watch", false, "keep polling for pending requests")
	interval := fs.Duration("interval", 2*time.Second, "poll interval")
	_ = fs.Parse(args)
	cfg := mustLoadConfig(*configPath)
	keyFile, privateKey, err := readApproverKey(*keyPath)
	die(err)
	die(runApprove(cfg, *server, keyFile, privateKey, *watch, *interval))
}

func cmdRequest(args []string) {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	configPath := fs.String("config", "", "config path")
	agent := fs.String("agent", "unknown", "agent name")
	profileName := fs.String("profile", "", "policy profile")
	resource := fs.String("resource", "", "resource identifier")
	reason := fs.String("reason", "", "approval reason")
	ttlValue := fs.String("ttl", "", "requested operator session TTL, e.g. 30m")
	_ = fs.Parse(args)
	cfg := mustLoadConfig(*configPath)
	ttl, err := parseSessionTTL(*ttlValue)
	die(err)
	req := Request{
		Agent:             *agent,
		Profile:           *profileName,
		Resource:          *resource,
		Reason:            *reason,
		SessionTTLSeconds: durationSeconds(ttl),
	}
	profile, err := cfg.validateRequest(req, false)
	die(err)
	stateDir := defaultStateDir()
	grant, created, err := ensureApproved(cfg, stateDir, req, profile)
	die(err)
	_ = appendAudit(stateDir, AuditEvent{
		Event:       "request",
		Agent:       req.Agent,
		Profile:     req.Profile,
		Resource:    req.Resource,
		Reason:      req.Reason,
		GrantID:     grant.ID,
		RequestHash: requestHash(req),
		Message:     map[bool]string{true: "grant_created", false: "grant_reused"}[created],
	})
	printJSON(grant)
}

func cmdSession(args []string) {
	if len(args) == 0 {
		die(fmt.Errorf("session requires start, list, or revoke"))
	}
	switch args[0] {
	case "start":
		cmdSessionStart(args[1:])
	case "list":
		cmdSessionList(args[1:])
	case "revoke":
		cmdSessionRevoke(args[1:])
	default:
		die(fmt.Errorf("unknown session command %q", args[0]))
	}
}

func cmdSessionStart(args []string) {
	fs := flag.NewFlagSet("session start", flag.ExitOnError)
	configPath := fs.String("config", "", "config path")
	stateDir := fs.String("state-dir", "", "state directory")
	agent := fs.String("agent", "unknown", "agent name")
	profileName := fs.String("profile", "", "policy profile")
	resource := fs.String("resource", "", "resource identifier")
	reason := fs.String("reason", "", "operator session reason")
	ttlValue := fs.String("ttl", "", "operator session TTL, e.g. 30m; capped by config")
	_ = fs.Parse(args)
	cfg := mustLoadConfig(*configPath)
	ttl, err := parseSessionTTL(*ttlValue)
	die(err)
	req := Request{
		Agent:             *agent,
		Profile:           *profileName,
		Resource:          *resource,
		Reason:            *reason,
		SessionTTLSeconds: durationSeconds(ttl),
	}
	profile, err := cfg.validateRequest(req, false)
	die(err)
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	sessionTTL := requestedSessionTTL(cfg, profile, req)
	grant, err := createGrant(dir, req, sessionTTL, time.Now())
	die(err)
	_ = appendAudit(dir, AuditEvent{
		Event:       "operator_session_started",
		Agent:       req.Agent,
		Profile:     req.Profile,
		Resource:    req.Resource,
		Reason:      req.Reason,
		GrantID:     grant.ID,
		RequestHash: requestHash(req),
		Message:     fmt.Sprintf("operator session active for %s", sessionTTL.Round(time.Second)),
	})
	printJSON(grant)
}

func cmdSessionList(args []string) {
	fs := flag.NewFlagSet("session list", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "state directory")
	activeOnly := fs.Bool("active", true, "show active sessions only")
	_ = fs.Parse(args)
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	grants, err := loadGrants(dir)
	die(err)
	if *activeOnly {
		grants = pruneExpired(grants, time.Now())
	}
	printJSON(grants)
}

func cmdSessionRevoke(args []string) {
	fs := flag.NewFlagSet("session revoke", flag.ExitOnError)
	stateDir := fs.String("state-dir", "", "state directory")
	id := fs.String("id", "", "session id")
	all := fs.Bool("all", false, "revoke all sessions")
	_ = fs.Parse(args)
	if !*all && *id == "" {
		die(fmt.Errorf("session revoke requires --id or --all"))
	}
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	die(revokeGrants(dir, *id, *all))
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "config path")
	agent := fs.String("agent", "unknown", "agent name")
	profileName := fs.String("profile", "", "policy profile")
	resource := fs.String("resource", "", "resource identifier")
	reason := fs.String("reason", "", "approval reason")
	ttlValue := fs.String("session-ttl", "", "requested operator session TTL, e.g. 30m")
	_ = fs.Parse(args)
	command := fs.Args()
	cfg := mustLoadConfig(*configPath)
	ttl, err := parseSessionTTL(*ttlValue)
	die(err)
	req := Request{
		Agent:             *agent,
		Profile:           *profileName,
		Resource:          *resource,
		Reason:            *reason,
		Command:           command,
		SessionTTLSeconds: durationSeconds(ttl),
	}
	profile, err := cfg.validateRequest(req, true)
	die(err)
	os.Exit(runScopedCommand(cfg, defaultStateDir(), req, profile))
}

func cmdRemoteRun(args []string) {
	fs := flag.NewFlagSet("remote-run", flag.ExitOnError)
	server := fs.String("server", "", "capbrokerd server URL")
	agent := fs.String("agent", "unknown", "agent name")
	profileName := fs.String("profile", "", "policy profile")
	resource := fs.String("resource", "", "resource identifier")
	reason := fs.String("reason", "", "approval reason")
	ttlValue := fs.String("session-ttl", "", "requested operator session TTL, e.g. 30m")
	wait := fs.Duration("wait", 5*time.Minute, "approval wait timeout")
	interval := fs.Duration("interval", 2*time.Second, "approval poll interval")
	_ = fs.Parse(args)
	command := fs.Args()
	ttl, err := parseSessionTTL(*ttlValue)
	die(err)
	req := Request{
		Agent:             *agent,
		Profile:           *profileName,
		Resource:          *resource,
		Reason:            *reason,
		Command:           command,
		SessionTTLSeconds: durationSeconds(ttl),
	}
	os.Exit(runRemoteCommand(*server, req, *wait, *interval))
}

func cmdVaultFetch(args []string) {
	fs := flag.NewFlagSet("vault-fetch", flag.ExitOnError)
	server := fs.String("server", "", "capbrokerd server URL (or CAPBROKER_SERVER)")
	agent := fs.String("agent", "unknown", "agent name")
	profileName := fs.String("profile", "", "vault profile (e.g. bsm-fetch, bw-fetch)")
	ref := fs.String("ref", "", "vault reference: BSM secret UUID or bw item name")
	field := fs.String("field", "", "bw vault field (password|username|notes|totp); ignored for bsm")
	reason := fs.String("reason", "", "approval reason for audit")
	wait := fs.Duration("wait", 5*time.Minute, "approval wait timeout")
	interval := fs.Duration("interval", 2*time.Second, "approval poll interval")
	_ = fs.Parse(args)
	if *profileName == "" || *ref == "" {
		die(fmt.Errorf("vault-fetch requires --profile and --ref"))
	}
	req := Request{
		Kind:       requestKindVault,
		Agent:      *agent,
		Profile:    *profileName,
		Resource:   *ref, // server enforces Resource == VaultRef
		Reason:     *reason,
		VaultRef:   *ref,
		VaultField: *field,
	}
	os.Exit(runVaultFetch(*server, req, *wait, *interval))
}

func cmdDoctor(args []string) {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", "", "config path")
	profileName := fs.String("profile", "", "policy profile")
	_ = fs.Parse(args)
	cfg := mustLoadConfig(*configPath)
	if !runDoctor(cfg, *profileName) {
		os.Exit(1)
	}
}

func cmdGrants(args []string) {
	fs := flag.NewFlagSet("grants", flag.ExitOnError)
	activeOnly := fs.Bool("active", true, "show active grants only")
	_ = fs.Parse(args)
	grants, err := loadGrants(defaultStateDir())
	die(err)
	if *activeOnly {
		grants = pruneExpired(grants, time.Now())
	}
	printJSON(grants)
}

func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	id := fs.String("id", "", "grant id")
	all := fs.Bool("all", false, "revoke all grants")
	_ = fs.Parse(args)
	if !*all && *id == "" {
		die(fmt.Errorf("revoke requires --id or --all"))
	}
	die(revokeGrants(defaultStateDir(), *id, *all))
}

func mustLoadConfig(path string) *Config {
	cfg, err := loadConfig(path)
	die(err)
	return cfg
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "capbroker:", err)
		os.Exit(1)
	}
}

func printJSON(v interface{}) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func usage() {
	fmt.Fprintln(os.Stderr, `capbroker - local approval and capability broker

Commands:
  capbroker init [--config PATH]
  capbroker keygen --name NAME [--out PATH]
  capbroker doctor [--profile PROFILE]
  capbroker request --agent AGENT --profile PROFILE --resource RESOURCE [--reason TEXT]
  capbroker session start --agent AGENT --profile PROFILE --resource RESOURCE [--ttl 30m] [--reason TEXT]
  capbroker session list
  capbroker session revoke --id SESSION_ID | --all
  capbroker run --agent AGENT --profile PROFILE --resource RESOURCE [--reason TEXT] -- COMMAND [ARGS...]
  capbroker serve [--addr ADDR] [--state-dir PATH]
  capbroker approve --server URL --key PATH [--watch]
  capbroker remote-run --server URL --agent AGENT --profile PROFILE --resource RESOURCE [--reason TEXT] -- COMMAND [ARGS...]
  capbroker vault-fetch --server URL --agent AGENT --profile PROFILE --ref REF [--field FIELD] [--reason TEXT]
  capbroker request-upgrade --server URL --agent AGENT --target-profile PROFILE --target-resource VALUE --reason TEXT --grant-mode once|session|permanent
  capbroker review-upgrades --server URL [--watch] [--operator IDENT]
  capbroker grants [--active=true]
  capbroker revoke --id GRANT_ID | --all
  capbroker auto-approve enable [--ttl 30m] [--idle-window 5m] [--reason TEXT]
  capbroker auto-approve disable
  capbroker auto-approve status`)
}
