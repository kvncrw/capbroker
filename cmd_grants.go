// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
)

// `capbroker grants` and `capbroker revoke` operate on three distinct
// grant sources, each with its own storage and lifecycle:
//
//   1. operator_session — grants.json (per-request, TTL-bound, written
//      by the local approval flow when a non-critical request is
//      approved). One grant per (agent, profile, resource) hash.
//
//   2. permanent — permanent-grants.jsonl (append-only, written by the
//      permission-upgrade flow when the operator picks "permanent"
//      mode). No expiry. Identified by the upgrade RequestID that
//      created it.
//
//   3. temporal — temporal-grants.jsonl (append-only, written by the
//      permission-upgrade flow for "once" or "session" mode). Has
//      ExpiresAt. Same RequestID identity as permanent.
//
// Pre-PR-#16 the CLI only surfaced #1, which made the upgrade-flow
// grants invisible until you grepped JSONL files by hand. This file
// unifies all three into one view and lets the operator revoke any of
// them by id from a single command.

// listedGrant is a presentation row, deliberately decoupled from the
// underlying storage types so the table layout stays clean as the two
// sources continue to diverge.
type listedGrant struct {
	source    string // "operator-session" | "permanent" | "temporal"
	id        string // grant.ID for op-session, RequestID for upgrade flow
	mode      string // grant.Kind for op-session, grant_mode for upgrade
	profile   string
	resource  string
	grantedBy string
	createdAt time.Time
	expiresAt time.Time // zero == permanent / no expiry
	reason    string
	expired   bool
}

func cmdGrants(args []string) {
	fs := flag.NewFlagSet("grants", flag.ExitOnError)
	all := fs.Bool("all", false, "include expired temporal grants (default: active only)")
	jsonOut := fs.Bool("json", false, "machine-readable JSON instead of the pretty table")
	kind := fs.String("kind", "", "filter by source: operator-session | permanent | temporal")
	stateDir := fs.String("state-dir", "", "state directory (default: $CAPBROKER_STATE_DIR or XDG)")
	_ = fs.Parse(args)

	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	rows, err := collectAllGrants(dir, time.Now())
	die(err)

	if !*all {
		filtered := rows[:0]
		for _, r := range rows {
			if !r.expired {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}
	if *kind != "" {
		filtered := rows[:0]
		for _, r := range rows {
			if r.source == *kind {
				filtered = append(filtered, r)
			}
		}
		rows = filtered
	}

	// Stable order: source ascending, then expiresAt ascending (zero last
	// since "never expires" is conceptually after "expires soonest").
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].source != rows[j].source {
			return rows[i].source < rows[j].source
		}
		ai, aj := rows[i].expiresAt, rows[j].expiresAt
		if ai.IsZero() != aj.IsZero() {
			return aj.IsZero() // i goes first if i has expiry and j doesn't
		}
		return ai.Before(aj)
	})

	if *jsonOut {
		printJSON(rows)
		return
	}
	renderGrantsTable(os.Stdout, rows)
}

func cmdRevoke(args []string) {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	id := fs.String("id", "", "grant id to revoke (matches operator-session ID or upgrade RequestID)")
	all := fs.Bool("all", false, "revoke all grants of the given --kind (default: operator-session)")
	kind := fs.String("kind", "operator-session", "for --all: operator-session | permanent | temporal")
	stateDir := fs.String("state-dir", "", "state directory (default: $CAPBROKER_STATE_DIR or XDG)")
	operator := fs.String("operator", "", "operator identity for audit (default: $USER@cli)")
	_ = fs.Parse(args)

	if !*all && *id == "" {
		die(fmt.Errorf("revoke requires --id or --all"))
	}
	dir := *stateDir
	if dir == "" {
		dir = defaultStateDir()
	}
	op := *operator
	if op == "" {
		op = os.Getenv("USER") + "@cli"
	}

	if *all {
		die(revokeAllByKind(dir, *kind, op))
		return
	}

	// Per-id revoke. Find across all sources, remove, audit each one. A
	// single id can in theory match multiple sources (it's the operator's
	// responsibility to use --kind if they want to be specific) — we
	// remove every match and audit every removal so the trail is honest.
	rows, err := collectAllGrants(dir, time.Now())
	die(err)
	hits := 0
	for _, r := range rows {
		if r.id != *id {
			continue
		}
		hits++
		if err := revokeOne(dir, r, op); err != nil {
			fmt.Fprintf(os.Stderr, "capbroker: revoke %s/%s failed: %v\n", r.source, r.id, err)
		} else {
			fmt.Printf("revoked %s grant %s (%s += %s)\n", r.source, r.id, r.profile, r.resource)
		}
	}
	if hits == 0 {
		die(fmt.Errorf("no grant with id %q found across operator-session/permanent/temporal", *id))
	}
}

func collectAllGrants(stateDir string, now time.Time) ([]listedGrant, error) {
	var out []listedGrant

	// Operator-session grants (grants.json)
	sess, err := loadGrants(stateDir)
	if err != nil {
		return nil, fmt.Errorf("load operator-session grants: %w", err)
	}
	for _, g := range sess {
		out = append(out, listedGrant{
			source:    "operator-session",
			id:        g.ID,
			mode:      g.Kind,
			profile:   g.Profile,
			resource:  g.Resource,
			createdAt: g.CreatedAt,
			expiresAt: g.ExpiresAt,
			reason:    g.Reason,
			expired:   !g.ExpiresAt.IsZero() && now.After(g.ExpiresAt),
		})
	}

	// Permanent (permanent-grants.jsonl) — never expires
	perms, err := loadGrantsJSONL(permanentGrantsPath(stateDir))
	if err != nil {
		return nil, fmt.Errorf("load permanent grants: %w", err)
	}
	for _, g := range perms {
		out = append(out, listedGrant{
			source:    "permanent",
			id:        g.RequestID,
			mode:      g.GrantMode,
			profile:   g.TargetProfile,
			resource:  g.TargetResource,
			grantedBy: g.GrantedBy,
			createdAt: g.GrantedAt,
			reason:    g.Reason,
			// expired stays false
		})
	}

	// Temporal (temporal-grants.jsonl) — has ExpiresAt
	temps, err := loadGrantsJSONL(temporalGrantsPath(stateDir))
	if err != nil {
		return nil, fmt.Errorf("load temporal grants: %w", err)
	}
	for _, g := range temps {
		out = append(out, listedGrant{
			source:    "temporal",
			id:        g.RequestID,
			mode:      g.GrantMode,
			profile:   g.TargetProfile,
			resource:  g.TargetResource,
			grantedBy: g.GrantedBy,
			createdAt: g.GrantedAt,
			expiresAt: g.ExpiresAt,
			reason:    g.Reason,
			expired:   !g.ExpiresAt.IsZero() && now.After(g.ExpiresAt),
		})
	}

	return out, nil
}

func renderGrantsTable(w io.Writer, rows []listedGrant) {
	if len(rows) == 0 {
		fmt.Fprintln(w, "no grants")
		return
	}
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tMODE\tPROFILE += RESOURCE\tID\tEXPIRES\tBY\tREASON")
	now := time.Now()
	for _, r := range rows {
		expires := "—"
		if !r.expiresAt.IsZero() {
			d := r.expiresAt.Sub(now).Round(time.Second)
			if d < 0 {
				expires = "expired " + (-d).Round(time.Minute).String() + " ago"
			} else if d > 30*24*time.Hour {
				expires = r.expiresAt.UTC().Format("2006-01-02")
			} else {
				expires = "in " + d.String()
			}
		}
		by := r.grantedBy
		if by == "" {
			by = "-"
		}
		reason := r.reason
		if len(reason) > 50 {
			reason = reason[:47] + "…"
		}
		idShort := r.id
		if len(idShort) > 24 {
			idShort = idShort[:21] + "…"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s += %s\t%s\t%s\t%s\t%q\n",
			r.source, r.mode, r.profile, r.resource, idShort, expires, by, reason)
	}
	_ = tw.Flush()
}

// revokeOne removes a single listed grant from its underlying storage
// and writes a permission_upgrade_revoked audit event. Permanent and
// temporal sources rewrite their JSONL atomically (matching the
// pruneTemporalGrants pattern).
func revokeOne(stateDir string, r listedGrant, operator string) error {
	switch r.source {
	case "operator-session":
		if err := revokeGrants(stateDir, r.id, false); err != nil {
			return err
		}
	case "permanent":
		if err := rewriteGrantsJSONLExclude(permanentGrantsPath(stateDir), r.id); err != nil {
			return err
		}
	case "temporal":
		if err := rewriteGrantsJSONLExclude(temporalGrantsPath(stateDir), r.id); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown source %q", r.source)
	}
	approved := false
	_ = appendAudit(stateDir, AuditEvent{
		Event:    "permission_upgrade_revoked",
		Agent:    "", // grants don't store agent for upgrade flow; profile is enough
		Profile:  r.profile,
		Resource: r.resource,
		Reason:   r.reason,
		GrantID:  r.id,
		Approved: &approved,
		Message:  fmt.Sprintf("source=%s mode=%s operator=%s", r.source, r.mode, operator),
	})
	return nil
}

func revokeAllByKind(stateDir, kind, operator string) error {
	switch kind {
	case "operator-session":
		// existing behavior: nuke grants.json
		if err := revokeGrants(stateDir, "", true); err != nil {
			return err
		}
	case "permanent":
		if err := os.Remove(permanentGrantsPath(stateDir)); err != nil && !os.IsNotExist(err) {
			return err
		}
	case "temporal":
		if err := os.Remove(temporalGrantsPath(stateDir)); err != nil && !os.IsNotExist(err) {
			return err
		}
	default:
		return fmt.Errorf("unknown --kind %q (want operator-session | permanent | temporal)", kind)
	}
	approved := false
	_ = appendAudit(stateDir, AuditEvent{
		Event:    "permission_upgrade_revoked",
		Approved: &approved,
		Message:  fmt.Sprintf("bulk-revoke source=%s operator=%s", kind, operator),
	})
	fmt.Printf("revoked all %s grants\n", kind)
	return nil
}

// rewriteGrantsJSONLExclude reads a JSONL file and rewrites it with
// every entry whose RequestID does NOT match the given id. flock-
// serialized like appendGrantJSONL; idempotent if id isn't present.
func rewriteGrantsJSONLExclude(path, id string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}
	unlock, err := lockGrantsFile(path)
	if err != nil {
		return err
	}
	defer unlock()
	all, err := loadGrantsJSONL(path)
	if err != nil {
		return err
	}
	var keep []permissionGrant
	removed := 0
	for _, g := range all {
		if strings.EqualFold(g.RequestID, id) {
			removed++
			continue
		}
		keep = append(keep, g)
	}
	if removed == 0 {
		return nil
	}
	if len(keep) == 0 {
		// Truncate rather than delete so subsequent appends still pick
		// the right path; matches the laptop daemon's expectation that
		// these files always exist (or always don't) per state-dir.
		return os.Truncate(path, 0)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	for _, g := range keep {
		line, err := json.Marshal(g)
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return err
		}
		if _, err := tmp.Write(append(line, '\n')); err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmpName)
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}
