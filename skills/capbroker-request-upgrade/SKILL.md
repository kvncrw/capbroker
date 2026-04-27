---
name: capbroker-request-upgrade
description: When a `cap-*` wrapper exits with `403 Forbidden: resource ... is not allowed for profile ...`, file a structured permission-upgrade request to the operator instead of giving up.
---

# Permission-upgrade requests

The capbroker daemon enforces a static allowlist (`Profile.Resources`)
plus a dynamic allowlist (temporal + permanent grants written by this
skill's flow). When a `cap-*` wrapper denies your command with the
literal phrase `is not allowed for profile`, the daemon's policy ran
and refused — the resource isn't in the allowlist for that profile.

Your job in that moment: file ONE upgrade request with a concrete
operator-visible justification, wait for the decision, and either
retry the original command (on grant) or surface the denial cleanly
to the user (on refusal).

Do not retry-spam. Do not invent reasons. Do not ask for permanent
grants without a specific argument why a temporal grant won't do.

## When to file

You should file a request iff ALL of the following hold:

1. The wrapper's stderr contains `is not allowed for profile` (literal phrase — the daemon's own message).
2. The capability you're asking for is *narrow*: a single literal value (`namespace/foo`, `gh:org/repo`), never a glob.
3. You have a concrete, mission-specific reason ≥30 characters that names: (a) what mission you're on, (b) the specific need this resource fills.
4. You haven't already filed an identical request in this session — duplicate reasons get rejected by the daemon's dedup window.

Do NOT file if:
- The error is a transient connectivity issue (the wrapper says timeout, network, etc.).
- You haven't actually run the command yet (don't pre-emptively ask).
- The resource is something the operator obviously wouldn't grant (e.g. `namespace/kube-system` from a research-mission agent).

## How to file

```sh
capbroker request-upgrade \
  --target-profile k8s-read \
  --target-resource namespace/basilisk \
  --reason "screenshot-research mission needs API pod logs to diagnose missing thumbnails (cron_xyz)" \
  --grant-mode once \
  --original-request "$ORIGINAL_REQUEST_ID"
```

### Grant-mode defaults

- **`once`** — default. The grant lasts 24h and is for "this single mission needs this resource right now". Pick this 95% of the time.
- **`session`** — only if the mission is going to repeatedly hit this resource over the next few hours. Bound to the operator's session TTL.
- **`permanent`** — never the default. Only request if you've established that this resource is *structurally* needed by this profile across all future missions and you can name the structural reason. Almost always wrong; the operator can downgrade your `permanent` request to `once` but they'll be annoyed.

### Reason quality

The reason is the only thing the operator sees on their phone. Make it stand alone:

- **Bad**: `"need access"` (rejected — too short)
- **Bad**: `"the api needs this"` (vague — what api? what need?)
- **Bad**: `"task failed without it"` (no signal — what task?)
- **Good**: `"screenshot mission cron_4f3 needs API pod logs to diagnose why thumbnail generation is silently failing for 30% of urls"`
- **Good**: `"web-research mission needs read access to the kestrel namespace's argocd-server logs to verify the deploy that broke /search landed cleanly"`

If you can't write a good reason in <30 seconds, you probably don't actually need the capability — give up and report the denial.

## After the decision

- **Exit 0 (granted)**: re-run the *exact* original command. If it 403s again with the same message, the grant didn't take — that's a daemon bug, give up and report it. Do not file another upgrade request.
- **Exit 1 (denied / timeout)**: stop. Report the denial to the user with the operator's message (which you can read from the request via `getJSON /v1/requests/{id}`). Do not file a second request with a "better" reason — the operator already saw the first one.

## What this skill is NOT for

- Adding entirely new profiles. Operators do that by editing `config.json`. If your profile doesn't exist, the wrapper would have said "unknown profile" not "resource is not allowed".
- Bypassing rate limits. The daemon caps you at 5 upgrade requests per hour per agent. If you're hitting that ceiling, you're spamming — stop.
- Routine operations. If you find yourself reaching for this skill more than once per mission, the static allowlist is wrong and the operator should fix it permanently. Surface that pattern to the user.
