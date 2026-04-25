# Threat Model

## Goal

Prevent durable secrets from entering chat transcripts, model context, logs, or
memories while still letting agents perform approved work.

The broker cannot make an arbitrary compromised machine safe. It can reduce
blast radius and make sensitive actions explicit, scoped, short-lived, and
auditable.

## Trust Boundaries

- The model is untrusted for secret custody.
- Agent transcripts and memories are untrusted for secret custody.
- Tool subprocesses are trusted only for the approved command and duration.
- The local user session is trusted to approve or deny requests.
- Vaults and providers remain systems of record for durable credentials.
- In distributed mode, `capbrokerd` is trusted for routing, policy checks, and
  audit state, but not for plaintext capability secrets.

## Properties In This Prototype

- Deny by default unless a policy profile allows the agent/resource/command.
- Operator sessions are scoped to `agent + profile + resource`.
- Operator sessions expire after their capped TTL and can be revoked.
- Commands matching `critical_commands` bypass implicit sessions and require
  explicit one-command approval.
- Secrets are resolved only after policy and approval pass.
- Secrets are injected as child-process environment variables or materialized as
  temporary `0600` files whose paths are exposed through environment variables.
- Child stdout/stderr are redacted for injected secret values.
- Audit records include metadata and command argv, not secret values.
- Remote approval decisions can be signed by authority-held Ed25519 approver
  keys.
- Remote leases are encrypted to the requesting agent's ephemeral ECDH key, so
  `capbrokerd` stores ciphertext rather than plaintext environment values or
  file contents.

## Known Gaps

- A malicious approved command can still exfiltrate the secret while it runs.
  Mitigation: keep command prefixes tight and prefer provider-specific broker
  operations over arbitrary `run`.
- Local approval dialogs do not defend against full desktop compromise.
  Mitigation: future mobile/passkey approval with signed request payloads.
- File grants are temporary local copies, not live mounts. A malicious approved
  command can still read or copy them while it runs. Mitigation: keep command
  prefixes tight, prefer read-only credentials, and keep TTLs short.
- Command secret sources can be dangerous if the config is writable by an
  attacker. Mitigation: config files should be mode `0600`, and policy should be
  managed as code for shared deployments.
- Redaction is best-effort and line-oriented. It is a last-resort guard, not the
  primary control.
- Remote request creation is not authenticated yet. Mitigation: keep
  `capbrokerd` behind a tailnet/private ingress/mTLS proxy until agent identity
  signatures are implemented.
- `capbrokerd` currently stores approved encrypted leases until state cleanup is
  added. Mitigation: keep TTLs short and protect the daemon state volume.

## Design Direction

Future versions should prefer specific capability tools:

- `github.pr_review(repo, pr, body)` with a GitHub App installation token minted
  server-side;
- `kubernetes.rollout_restart(namespace, deployment)` via a broker-held service
  identity or short-lived RoleBinding;
- `vault.read_field(path, field)` returning only into a subprocess or provider
  call, not to chat.

The more the broker performs the sensitive operation itself, the less often raw
secrets need to enter a child process at all.
