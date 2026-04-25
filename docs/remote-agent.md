# Remote Agent Workflow

This is the distributed workflow for an agent running on one machine while the
approval authority and secret resolution stay on another trusted host.

## Trust Split

- The authority host runs `capbroker serve --local-approve` on a private
  address.
- The remote agent host runs `capbroker remote-run` or a wrapper such as
  `cap-gh`.
- Durable capability secrets stay on the authority host or in CLIs available to
  that host.
- The remote agent receives only a short encrypted lease for the exact command
  it asked to run.

The authority daemon stores policy, pending requests, audit events, and
encrypted leases under the configured state directory. The remote agent host
does not need Bitwarden, 1Password, GitHub PATs, kubeconfigs, or other durable
credentials for this workflow.

The remote agent still needs ordinary tooling in its runtime image (`kubectl`,
`gh`, `jq`, `rg`, database clients as needed). The broker can lease credentials
to approved commands, but it does not install those executables into the agent
runtime.

## Authority Host

Start the listener from the capbroker project root:

```bash
./scripts/run-authority
```

By default this listens on loopback:

```text
127.0.0.1:8787
```

Override the address for a private LAN, tailnet, or mTLS-protected ingress:

```bash
CAPBROKER_LISTEN_ADDR=10.0.0.10:8787 ./scripts/run-authority
```

The authority config at `~/.config/capbroker/config.json` can resolve the
GitHub profile token with:

```json
{
  "type": "command",
  "command": ["gh", "auth", "token"]
}
```

Swap that source for `bw`, `op`, `vault`, `aws`, or another secret-provider CLI
when desired. The important property is that the provider session stays on the
authority host; the CLI returns only the requested field for the approved
capability.

Provider plugins are the preferred shared shape for vault integration:

```json
{
  "secret_sources": {
    "read_only_kubeconfig": {
      "type": "provider",
      "provider": "example-vault",
      "ref": "00000000-0000-0000-0000-000000000000",
      "field": "value"
    }
  },
  "secret_providers": {
    "example-vault": {
      "type": "command",
      "command": ["capbroker-provider-example"]
    }
  }
}
```

For kubeconfigs and other file-shaped material, map the source through a profile
file grant:

```json
{
  "profiles": {
    "k8s-read": {
      "files": {
        "KUBECONFIG": "read_only_kubeconfig"
      }
    }
  }
}
```

The remote agent receives only an encrypted lease. `remote-run` writes the
kubeconfig to a temporary `0600` file, sets `KUBECONFIG` to that path for the
approved command, and removes the file when the command exits.

## Remote Agent

The remote agent image or runtime needs:

- `capbroker`
- the command-line tools used by approved profiles, such as `gh` or `kubectl`
- wrapper scripts such as `cap-gh` or `cap-kubectl`, if desired
- `CAPBROKER_SERVER=http://10.0.0.10:8787`
- the directory containing these tools at the front of `PATH`

Use:

```bash
cap-gh pr view 142 --repo example-org/example-repo
cap-gh pr diff 142 --repo example-org/example-repo
cap-gh pr review 142 --repo example-org/example-repo --comment --body-file review.md
cap-kubectl -n example-app get pods
cap-kubectl -n example-app logs deploy/example-worker --tail=80
```

`cap-gh` extracts the repo from `--repo`/`-R` and wraps:

```bash
capbroker remote-run \
  --agent remote-agent \
  --profile github-review \
  --resource OWNER/REPO \
  -- gh ...
```

`cap-kubectl` extracts `-n`/`--namespace` and wraps:

```bash
capbroker remote-run \
  --agent remote-agent \
  --profile k8s-read \
  --resource namespace/NAME \
  -- kubectl ...
```

## Current Limits

- The authority daemon must be running in a real user session if local desktop
  or TTY approval prompts are enabled.
- Request creation is not authenticated yet. Keep this LAN-only until agent
  identity signatures land.
- Leases are exact-command scoped in `remote-run`, but approved encrypted leases
  remain in daemon state until cleanup is added.
- Kubernetes admin workflows should use separate executor/runner profiles before
  handing raw cluster-admin credentials to a remote agent.
