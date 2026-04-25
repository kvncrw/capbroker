# capbroker

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)

`capbroker` is a first-pass local approval and capability broker for chat agents.
It keeps durable credentials out of model context by approving scoped tool runs and
injecting secrets only into the child process that needs them.

This prototype is intentionally local-first:

- approval is on the authority host via `zenity`, `kdialog`, `qarma`, or a TTY
  prompt;
- policy is deny-by-default JSON under XDG config;
- active grants are cached under XDG state for short TTLs;
- secrets are read from env/files/commands at execution time;
- child output is redacted if it accidentally prints an injected secret;
- audit events are JSONL and do not include secret values.

It also has a first-pass distributed mode for agents running on a different
machine. See [docs/remote-agent.md](docs/remote-agent.md).

## Install

```bash
go build -o capbroker .
install -m 0755 capbroker ~/.local/bin/capbroker
capbroker init
capbroker doctor --profile github-review
```

Default paths:

- config: `~/.config/capbroker/config.json`
- state: `~/.local/state/capbroker/`

Override with `CAPBROKER_CONFIG` and `CAPBROKER_STATE_DIR`.

## Workflow

Start an operator session when you are present and want the agent to keep
working without repeated prompts:

```bash
capbroker session start \
  --agent hermes \
  --profile github-review \
  --resource example-org/example-repo \
  --ttl 45m \
  --reason "operator present: review and update repo"
```

For the session TTL, capbroker silently caps the requested value at
`defaults.max_session_seconds`, which defaults to 3 hours. Non-critical commands
inside the same `agent + profile + resource` scope reuse the session. Commands
matching `critical_commands` still require an explicit one-command approval.

Run a GitHub command through a profile:

```bash
capbroker run \
  --agent codex \
  --profile github-review \
  --resource example-org/example-repo \
  --reason "review PR 139" \
  -- gh pr view 139 --repo example-org/example-repo
```

The broker validates:

- agent is allowed by the profile;
- resource matches the profile resource patterns;
- command starts with an allowed command prefix;
- local approval exists or is granted by the user.

Then it resolves profile secrets and runs the command. The agent sees command
output, not the credential. Secret resolution happens after approval, so a
vault or token helper is not touched until the local user has approved the
capability.

Request approval without running a command:

```bash
capbroker request \
  --agent remote-agent \
  --profile k8s-read \
  --resource namespace/example-app \
  --reason "inspect failed deployment"
```

List and revoke grants:

```bash
capbroker session list
capbroker session revoke --id cap_...
capbroker session revoke --all
```

Run through a remote approval authority:

```bash
./scripts/run-authority
```

From a remote agent host:

```bash
capbroker remote-run \
  --agent hermes \
  --profile github-review \
  --resource example-org/example-repo \
  --reason "review PR 142" \
  -- gh pr view 142 --repo example-org/example-repo
```

Or use the wrapper:

```bash
cap-gh pr view 142 --repo example-org/example-repo
```

## Policy Shape

See [examples/config.json](examples/config.json). A profile is the unit of
approval. Keep profiles narrow enough that "approve for 10 minutes" is a sane
decision.

```json
{
  "profiles": {
    "github-review": {
      "agents": ["remote-agent", "hermes", "codex"],
      "resources": ["example-org/*"],
      "ttl_seconds": 900,
      "require_approval": true,
      "allowed_commands": [["gh", "pr", "view"], ["gh", "pr", "review"]],
      "critical_commands": [["gh", "repo", "delete"]],
      "env": {
        "GH_TOKEN": "github_token_from_gh_cli"
      }
    }
  }
}
```

Secret sources can be:

- `env`: read a local environment variable;
- `file`: read a file, such as a vault session file or token file;
- `command`: run a command and use stdout;
- `provider`: call a named provider plugin with a JSON request on stdin and use
  stdout.

Provider plugins keep capbroker agent-agnostic. A provider is just an executable
contract:

```json
{
  "secret_sources": {
    "kubeconfig": {
      "type": "provider",
      "provider": "bws",
      "ref": "secret-id-or-path",
      "field": "value"
    }
  },
  "secret_providers": {
    "bws": {
      "type": "command",
      "command": ["capbroker-provider-bws"]
    }
  }
}
```

The provider command receives `{"ref":"...","field":"...","metadata":{...}}`
on stdin and must print only the requested value. This is enough for Bitwarden
Secrets Manager, 1Password, Vault, AWS Secrets Manager, or site-local
contrib providers without baking any one vault into capbroker. For real vault
integration, return one specific item field, never whole vault records.

Profiles can also materialize a secret as a temporary file and expose the path
through an environment variable:

```json
{
  "profiles": {
    "k8s-read": {
      "files": {
        "KUBECONFIG": "kubeconfig"
      }
    }
  }
}
```

The file contents are encrypted inside distributed leases, written with mode
`0600` for the approved subprocess, and removed when the command exits.

Private repositories require a GitHub credential source. The default GitHub
example uses `gh auth token` as a local secret source and injects it as
`GH_TOKEN` only into the approved subprocess. Validate it with:

```bash
capbroker doctor --profile github-review
```

If that fails, run `gh auth login -h github.com` locally or change the source to
a password manager command that returns only the token. If you prefer a literal
env var source, change that source to:

```json
{
  "type": "env",
  "env": "GITHUB_TOKEN"
}
```

## Current Limits

Distributed mode is still LAN-only and unauthenticated at request creation.
Keep it on a trusted network until agent identity signatures or mTLS land. Next
useful steps are an MCP server, Git credential helper, Kubernetes exec plugin,
lease cleanup, and signed mobile approval.

## License

`capbroker` is licensed under `AGPL-3.0-or-later`. See [LICENSE](LICENSE) for
the canonical AGPLv3 text and [docs/license.md](docs/license.md) for project
licensing notes.
