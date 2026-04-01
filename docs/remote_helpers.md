# Remote Helpers

Remote helpers connect the local agent to authorized Linux hosts for:

- probing capabilities
- creating per-task remote workspaces
- uploading files and scripts
- running commands, Python, and templates
- downloading artifacts, traces, and summaries

## Public edition policy

- The public repo does not ship any concrete `remote_hosts`
- Passwords should stay in environment variables
- Hostnames, IPs, usernames, and notes are operator-owned configuration

## Minimal config shape

```json
{
  "remote_policy": {
    "auto_select_for_binary": true,
    "disable_local_wsl_runner": true,
    "pwn_remote_first": true,
    "preferred_hosts_by_category": {}
  },
  "remote_hosts": {
    "linux_primary": {
      "host": "YOUR_HOST_OR_IP",
      "port": 22,
      "username": "YOUR_USERNAME",
      "password_env": "CTF_AGENT_REMOTE_PRIMARY_PASSWORD",
      "base_dir": "/tmp/ctf-agent",
      "python_bin": "python3",
      "preferred_for": ["pwn", "re", "reverse"],
      "notes": "Primary helper host"
    }
  }
}
```

## Common commands

```powershell
ctf-agent remote-probe --host linux_primary --config .\local_config.json
ctf-agent remote-recommend --category pwn --target .\chall --config .\local_config.json
ctf-agent remote-template --kind pwn-ubuntu-bootstrap --host linux_primary --execute --config .\local_config.json
```

## Live smoke

`ctf-agent pwn-live-smoke` now uses configured remote hosts dynamically. If none are configured, it returns `skipped` instead of assuming private host aliases.

## Capability notes

The strongest public setup usually adds:

- one or more Ubuntu / Debian helpers
- optional Kali helper
- optional CentOS / Rocky / Alma fallback

The exact topology is up to the operator.
