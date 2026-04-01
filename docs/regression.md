# Regression

The public repo keeps the regression and smoke flows so you can validate the runtime after local changes.

Examples:

```powershell
ctf-agent regress --cases-root .\tests --config .\local_config.json
ctf-agent pwn-live-smoke --config .\local_config.json
```

If no compatible remote hosts are configured, `pwn-live-smoke` returns `skipped`.
