# Ubuntu Pwn Bootstrap

`pwn-ubuntu-bootstrap` is the generic bootstrap template for preparing an Ubuntu or Debian helper for `pwn` work.

Typical uses:

- install baseline build tools
- install debugger dependencies
- improve parity before a harder pwn lane

Example:

```powershell
ctf-agent remote-template --kind pwn-ubuntu-bootstrap --host linux_primary --execute --config .\local_config.json
```
