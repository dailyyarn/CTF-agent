# Kali Helper Notes

This project can work with a manually managed Kali helper, including a VMware guest, but the public repo does not assume any specific IP, port forward, or guest image.

Operator responsibilities:

- start the guest manually
- enable SSH
- add the helper to `remote_hosts`
- keep credentials in environment variables

Kali is optional. Ubuntu / Debian helpers remain a good default for most public setups.
