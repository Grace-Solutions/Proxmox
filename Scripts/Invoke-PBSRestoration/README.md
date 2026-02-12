# Invoke-PBSRestoration

Restores the latest PBS (Proxmox Backup Server) backups for guests selected by VMID list, notes regex, or JSON configuration. Supports both VMs (`qemu`) and containers (`lxc`).

## Features

- **Selection modes**: VMID list, backup notes regex, or JSON config (local file or HTTP URL)
- **Round-robin storage**: Automatically distributes restores across available target storages
- **Template auto-remap**: Detects templates and assigns new VMIDs when restoring to a different node
- **Dry-run mode**: Preview what would be restored without executing
- **Idempotent**: Skips guests that already exist (unless `--force` is used)
- **Central logging**: UTC timestamps with optional file logging

## Usage

```bash
# Restore specific VMIDs
bash Invoke-PBSRestoration.sh --vmids "101,102"

# Restore by backup notes regex
bash Invoke-PBSRestoration.sh --notes-regex "DOCKER-HOST-.*"

# Restore from JSON config
bash Invoke-PBSRestoration.sh --config Invoke-PBSRestoration.json

# Restore from remote JSON config
bash Invoke-PBSRestoration.sh --config "https://example.com/configs/restore.json"

# Dry run with specific target storage
bash Invoke-PBSRestoration.sh -i "5000" --force --target-storage local-zfs-pool-00001 --dry-run
```

## Parameters

| Flag | Description |
|---|---|
| `-i, --vmids LIST` | Comma-separated VMID list |
| `-n, --notes-regex PAT` | Extended regex matched against backup notes |
| `-c, --config FILE\|URL` | JSON config file path or HTTP(S) URL |
| `-s, --pbs-storage NAME` | PBS storage name (default: auto) |
| `-t, --target-storage S` | Target storage name (default: auto) |
| `--target-storage-mode MODE` | `round-robin` or `single` (default: round-robin) |
| `-N, --node NODE` | Target node for restore (default: local hostname) |
| `-f, --force` | Overwrite existing guest with same VMID |
| `-u, --unique` | Assign unique random MAC addresses on restore |
| `--start` | Start guest after successful restore |
| `--pool POOL` | Add restored guest to this pool |
| `--bwlimit KB/S` | I/O bandwidth limit in KiB/s |
| `--dry-run` | Show what would be restored without executing |
| `-l, --log-file FILE` | Log file path |
| `-d, --debug` | Enable debug logging |
| `-h, --help` | Show help message |

## JSON Config Example

See `Invoke-PBSRestoration.json.example` for the configuration format.

