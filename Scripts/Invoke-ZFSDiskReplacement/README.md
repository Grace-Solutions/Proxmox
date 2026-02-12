# Invoke-ZFSDiskReplacement

Idempotently replaces a failed disk in a ZFS mirror pool with a new spare. Handles partition table replication, `zpool replace`, and resilver monitoring.

## Features

- **Idempotent state detection**: Detects resilver already in progress, pool already healthy, or replacement already complete
- **Automatic discovery**: Finds the failed disk reference in the pool and identifies the healthy mirror member
- **Partition table replication**: Copies partition layout from the healthy disk to the new disk via `sgdisk`
- **By-id device paths**: Uses `/dev/disk/by-id/` paths for ZFS stability
- **Resilver monitoring**: Optional `--monitor` flag to track progress to completion
- **Dry-run mode**: Preview all steps without executing

## Usage

```bash
# Replace a failed disk
bash Invoke-ZFSDiskReplacement.sh \
    --pool local-zfs-pool-00001-A \
    --failed nvme2n1 \
    --new nvme0n1

# Dry run to preview
bash Invoke-ZFSDiskReplacement.sh \
    --pool local-zfs-pool-00001-A \
    --failed nvme2n1 \
    --new nvme0n1 \
    --dry-run

# Replace and monitor resilver progress
bash Invoke-ZFSDiskReplacement.sh \
    --pool local-zfs-pool-00001-A \
    --failed nvme2n1 \
    --new nvme0n1 \
    --monitor --monitor-interval 30
```

## Parameters

| Flag | Description |
|---|---|
| `-p, --pool POOL` | ZFS pool name (required) |
| `-f, --failed DEVICE` | Failed disk device name, e.g. `nvme2n1` (required) |
| `-n, --new DEVICE` | New replacement disk device name, e.g. `nvme0n1` (required) |
| `--monitor` | Monitor resilver progress until completion |
| `--monitor-interval S` | Seconds between progress checks (default: 30) |
| `--dry-run` | Show what would be done without executing |
| `-l, --log-file FILE` | Log file path |
| `-d, --debug` | Enable debug logging |
| `-h, --help` | Show help message |

