# Invoke-ProxmoxUEFIKeyEnrollment

Idempotently enrolls Microsoft UEFI CA 2023 certificates on Windows VMs whose EFI disk has `pre-enrolled-keys` but lacks `ms-cert=2023`.

## Features

- **Auto-detection**: Discovers Windows VMs (`win10`/`win11`) needing enrollment
- **OS filtering**: Skips non-Windows VMs (Linux etc.) that don't need the certificate
- **Template handling**: Temporarily removes template flag, enrolls, then restores it
- **Graceful shutdown**: ACPI shutdown with configurable timeout for running VMs
- **State preservation**: Restarts VMs that were running; leaves stopped VMs stopped
- **Dry-run mode**: Preview what would be done without executing
- **Idempotent**: Re-running finds nothing to do once all VMs are enrolled

## Usage

```bash
# Enroll all eligible VMs on the local node
bash Invoke-ProxmoxUEFIKeyEnrollment.sh

# Enroll specific VMIDs
bash Invoke-ProxmoxUEFIKeyEnrollment.sh --vmids "22008,5401,25000"

# Dry run to preview
bash Invoke-ProxmoxUEFIKeyEnrollment.sh --dry-run

# Custom shutdown timeout (seconds)
bash Invoke-ProxmoxUEFIKeyEnrollment.sh --shutdown-timeout 300
```

## Parameters

| Flag | Description |
|---|---|
| `-i, --vmids LIST` | Comma-separated VMID list |
| `-c, --config FILE` | JSON config file path |
| `-N, --node NODE` | Target node (default: local hostname) |
| `--shutdown-timeout S` | Seconds to wait for graceful shutdown (default: 120) |
| `--dry-run` | Show what would be done without executing |
| `-l, --log-file FILE` | Log file path |
| `-d, --debug` | Enable debug logging |
| `-h, --help` | Show help message |

