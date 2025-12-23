# Proxmox Template Creation Script

Automated creation of Proxmox VM templates from cloud images with full customization support.

## Features

- **Cloud Image Support**: Downloads and converts cloud images (Ubuntu, Debian, etc.) to Proxmox templates
- **Image Caching**: Caches downloaded images to reduce server load (configurable TTL, default 8 hours)
- **Automatic Storage Detection**: Set `storagePool` to `"auto"` for auto-detection of ZFS/LVM/BTRFS storage
- **Random Password Generation**: Configurable password length and special characters (QWERTY-typeable)
- **SMBIOS Customization**: Configure manufacturer, product, version, sku, family (UUID and serial always randomized)
- **TPM 2.0**: Automatic TPM 2.0 device provisioning for secure boot support
- **VirtIO RNG**: Hardware random number generator for improved entropy
- **NUMA**: Non-Uniform Memory Access enabled for better multi-socket performance
- **SPICE Enhancements**: Folder sharing and video streaming enabled by default
- **VM Firewall**: Pre-configured firewall with RFC1918, RFC6598, and public internet rules
- **Dynamic Tags**: Automatic tagging with template type, OS, version, and features
- **GitHub Script Integration**: Download and execute scripts from private GitHub repos on first boot
- **Cloud-Init Configuration**: Full cloud-init support with user, password, SSH keys, network settings
- **Package Installation**: Install packages during image customization (global + per-template)
- **Custom Commands**: Run virt-customize commands and first-boot commands
- **VM Notes**: Auto-generated markdown notes with credentials and configuration
- **Idempotent**: Safe to run multiple times without creating duplicate resources

## Requirements

The following packages are required on the Proxmox host (configured in `orchestratorPackages`):

```
jq libguestfs-tools virt-v2v apg openssl curl
```

## Script Execution

```bash
# Make script executable (one-time)
chmod +x Create-ProxmoxTemplate.sh

# Run with bash
bash Create-ProxmoxTemplate.sh

# Run with sh
sh Create-ProxmoxTemplate.sh

# Run directly (requires executable permission)
./Create-ProxmoxTemplate.sh

# Process a specific VMID
bash Create-ProxmoxTemplate.sh -v 9000

# Use a different config file
bash Create-ProxmoxTemplate.sh -c /path/to/config.json

# Enable verbose/debug logging
bash Create-ProxmoxTemplate.sh -d
```

## Configuration

Copy `Create-ProxmoxTemplate.json.example` to `Create-ProxmoxTemplate.json` and customize.

### Complete Example

```json
{
  "globalSettings": {
    "storagePool": "auto",
    "downloadDirectory": "/tmp/proxmox-templates",
    "imageCacheHours": 8,
    "tags": ["template", "linux", "managed"],
    "randomPassword": {
      "enabled": true,
      "length": 16,
      "specialChars": "!@#$%^&*()-_=+"
    },
    "orchestratorPackages": ["jq", "libguestfs-tools", "curl"],
    "templatePackages": ["qemu-guest-agent", "curl", "wget", "htop"],
    "smbios": {
      "manufacturer": "My Organization",
      "product": "Virtual Machine",
      "version": "1.0",
      "sku": "VM-001",
      "family": "Server"
    },
    "github": {
      "personalAccessToken": "",
      "username": "your-username",
      "repo": "your-repo",
      "branch": "main",
      "scripts": [
        {
          "enabled": true,
          "repoPath": "Scripts/Setup.sh",
          "description": "Initial setup script"
        }
      ]
    },
    "cloudInit": {
      "user": "admin",
      "password": "changeme",
      "nameserver": "8.8.8.8",
      "searchdomain": "example.com",
      "sshkey": ""
    }
  },
  "templates": [
    {
      "enabled": true,
      "vmid": "9000",
      "name": "Template-Ubuntu-2404-LTS",
      "imageUrl": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
      "osDiskSize": "64G",
      "dataDiskSize": "128G",
      "timezone": "America/New_York",
      "tags": ["ubuntu", "v24.04", "lts", "production"],
      "installPowerShell": true,
      "github": {"enabled": true},
      "vmHardware": {
        "cores": 4,
        "sockets": 1,
        "memory": 8192,
        "balloon": 4096,
        "cpu": "x86-64-v3",
        "machine": "q35",
        "bios": "ovmf",
        "scsihw": "virtio-scsi-single",
        "ostype": "l26"
      },
      "network": [
        {
          "bridge": "vmbr0",
          "firewall": 1,
          "vlan": "10",
          "ip": "",
          "gateway": "",
          "ip6": "",
          "gateway6": ""
        }
      ],
      "cloudInit": {},
      "packages": ["nginx", "docker.io"],
      "virtCustomizeCommands": [],
      "firstBootCommands": ["apt-get update && apt-get upgrade -y"]
    }
  ]
}
```

### Global Settings

| Setting | Description |
|---------|-------------|
| `storagePool` | Storage pool name, or `"auto"` for auto-detection |
| `downloadDirectory` | Temp directory for downloading images |
| `imageCacheHours` | Hours to cache downloaded images before re-downloading (default: 8) |
| `tags` | Default tags array for all templates (see Tag Configuration) |
| `randomPassword.enabled` | Generate random passwords for users |
| `randomPassword.length` | Length of generated passwords (default: 12) |
| `randomPassword.specialChars` | Special characters to use (default: `!@#$%^&*()-_=+[]{}|;:,.<>?`) |
| `orchestratorPackages` | Packages to install on Proxmox host |
| `templatePackages` | Packages to install on all templates |
| `smbios` | SMBIOS settings (manufacturer, product, version, sku, family) |
| `github` | GitHub API settings for downloading scripts |
| `cloudInit` | Default cloud-init settings for all templates |

### Template Settings

| Setting | Description |
|---------|-------------|
| `enabled` | Process this template (true/false) |
| `vmid` | Proxmox VM ID |
| `name` | Template name |
| `imageUrl` | URL to cloud image (.img or .qcow2) |
| `osDiskSize` | OS disk size (e.g., "64G") |
| `dataDiskSize` | Additional data disk size |
| `timezone` | Timezone for the VM (see Timezone Reference) |
| `tags` | Array of tags for this template (overrides global tags) |
| `installPowerShell` | Install PowerShell via snap on first boot (true/false) |
| `github.enabled` | Enable GitHub script processing for this template (true/false) |
| `vmHardware` | CPU, memory, machine type, BIOS settings (see Hardware Reference) |
| `network` | Array of network adapters (see Network Configuration) |
| `cloudInit` | Per-template cloud-init overrides |
| `packages` | Additional packages for this template |
| `virtCustomizeCommands` | Commands to run during image customization |
| `firstBootCommands` | Commands to run on first boot of cloned VMs |

### Tag Configuration

Tags can be configured at three levels with the following precedence:

1. **Per-template tags** (highest) - `templates[].tags` array
2. **Global tags** - `globalSettings.tags` array
3. **Auto-generated** (lowest) - Automatically generated from template name/URL

**Examples:**

```json
// Global tags (applied to all templates without per-template tags)
"globalSettings": {
  "tags": ["template", "linux", "cloud-init"]
}

// Per-template tags (override global tags)
"templates": [{
  "tags": ["template", "ubuntu", "v24.04", "lts", "production"]
}]
```

If both global and per-template `tags` arrays are empty, the script auto-generates tags based on:
- OS detection from template name/URL (ubuntu, debian, rocky, etc.)
- Version extraction (v24.04, v12, etc.)
- LTS detection
- "template" and "cloud-init" base tags

### Network Configuration

The `network` setting is an array of network adapter objects. Each adapter supports:

| Field | Description | Default |
|-------|-------------|---------|
| `bridge` | Proxmox bridge (e.g., "vmbr0") | "vmbr0" |
| `firewall` | Enable firewall (0 or 1) | 1 |
| `vlan` | VLAN tag (optional) | "" |
| `ip` | Static IPv4 in CIDR format (e.g., "192.168.1.100/24") | "" (DHCP) |
| `gateway` | IPv4 gateway (optional, used with static IP) | "" |
| `ip6` | Static IPv6 in CIDR format (e.g., "2001:db8::1/64") | "" (DHCP) |
| `gateway6` | IPv6 gateway (optional, used with static IPv6) | "" |

**DHCP (default):** Leave `ip` and `ip6` empty for DHCP on both IPv4 and IPv6.

**Static IPv4 only:**
```json
"network": [
    {
        "bridge": "vmbr0",
        "firewall": 1,
        "vlan": "",
        "ip": "192.168.1.100/24",
        "gateway": "192.168.1.1",
        "ip6": "",
        "gateway6": ""
    }
]
```

**Multiple adapters (static + DHCP):**
```json
"network": [
    {
        "bridge": "vmbr0",
        "firewall": 1,
        "vlan": "",
        "ip": "192.168.1.100/24",
        "gateway": "192.168.1.1",
        "ip6": "",
        "gateway6": ""
    },
    {
        "bridge": "vmbr1",
        "firewall": 1,
        "vlan": "100",
        "ip": "",
        "gateway": "",
        "ip6": "",
        "gateway6": ""
    }
]
```

### Random Password Configuration

```json
"randomPassword": {
    "enabled": true,
    "length": 12,
    "specialChars": "!@#$%^&*()-_=+[]{}|;:,.<>?"
}
```

- Characters are limited to QWERTY-typeable characters
- Passwords include lowercase, uppercase, digits, and special characters
- Only randomly generated passwords are displayed in VM notes

### GitHub Integration

Download and execute scripts from GitHub on first boot. Supports both `.sh` (bash) and `.ps1` (PowerShell) scripts with automatic interpreter detection. Works with both public and private repositories.

**Global Settings (`globalSettings.github`):**

```json
"github": {
    "personalAccessToken": "",
    "username": "your-username",
    "repo": "your-repo",
    "rootUrl": "https://api.github.com/repos",
    "contents": "contents",
    "query": "?ref=",
    "branch": "main",
    "mimeType": "application/vnd.github.v3.raw",
    "downloadsDirectory": "/downloads/cloud-init",
    "scripts": [
        {
            "enabled": true,
            "repoPath": "Scripts/PostDeploymentConfiguration.sh",
            "description": "Bash configuration script"
        },
        {
            "enabled": true,
            "repoPath": "Scripts/Configure.ps1",
            "description": "PowerShell script"
        }
    ]
}
```

| Field | Description |
|-------|-------------|
| `personalAccessToken` | GitHub Personal Access Token for private repos (leave empty for public repos) |
| `scripts` | Array of script objects to download and execute |

**Script Object Fields:**

| Field | Description |
|-------|-------------|
| `enabled` | Process this script (true/false) |
| `repoPath` | Path to script in GitHub repo |
| `description` | Description for logging |

**Per-Template Settings:**

Each template must explicitly enable GitHub script processing:

```json
{
  "enabled": true,
  "vmid": "9003",
  "name": "Template-With-GitHub",
  "tags": ["ubuntu", "github", "production"],
  "installPowerShell": true,
  "github": {"enabled": true}
}
```

| Field | Description |
|-------|-------------|
| `github.enabled` | Enable GitHub script processing for this template (default: false) |
| `installPowerShell` | Install PowerShell via snap on first boot (default: false) |

**Script Interpreter Selection:**

| Extension | Interpreter | Command |
|-----------|-------------|---------|
| `.sh` | Bash | `bash /path/to/script.sh` |
| `.ps1` | PowerShell | `pwsh -ExecutionPolicy Bypass -NoProfile -NoLogo -NonInteractive -File /path/to/script.ps1` |
| Other | Direct | `/path/to/script` (uses shebang) |

PowerShell is installed automatically via `snap install powershell --classic` on first boot if `installPowerShell: true` is set at the template level.

## Hardware Reference

### vmHardware.ostype

| Value | Description |
|-------|-------------|
| `l26` | Linux 2.6 - 6.x kernel (recommended for modern Linux) |
| `l24` | Linux 2.4 kernel |
| `win11` | Windows 11 / 2022 |
| `win10` | Windows 10 / 2016 / 2019 |
| `win8` | Windows 8 / 2012 |
| `win7` | Windows 7 / 2008 R2 |
| `wxp` | Windows XP / 2003 |
| `other` | Other OS |

### vmHardware.bios

| Value | Description |
|-------|-------------|
| `seabios` | SeaBIOS (legacy BIOS, default) |
| `ovmf` | OVMF/UEFI (required for secure boot, TPM 2.0) |

### vmHardware.machine

| Value | Description |
|-------|-------------|
| `q35` | Q35 chipset (recommended - PCIe, modern features) |
| `i440fx` | i440FX chipset (legacy compatibility) |

### vmHardware.scsihw

| Value | Description |
|-------|-------------|
| `virtio-scsi-single` | VirtIO SCSI single queue (recommended) |
| `virtio-scsi-pci` | VirtIO SCSI multi-queue |
| `lsi` | LSI Logic SAS |
| `lsi53c810` | LSI 53C810 |
| `megasas` | MegaRAID SAS |
| `pvscsi` | VMware Paravirtual SCSI |

### vmHardware.cpu

| Value | Description |
|-------|-------------|
| `x86-64-v3` | AVX2, BMI, FMA (modern Intel Haswell+/AMD Zen+) |
| `x86-64-v2` | SSE4.2, POPCNT (Intel Nehalem+/AMD Zen) |
| `x86-64-v4` | AVX-512 (Intel Ice Lake+) |
| `host` | Pass-through host CPU (best performance, no migration) |
| `kvm64` | Generic KVM 64-bit |
| `qemu64` | Generic QEMU 64-bit |
| `max` | Maximum available features |

## Timezone Reference

Common timezones for the `timezone` setting:

| Region | Timezone |
|--------|----------|
| US Eastern | `America/New_York` |
| US Central | `America/Chicago` |
| US Mountain | `America/Denver` |
| US Pacific | `America/Los_Angeles` |
| UK | `Europe/London` |
| Central Europe | `Europe/Berlin` |
| Japan | `Asia/Tokyo` |
| Australia Eastern | `Australia/Sydney` |
| UTC | `Etc/UTC` |

Full list: `timedatectl list-timezones`

## Cloud Image Reference

### Ubuntu Cloud Images

| Version | URL |
|---------|-----|
| Ubuntu 24.04 LTS (Noble) Current | `https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img` |
| Ubuntu 22.04 LTS (Jammy) Current | `https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img` |
| Ubuntu 20.04 LTS (Focal) Current | `https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img` |

### Debian Cloud Images

| Version | URL |
|---------|-----|
| Debian 12 (Bookworm) Generic | `https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2` |
| Debian 11 (Bullseye) Generic | `https://cloud.debian.org/images/cloud/bullseye/latest/debian-11-generic-amd64.qcow2` |

### Other Distributions

| Distribution | URL |
|--------------|-----|
| Rocky Linux 9 | `https://download.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2` |
| AlmaLinux 9 | `https://repo.almalinux.org/almalinux/9/cloud/x86_64/images/AlmaLinux-9-GenericCloud-latest.x86_64.qcow2` |
| Fedora Cloud 39 | `https://download.fedoraproject.org/pub/fedora/linux/releases/39/Cloud/x86_64/images/Fedora-Cloud-Base-39-1.5.x86_64.qcow2` |

## VM Firewall

Each template is provisioned with a comprehensive VM-level firewall configuration. The firewall state (enabled/disabled) is determined by the network adapter `firewall` setting:

- If **any** network adapter has `firewall: 1`, the VM firewall is **enabled**
- If **all** network adapters have `firewall: 0`, the VM firewall is **disabled** but rules are still created (ready to enable later)

### Firewall Options

| Option | Value | Description |
|--------|-------|-------------|
| `enable` | 0 or 1 | Firewall state (based on network adapter settings) |
| `policy_in` | DROP | Default deny inbound |
| `policy_out` | DROP | Default deny outbound |
| `log_level_in` | info | Log denied inbound traffic |

### IPSets

| IPSet | Description |
|-------|-------------|
| `rfc1918` | RFC 1918 private address space (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) |
| `rfc6598` | RFC 6598 CGNAT address space (100.64.0.0/10) |
| `public_internet` | All public routable IPv4 addresses |

### Firewall Rules

| Direction | Protocol | Port | Destination | Description |
|-----------|----------|------|-------------|-------------|
| IN/OUT | any | any | +rfc1918 | Allow RFC1918 private network traffic |
| IN/OUT | any | any | +rfc6598 | Allow RFC6598 CGNAT traffic |
| OUT | TCP | 80 | +public_internet | Allow HTTP to public internet |
| OUT | TCP | 443 | +public_internet | Allow HTTPS to public internet |
| IN/OUT | ICMP | any | any | Allow ICMP (ping) |
| IN/OUT | UDP | 67:68 | any | Allow DHCP |
| IN/OUT | TCP/UDP | 53 | any | Allow DNS |
| IN | TCP | 22 | any | Allow SSH inbound |

## Hardware Devices

Each template is provisioned with the following hardware:

| Device | Configuration | Description |
|--------|---------------|-------------|
| NUMA | Enabled | Non-Uniform Memory Access for better performance |
| TPM 2.0 | v2.0, 4MB | Trusted Platform Module for secure boot |
| VirtIO RNG | /dev/urandom, 1024 bytes/1000ms | Hardware random number generator |
| SPICE Enhancements | foldersharing=1, videostreaming=all | Folder sharing and video streaming |

## Dynamic Tags

Templates are automatically tagged with:

- `template` - Identifies as a template
- OS name (e.g., `ubuntu`, `debian`)
- Version (e.g., `v24.04`, `v12`)
- `lts` - If LTS version detected
- `cloud-init` - Cloud-init enabled

Example: `template;ubuntu;v24.04;lts;cloud-init`

## Processing Order

1. Check image cache (download if expired or missing)
2. Detect OS partition dynamically
3. Expand OS partition and filesystem
4. Create VM with hardware settings (TPM, RNG, SPICE)
5. Enable SSH root login and password authentication
6. Install global + per-template packages
7. Run `virtCustomizeCommands`
8. Configure `firstBootCommands`
9. Download and configure GitHub scripts (first boot)
10. Configure cloud-init
11. Configure VM firewall
12. Generate VM notes with credentials
13. Apply dynamic tags
14. Reset machine-id
15. Convert to template

## Example Output

```bash
$ bash Create-ProxmoxTemplate.sh

2025-12-23T01:43:27Z - INFO - Starting Proxmox template creation
2025-12-23T01:43:27Z - INFO - Storage pool: local-zfs-pool-000
2025-12-23T01:43:27Z - INFO - Found 1 enabled template(s) of 4 total
2025-12-23T01:43:27Z - INFO - Processing template 1/1: Template-Ubuntu-LTS-2404 (9001)
2025-12-23T01:43:27Z - INFO - Using cached image (less than 8 hours old)
2025-12-23T01:43:27Z - INFO - Detected OS partition: /dev/sda1
2025-12-23T01:43:28Z - INFO - Creating VM 9001...
2025-12-23T01:43:29Z - INFO - Configuring hardware devices (TPM, RNG, SPICE)
2025-12-23T01:43:30Z - INFO - Generated random password for root: *ko;nhe+PjY6
2025-12-23T01:43:31Z - INFO - Installing 19 package(s)
2025-12-23T01:43:45Z - INFO - Configuring firewall for VM 9001
2025-12-23T01:43:46Z - INFO - Firewall configured and enabled
2025-12-23T01:43:47Z - INFO - Converting VM 9001 to template
2025-12-23T01:43:48Z - INFO - Template Template-Ubuntu-LTS-2404 (9001) created successfully
```
