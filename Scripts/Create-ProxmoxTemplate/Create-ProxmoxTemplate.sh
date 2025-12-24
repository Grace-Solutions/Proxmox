#!/bin/bash
# Create-ProxmoxTemplate.sh
# Creates or updates Proxmox VM templates from cloud images
# Supports cloud-init configuration, OS disk, optional data disk, and template conversion

set -uo pipefail

SCRIPT_NAME=$(basename "$0" .sh)
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# =============================================================================
# LOGGING
# =============================================================================
LOG_FILE=""
LOG_LEVEL="INFO"

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local log_entry="$timestamp - $level - $message"

    echo "$log_entry" >&2
    [[ -n "$LOG_FILE" ]] && echo "$log_entry" >> "$LOG_FILE" || true
}

log_info()    { log "INFO" "$@"; }
log_warn()    { log "WARN" "$@"; }
log_error()   { log "ERROR" "$@"; }
log_debug()   { [[ "$LOG_LEVEL" == "DEBUG" ]] && log "DEBUG" "$@" || true; }

# =============================================================================
# ERROR HANDLING
# =============================================================================
LAST_ERROR_LINE=""
LAST_ERROR_CMD=""

# Capture error details before exit
error_trap() {
    LAST_ERROR_LINE="$1"
    LAST_ERROR_CMD="$2"
}
trap 'error_trap $LINENO "$BASH_COMMAND"' ERR

cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        if [[ -n "$LAST_ERROR_LINE" ]]; then
            log_error "Script failed at line $LAST_ERROR_LINE: $LAST_ERROR_CMD"
        fi
        log_error "Exit code: $exit_code"
    fi
    exit $exit_code
}
trap cleanup EXIT

error_exit() {
    log_error "$1"
    exit 1
}

# Enable exit on error after traps are set
set -e

# =============================================================================
# USAGE
# =============================================================================
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Creates or updates Proxmox VM templates from cloud images.

Options:
    -c, --config FILE       Configuration file path (default: ${SCRIPT_NAME}.json)
    -v, --vmid VMID         Process only this VMID (optional, processes all enabled if not specified)
    -l, --log-file FILE     Log file path (optional)
    -d, --debug             Enable debug logging
    -h, --help              Show this help message

Examples:
    $(basename "$0")
    $(basename "$0") -c custom-config.json -v 9001 -l /var/log/template.log
EOF
    exit 0
}

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================
CONFIG_FILE="${SCRIPT_DIR}/${SCRIPT_NAME}.json"
SINGLE_VMID=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--config)    CONFIG_FILE="$2"; shift 2 ;;
        -v|--vmid)      SINGLE_VMID="$2"; shift 2 ;;
        -l|--log-file)  LOG_FILE="$2"; shift 2 ;;
        -d|--debug)     LOG_LEVEL="DEBUG"; shift ;;
        -h|--help)      usage ;;
        *)              error_exit "Unknown option: $1" ;;
    esac
done

[[ ! -f "$CONFIG_FILE" ]] && error_exit "Configuration file not found: $CONFIG_FILE"

# =============================================================================
# JSON CONFIG PARSING
# =============================================================================
get_global() {
    jq -r ".globalSettings.$1 // empty" "$CONFIG_FILE"
}

get_global_array() {
    jq -r ".globalSettings.$1[]? // empty" "$CONFIG_FILE"
}

get_template_count() {
    jq '.templates | length' "$CONFIG_FILE"
}

get_template_field() {
    local index="$1"
    local field="$2"
    jq -r ".templates[$index].$field // empty" "$CONFIG_FILE"
}

# =============================================================================
# LOAD CONFIGURATION
# =============================================================================
get_template_array() {
    local index="$1"
    local field="$2"
    jq -r ".templates[$index].$field[]? // empty" "$CONFIG_FILE"
}

get_combined_packages() {
    local index="$1"
    # Combine global templatePackages + per-template packages
    jq -r '(.globalSettings.templatePackages // []) + (.templates['"$index"'].packages // []) | unique | .[]' "$CONFIG_FILE"
}

# Get network adapter field from array (supports both array and legacy single object format)
get_network_field() {
    local template_index="$1"
    local net_index="$2"
    local field="$3"
    local result

    # Check if network is an array or legacy single object
    local is_array=$(jq -r ".templates[$template_index].network | type == \"array\"" "$CONFIG_FILE")

    if [[ "$is_array" == "true" ]]; then
        result=$(jq -r ".templates[$template_index].network[$net_index].$field // empty" "$CONFIG_FILE")
    else
        # Legacy single object format (only valid for net_index 0)
        if [[ "$net_index" == "0" ]]; then
            result=$(jq -r ".templates[$template_index].network.$field // empty" "$CONFIG_FILE")
        else
            result=""
        fi
    fi
    echo "$result"
}

# Get GitHub script field from array of objects
get_github_script_field() {
    local index="$1"
    local field="$2"
    jq -r ".globalSettings.github.scripts[$index].$field // empty" "$CONFIG_FILE"
}

# Build ipconfig string for a network adapter
# Returns "ip=dhcp,ip6=dhcp" by default, or static config if IP values provided
build_ipconfig() {
    local template_index="$1"
    local net_index="$2"

    local ip=$(get_network_field "$template_index" "$net_index" "ip")
    local gateway=$(get_network_field "$template_index" "$net_index" "gateway")
    local ip6=$(get_network_field "$template_index" "$net_index" "ip6")
    local gateway6=$(get_network_field "$template_index" "$net_index" "gateway6")

    local ipconfig=""

    # IPv4 configuration
    if [[ -n "$ip" ]]; then
        # Static IPv4 (ip should be in CIDR format e.g., 192.168.1.10/24)
        ipconfig="ip=${ip}"
        [[ -n "$gateway" ]] && ipconfig+=",gw=${gateway}"
    else
        # DHCP for IPv4
        ipconfig="ip=dhcp"
    fi

    # IPv6 configuration
    if [[ -n "$ip6" ]]; then
        # Static IPv6 (ip6 should be in CIDR format e.g., 2001:db8::1/64)
        ipconfig+=",ip6=${ip6}"
        [[ -n "$gateway6" ]] && ipconfig+=",gw6=${gateway6}"
    else
        # DHCP for IPv6
        ipconfig+=",ip6=dhcp"
    fi

    echo "$ipconfig"
}

load_config() {
    log_info "Loading configuration from $CONFIG_FILE"

    # Global settings
    STORAGE_POOL=$(get_global "storagePool")
    DOWNLOAD_DIR=$(get_global "downloadDirectory")

    # GitHub settings (for building URLs and downloading scripts)
    GITHUB_TOKEN=$(get_global "github.personalAccessToken")
    GITHUB_USERNAME=$(get_global "github.username")
    GITHUB_REPO=$(get_global "github.repo")
    GITHUB_ROOT_URL=$(get_global "github.rootUrl")
    GITHUB_CONTENTS=$(get_global "github.contents")
    GITHUB_QUERY=$(get_global "github.query")
    GITHUB_BRANCH=$(get_global "github.branch")
    GITHUB_MIMETYPE=$(get_global "github.mimeType")
    GITHUB_DOWNLOADS_DIR=$(get_global "github.downloadsDirectory")
    # Get count of scripts (array of objects with enabled, repoPath, description)
    GITHUB_SCRIPTS_COUNT=$(jq -r '.globalSettings.github.scripts | if type == "array" then length else 0 end' "$CONFIG_FILE")

    # Set defaults
    [[ -z "$GITHUB_ROOT_URL" ]] && GITHUB_ROOT_URL="https://api.github.com/repos"
    [[ -z "$GITHUB_CONTENTS" ]] && GITHUB_CONTENTS="contents"
    [[ -z "$GITHUB_QUERY" ]] && GITHUB_QUERY="?ref="
    [[ -z "$GITHUB_BRANCH" ]] && GITHUB_BRANCH="main"
    [[ -z "$GITHUB_MIMETYPE" ]] && GITHUB_MIMETYPE="application/vnd.github.v3.raw"
    [[ -z "$GITHUB_DOWNLOADS_DIR" ]] && GITHUB_DOWNLOADS_DIR="/downloads/cloud-init"

    # Random password settings
    RANDOM_PASSWORD_ENABLED=$(get_global "randomPassword.enabled")
    RANDOM_PASSWORD_LENGTH=$(get_global "randomPassword.length")
    RANDOM_PASSWORD_SPECIAL_CHARS=$(get_global "randomPassword.specialChars")
    [[ -z "$RANDOM_PASSWORD_LENGTH" ]] && RANDOM_PASSWORD_LENGTH=16
    # Default to safe QWERTY-typeable special characters (no backtick, backslash, quotes that cause issues)
    [[ -z "$RANDOM_PASSWORD_SPECIAL_CHARS" ]] && RANDOM_PASSWORD_SPECIAL_CHARS='!@#$%^&*()-_=+[]{}|;:,.<>?'

    # Global tags (array of strings, semicolon-joined)
    G_TAGS=$(jq -r '.globalSettings.tags | if type == "array" and length > 0 then join(";") else "" end' "$CONFIG_FILE")

    # SMBIOS settings (uuid and serial are always randomized)
    SMBIOS_MANUFACTURER=$(get_global "smbios.manufacturer")
    SMBIOS_PRODUCT=$(get_global "smbios.product")
    SMBIOS_VERSION=$(get_global "smbios.version")
    SMBIOS_SKU=$(get_global "smbios.sku")
    SMBIOS_FAMILY=$(get_global "smbios.family")

    # Global cloud-init defaults
    G_CI_USER=$(get_global "cloudInit.user")
    G_CI_PASSWORD=$(get_global "cloudInit.password")
    G_CI_NAMESERVER=$(get_global "cloudInit.nameserver")
    G_CI_SEARCHDOMAIN=$(get_global "cloudInit.searchdomain")
    G_CI_SSHKEY=$(get_global "cloudInit.sshkey")

    # Initialize root password (will be set per-template if random passwords enabled)
    G_ROOT_PASSWORD=""
    G_RANDOM_PASSWORD_GENERATED="false"

    # Orchestrator packages (for the host running this script)
    mapfile -t ORCHESTRATOR_PACKAGES < <(get_global_array "orchestratorPackages")
}

# Load per-template settings into T_ prefixed variables
load_template_config() {
    local index="$1"

    # Store template index for use in other functions
    T_INDEX="$index"

    T_TIMEZONE=$(get_template_field "$index" "timezone")

    # VM Hardware
    T_CORES=$(get_template_field "$index" "vmHardware.cores")
    T_SOCKETS=$(get_template_field "$index" "vmHardware.sockets")
    T_MEMORY=$(get_template_field "$index" "vmHardware.memory")
    T_BALLOON=$(get_template_field "$index" "vmHardware.balloon")
    T_CPU=$(get_template_field "$index" "vmHardware.cpu")
    T_MACHINE=$(get_template_field "$index" "vmHardware.machine")
    T_BIOS=$(get_template_field "$index" "vmHardware.bios")
    T_SCSIHW=$(get_template_field "$index" "vmHardware.scsihw")
    T_OSTYPE=$(get_template_field "$index" "vmHardware.ostype")

    # Network adapters count (array of network objects)
    T_NET_COUNT=$(jq -r ".templates[$index].network | if type == \"array\" then length else 1 end" "$CONFIG_FILE")
    [[ -z "$T_NET_COUNT" || "$T_NET_COUNT" == "null" ]] && T_NET_COUNT=1

    # Check if any network adapter has firewall enabled (for VM-level firewall state)
    T_FIREWALL_ENABLED=$(jq -r ".templates[$index].network | if type == \"array\" then (if any(.[]; .firewall == 1) then \"1\" else \"0\" end) else \"1\" end" "$CONFIG_FILE")
    [[ -z "$T_FIREWALL_ENABLED" || "$T_FIREWALL_ENABLED" == "null" ]] && T_FIREWALL_ENABLED="1"

    # Cloud-init (use per-template if set, otherwise fall back to global)
    local ci_user=$(get_template_field "$index" "cloudInit.user")
    local ci_password=$(get_template_field "$index" "cloudInit.password")
    local ci_nameserver=$(get_template_field "$index" "cloudInit.nameserver")
    local ci_searchdomain=$(get_template_field "$index" "cloudInit.searchdomain")
    local ci_sshkey=$(get_template_field "$index" "cloudInit.sshkey")

    T_CI_USER="${ci_user:-$G_CI_USER}"
    T_CI_PASSWORD="${ci_password:-$G_CI_PASSWORD}"
    T_CI_NAMESERVER="${ci_nameserver:-$G_CI_NAMESERVER}"
    T_CI_SEARCHDOMAIN="${ci_searchdomain:-$G_CI_SEARCHDOMAIN}"
    T_CI_SSHKEY="${ci_sshkey:-$G_CI_SSHKEY}"

    # Generate random passwords if enabled
    T_ROOT_PASSWORD=""
    T_RANDOM_PASSWORD_GENERATED="false"
    if [[ "$RANDOM_PASSWORD_ENABLED" == "true" ]]; then
        T_RANDOM_PASSWORD_GENERATED="true"
        # Generate password using only QWERTY-typeable characters from config
        # Character pool: lowercase, uppercase, digits, and configured special chars
        local char_pool="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789${RANDOM_PASSWORD_SPECIAL_CHARS}"

        generate_random_password() {
            local length="$1"
            local pool="$2"
            local password=""
            local pw_i
            for ((pw_i=0; pw_i<length; pw_i++)); do
                local rand_index=$((RANDOM % ${#pool}))
                password+="${pool:$rand_index:1}"
            done
            echo "$password"
        }

        T_CI_GENERATED_PASSWORD=$(generate_random_password "$RANDOM_PASSWORD_LENGTH" "$char_pool")

        # If cloud-init user is root, use same password for both
        if [[ "$T_CI_USER" == "root" ]]; then
            T_ROOT_PASSWORD="$T_CI_GENERATED_PASSWORD"
            log_info "Generated random password for root (cloud-init user is root)"
        else
            # Generate separate password for root
            T_ROOT_PASSWORD=$(generate_random_password "$RANDOM_PASSWORD_LENGTH" "$char_pool")
            log_info "Generated separate random passwords for ${T_CI_USER} and root"
        fi

        # Only use generated password if no password was specified in config
        if [[ -z "$T_CI_PASSWORD" ]]; then
            T_CI_PASSWORD="$T_CI_GENERATED_PASSWORD"
        fi
    else
        # If random password not enabled, root gets same password as cloud-init user
        T_ROOT_PASSWORD="$T_CI_PASSWORD"
    fi

    # Packages (global templatePackages + per-template packages)
    mapfile -t T_PACKAGES < <(get_combined_packages "$index")

    # Custom commands
    mapfile -t T_CUSTOMIZE_CMDS < <(get_template_array "$index" "virtCustomizeCommands")
    mapfile -t T_FIRSTBOOT_CMDS < <(get_template_array "$index" "firstBootCommands")

    # GitHub processing enabled for this template (defaults to false)
    T_GITHUB_ENABLED=$(get_template_field "$index" "github.enabled")
    [[ -z "$T_GITHUB_ENABLED" ]] && T_GITHUB_ENABLED="false"

    # PowerShell installation per-template (defaults to false)
    T_INSTALL_POWERSHELL=$(get_template_field "$index" "installPowerShell")
    [[ -z "$T_INSTALL_POWERSHELL" ]] && T_INSTALL_POWERSHELL="false"

    # Per-template tags (array of strings, semicolon-joined)
    T_TAGS=$(jq -r ".templates[$index].tags | if type == \"array\" and length > 0 then join(\";\") else \"\" end" "$CONFIG_FILE")
}

# =============================================================================
# STORAGE DETECTION
# =============================================================================
detect_storage() {
    log_info "Auto-detecting storage pool"

    # Get current node name
    local node=$(hostname)

    # Use pvesh to get storage info in JSON format
    # Filter for: active=1, enabled=1, content contains "images", type is zfspool/lvmthin/lvm/btrfs/dir
    local storage=$(pvesh get "/nodes/${node}/storage" --output-format json 2>/dev/null | jq -r '
        [.[] | select(
            .active == 1 and
            .enabled == 1 and
            (.content | test("images")) and
            (.type | test("^(zfspool|lvmthin|lvm|btrfs|dir)$"))
        )] |
        # Prefer ZFS/LVM/BTRFS over dir, then sort by available space
        sort_by(if .type == "dir" then 1 else 0 end, -(.avail // 0)) |
        first |
        .storage // empty
    ')

    if [[ -n "$storage" ]]; then
        log_info "Detected storage pool: $storage"
        echo "$storage"
        return 0
    fi

    error_exit "No suitable storage found (requires: active, enabled, supports disk images, type: zfspool/lvmthin/lvm/btrfs/dir)"
}

# =============================================================================
# VALIDATION
# =============================================================================
validate_config() {
    # Auto-detect storage if not specified or set to "auto"/"automatic"
    if [[ -z "$STORAGE_POOL" || "$STORAGE_POOL" == "auto" || "$STORAGE_POOL" == "automatic" ]]; then
        STORAGE_POOL=$(detect_storage)
    fi

    [[ -z "$STORAGE_POOL" ]] && error_exit "No storage pool available"
    [[ $(get_template_count) -eq 0 ]] && error_exit "No templates defined in configuration"

    # Validate required tools
    for cmd in jq qm curl qemu-img virt-customize pvesm virt-edit; do
        command -v "$cmd" &>/dev/null || error_exit "Required command not found: $cmd"
    done

    log_info "Using storage pool: $STORAGE_POOL"
    log_info "Configuration validated successfully"
}

# =============================================================================
# FUNCTIONS
# =============================================================================

download_image() {
    local url="$1"
    local filename=$(basename "$url")
    local cache_dir="${DOWNLOAD_DIR}/cache"
    local cache_max_age_hours=8

    # Create cache directory
    mkdir -p "$cache_dir"

    local cached_file="${cache_dir}/${filename}"
    local needs_download="true"

    # Check if cached copy exists and is fresh (less than 8 hours old)
    if [[ -f "$cached_file" ]]; then
        local file_age_seconds=$(($(date +%s) - $(stat -c %Y "$cached_file" 2>/dev/null || stat -f %m "$cached_file" 2>/dev/null)))
        local max_age_seconds=$((cache_max_age_hours * 3600))

        if [[ $file_age_seconds -lt $max_age_seconds ]]; then
            local hours_old=$((file_age_seconds / 3600))
            log_info "Using cached image: $filename (${hours_old}h old, max ${cache_max_age_hours}h)"
            cp "$cached_file" "./${filename}"
            needs_download="false"
        else
            local hours_old=$((file_age_seconds / 3600))
            log_info "Cached image expired: $filename (${hours_old}h old > ${cache_max_age_hours}h max)"
        fi
    fi

    if [[ "$needs_download" == "true" ]]; then
        log_info "Downloading cloud image: $filename"
        if ! curl -L -O -k --progress-bar "$url"; then
            error_exit "Failed to download image from $url"
        fi
        # Cache the downloaded image
        cp "./${filename}" "$cached_file"
        log_info "Cached image to $cached_file"
    fi
    echo "$filename"
}

# Expand the OS partition in the image
expand_os_partition() {
    local image_file="$1"

    log_info "Detecting and expanding OS partition"

    # Use virt-filesystems to detect the OS partition
    local os_partition=$(virt-filesystems -a "$image_file" --filesystems -l 2>/dev/null | \
        awk '/ext[234]|xfs|btrfs/ {print $1; exit}')

    if [[ -z "$os_partition" ]]; then
        log_warn "Could not detect OS partition, skipping partition expansion"
        return 0
    fi

    log_info "Detected OS partition: $os_partition"

    # Extract disk and partition number (e.g., /dev/sda1 -> /dev/sda and 1)
    local disk=$(echo "$os_partition" | sed 's/[0-9]*$//')
    local part_num=$(echo "$os_partition" | grep -oE '[0-9]+$')

    if [[ -n "$disk" && -n "$part_num" ]]; then
        log_info "Expanding partition ${part_num} on ${disk}"
        virt-customize -a "$image_file" --run-command "growpart ${disk} ${part_num}" 2>/dev/null || log_warn "growpart failed (may already be expanded)"

        # Detect filesystem type and resize accordingly
        # virt-filesystems output: Name Type VFS Label Size Parent
        # We need column 3 (VFS) which is the actual filesystem type
        local fs_type=$(virt-filesystems -a "$image_file" --filesystems -l 2>/dev/null | \
            awk -v part="$os_partition" '$1 == part {print $3}')

        case "$fs_type" in
            ext2|ext3|ext4)
                log_info "Resizing ext filesystem on $os_partition"
                virt-customize -a "$image_file" --run-command "resize2fs ${os_partition}" 2>/dev/null || true
                ;;
            xfs)
                log_info "Resizing XFS filesystem on $os_partition"
                virt-customize -a "$image_file" --run-command "xfs_growfs ${os_partition}" 2>/dev/null || true
                ;;
            btrfs)
                log_info "Resizing Btrfs filesystem on $os_partition"
                virt-customize -a "$image_file" --run-command "btrfs filesystem resize max ${os_partition}" 2>/dev/null || true
                ;;
            *)
                log_warn "Unknown filesystem type: $fs_type, skipping resize"
                ;;
        esac
    else
        log_warn "Could not parse disk/partition from: $os_partition"
    fi
}

convert_to_qcow2() {
    local input_file="$1"
    local base_name="${input_file%.*}"
    local output_file="${base_name}.qcow2"

    # Detect input format
    local input_format=$(qemu-img info "$input_file" | grep -oP 'file format: \K\w+')
    log_info "Detected image format: $input_format"

    if [[ "$input_format" == "qcow2" ]]; then
        # Already qcow2, just rename if needed
        if [[ "$input_file" != "$output_file" ]]; then
            log_info "Renaming $input_file to $output_file"
            mv "$input_file" "$output_file"
        fi
    else
        # Convert to qcow2
        log_info "Converting $input_file from $input_format to qcow2 format"
        qemu-img convert -f "$input_format" -O qcow2 "$input_file" "$output_file"
        rm -f "$input_file"
    fi
    echo "$output_file"
}

resize_image() {
    local image_file="$1"
    local new_size="$2"

    log_info "Resizing image to $new_size"
    qemu-img resize "$image_file" "$new_size"
}

customize_image() {
    local image_file="$1"

    log_info "Customizing image"

    # Enable root login and unlock passwords in cloud-init
    virt-edit -a "$image_file" "/etc/cloud/cloud.cfg" -e 's/disable_root: true/disable_root: false/' 2>/dev/null || true
    virt-edit -a "$image_file" "/etc/cloud/cloud.cfg" -e 's/lock_passwd: [Tt]rue/lock_passwd: false/' 2>/dev/null || true

    # Always enable SSH root login with password
    log_debug "Enabling SSH root login"
    virt-customize -a "$image_file" --run-command "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config" 2>/dev/null || true
    virt-customize -a "$image_file" --run-command "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config" 2>/dev/null || true

    # Set timezone
    log_debug "Setting timezone to $T_TIMEZONE"
    virt-customize -a "$image_file" --timezone "$T_TIMEZONE"

    # Update packages first
    log_info "Updating packages in image"
    virt-customize -a "$image_file" --update

    # Install packages on first boot (when network is available)
    if [[ ${#T_PACKAGES[@]} -gt 0 ]]; then
        local pkg_list=$(IFS=,; echo "${T_PACKAGES[*]}")
        log_info "Adding ${#T_PACKAGES[@]} package(s) for first-boot install: ${T_PACKAGES[*]}"
        virt-customize -a "$image_file" --firstboot-install "$pkg_list"
    fi

    # Configure user account if specified
    if [[ -n "$T_CI_USER" && -n "$T_CI_PASSWORD" ]]; then
        log_info "Configuring user account: $T_CI_USER"
        virt-customize -a "$image_file" --run-command "mkdir -p /home/${T_CI_USER}"
        virt-customize -a "$image_file" --run-command "adduser --uid 2500 --system --home /home/${T_CI_USER} --shell /bin/bash --ingroup root --gecos '' --quiet --disabled-password ${T_CI_USER}" 2>/dev/null || true
        virt-customize -a "$image_file" --run-command "usermod -aG sudo,root ${T_CI_USER}" 2>/dev/null || true
        # Use printf and escape single quotes in passwords for chpasswd
        local escaped_ci_pwd="${T_CI_PASSWORD//\'/\'\\\'\'}"
        local escaped_root_pwd="${T_ROOT_PASSWORD//\'/\'\\\'\'}"
        virt-customize -a "$image_file" --run-command "printf '%s:%s\n' '${T_CI_USER}' '${escaped_ci_pwd}' | chpasswd"
        # Set root password (may be different if random passwords enabled)
        virt-customize -a "$image_file" --run-command "printf '%s:%s\n' 'root' '${escaped_root_pwd}' | chpasswd"
    fi

    # Run custom commands
    if [[ ${#T_CUSTOMIZE_CMDS[@]} -gt 0 ]]; then
        log_info "Running ${#T_CUSTOMIZE_CMDS[@]} customize command(s)"
        for cmd in "${T_CUSTOMIZE_CMDS[@]}"; do
            log_debug "Running: $cmd"
            virt-customize -a "$image_file" --run-command "$cmd" || log_warn "Command failed: $cmd"
        done
    fi

    # Install QEMU guest agent as the very first firstboot command (ensures it's available for Proxmox)
    log_info "Adding QEMU guest agent installation as first boot command"
    virt-customize -a "$image_file" --firstboot-command "apt-get update && apt-get install -y qemu-guest-agent && systemctl enable --now qemu-guest-agent"

    # Install PowerShell if enabled for this template (after qemu-guest-agent, before other first boot commands)
    if [[ "$T_INSTALL_POWERSHELL" == "true" ]]; then
        log_info "Adding PowerShell installation as first boot command"
        virt-customize -a "$image_file" --firstboot-command "snap install powershell --classic"
    fi

    # Configure iptables firewall rules (before custom first boot commands)
    # Rules: Loopback, Established, RFC1918/6598 east-west, Internet outbound, ICMP, Drop other inbound
    # Note: iptables-persistent should be in globalSettings.templatePackages for persistence
    log_info "Adding iptables firewall configuration as first boot commands"

    # Flush existing rules and set chain policies
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -F && iptables -X && iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -P OUTPUT DROP"

    # Allow loopback interface (INPUT and OUTPUT)
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -A INPUT -i lo -j ACCEPT && iptables -A OUTPUT -o lo -j ACCEPT"

    # Allow established and related connections (INPUT and OUTPUT)
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT && iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"

    # Allow all RFC1918 inbound and outbound (east-west private network traffic)
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT && iptables -A INPUT -s 172.16.0.0/12 -j ACCEPT && iptables -A INPUT -s 192.168.0.0/16 -j ACCEPT"
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT && iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT && iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT"

    # Allow all RFC6598 CGNAT inbound and outbound (east-west CGNAT traffic)
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -A INPUT -s 100.64.0.0/10 -j ACCEPT && iptables -A OUTPUT -d 100.64.0.0/10 -j ACCEPT"

    # Allow ICMP (ping) inbound and outbound
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -A INPUT -p icmp -j ACCEPT && iptables -A OUTPUT -p icmp -j ACCEPT"

    # Allow all outbound to internet (public routable addresses - everything not RFC1918/6598)
    # This covers HTTP, HTTPS, DNS, NTP, and all other internet-bound traffic
    virt-customize -a "$image_file" --firstboot-command \
        "iptables -A OUTPUT -j ACCEPT"

    # Save iptables rules for persistence across reboots
    virt-customize -a "$image_file" --firstboot-command \
        "iptables-save > /etc/iptables/rules.v4"

    # Add per-template first boot commands
    if [[ ${#T_FIRSTBOOT_CMDS[@]} -gt 0 ]]; then
        log_info "Adding ${#T_FIRSTBOOT_CMDS[@]} per-template first boot command(s)"
        for cmd in "${T_FIRSTBOOT_CMDS[@]}"; do
            log_debug "First boot command: $cmd"
            virt-customize -a "$image_file" --firstboot-command "$cmd"
        done
    fi

    # Add GitHub scripts as first boot commands (after per-template commands)
    # Only process if github.enabled is true for this template
    local enabled_scripts=0
    if [[ "$T_GITHUB_ENABLED" == "true" ]]; then
        for ((s_idx=0; s_idx<GITHUB_SCRIPTS_COUNT; s_idx++)); do
            local s_enabled=$(get_github_script_field "$s_idx" "enabled")
            [[ "$s_enabled" == "true" ]] && ((enabled_scripts++)) || true
        done
    fi

    if [[ "$T_GITHUB_ENABLED" == "true" && $enabled_scripts -gt 0 && -n "$GITHUB_USERNAME" && -n "$GITHUB_REPO" ]]; then
        log_info "Adding $enabled_scripts enabled GitHub script(s) as first boot commands"

        # Create downloads directory
        virt-customize -a "$image_file" --run-command "mkdir -p '${GITHUB_DOWNLOADS_DIR}'"

        for ((s_idx=0; s_idx<GITHUB_SCRIPTS_COUNT; s_idx++)); do
            local s_enabled=$(get_github_script_field "$s_idx" "enabled")
            [[ "$s_enabled" != "true" ]] && continue

            local repopath=$(get_github_script_field "$s_idx" "repoPath")
            local s_description=$(get_github_script_field "$s_idx" "description")
            local s_params=$(get_github_script_field "$s_idx" "params")

            local filename=$(basename "$repopath")
            local script_url="${GITHUB_ROOT_URL}/${GITHUB_USERNAME}/${GITHUB_REPO}/${GITHUB_CONTENTS}/${repopath}${GITHUB_QUERY}${GITHUB_BRANCH}"
            local script_path="${GITHUB_DOWNLOADS_DIR}/${filename}"
            local log_path="${GITHUB_DOWNLOADS_DIR}/${filename}.log"

            log_debug "GitHub script: $filename"
            [[ -n "$s_description" ]] && log_debug "Description: $s_description"
            [[ -n "$s_params" ]] && log_debug "Parameters: $s_params"
            log_debug "URL: $script_url"

            # Determine interpreter based on file extension
            local interpreter=""
            case "$filename" in
                *.ps1) interpreter="pwsh -ExecutionPolicy Bypass -NoProfile -NoLogo -NonInteractive -File" ;;
                *.sh)  interpreter="bash" ;;
                *)     interpreter="" ;;  # Execute directly (relies on shebang)
            esac

            # Build curl command - base options (silent, follow redirects, fail on error)
            local curl_opts="-sfL"

            # Build auth header (only for private repos with PAT)
            local curl_headers="-H 'Accept: ${GITHUB_MIMETYPE}'"
            if [[ -n "$GITHUB_TOKEN" ]]; then
                curl_headers="${curl_headers} -H 'Authorization: Bearer ${GITHUB_TOKEN}'"
            fi

            # Build execution command based on interpreter (append params if provided)
            local exec_cmd
            if [[ -n "$interpreter" ]]; then
                exec_cmd="${interpreter} '${script_path}'"
            else
                exec_cmd="'${script_path}'"
            fi
            [[ -n "$s_params" ]] && exec_cmd="${exec_cmd} ${s_params}"

            # Download the script, make executable, and execute with appropriate interpreter
            virt-customize -a "$image_file" --firstboot-command \
                "curl ${curl_opts} ${curl_headers} '${script_url}' -o '${script_path}' && chmod +x '${script_path}' && ${exec_cmd} 2>&1 | tee '${log_path}'"
        done
    fi

    # Perform final reboot after all GitHub scripts
    log_debug "Adding final reboot command"
    virt-customize -a "$image_file" --firstboot-command "shutdown -r now"

    ###THE FOLLOWING STEPS MUST BE THE FINAL STEPS!###
    # Reset the machine ID. This ensures that the network configuration gets reset because
    # the DHCP unique identifier has been changed. If these steps are skipped, this will
    # cause your cloned machines to get the same IP address.
    log_debug "Resetting machine-id (FINAL STEP)"
    virt-customize -a "$image_file" --run-command 'truncate --size 0 /etc/machine-id'
    virt-customize -a "$image_file" --run-command 'truncate --size 0 /var/lib/dbus/machine-id' 2>/dev/null || true
    virt-customize -a "$image_file" --run-command 'rm -f -v /var/lib/dbus/machine-id' 2>/dev/null || true
    virt-customize -a "$image_file" --run-command 'ln -s /etc/machine-id /var/lib/dbus/machine-id'
    virt-customize -a "$image_file" --truncate '/etc/machine-id'
    ###THE FOLLOWING STEPS MUST BE THE FINAL STEPS!###
}

vm_exists() {
    local vmid="$1"
    qm status "$vmid" &>/dev/null
}

is_template() {
    local vmid="$1"
    qm config "$vmid" 2>/dev/null | grep -q "^template: 1"
}

stop_vm() {
    local vmid="$1"
    local status=$(qm status "$vmid" 2>/dev/null | grep -oP 'status: \K\w+' || echo "unknown")

    if [[ "$status" == "running" ]]; then
        log_info "Stopping VM $vmid"
        qm stop "$vmid" --timeout 60
        sleep 3
    fi
}

create_vm() {
    local vmid="$1"
    local name="$2"

    log_info "Creating VM $vmid: $name"

    qm create "$vmid" \
        --name "$name" \
        --cores "$T_CORES" \
        --sockets "$T_SOCKETS" \
        --memory "$T_MEMORY" \
        --balloon "$T_BALLOON" \
        --cpu "$T_CPU" \
        --machine "$T_MACHINE" \
        --bios "$T_BIOS" \
        --scsihw "$T_SCSIHW" \
        --ostype "$T_OSTYPE" \
        --numa 1 \
        --agent 1,fstrim_cloned_disks=1 \
        --onboot 1 \
        --hotplug disk,network,usb,memory,cpu

    # Add network interfaces (loop through network array)
    log_debug "Configuring $T_NET_COUNT network adapter(s)"
    for ((net_i=0; net_i<T_NET_COUNT; net_i++)); do
        local bridge=$(get_network_field "$T_INDEX" "$net_i" "bridge")
        local firewall=$(get_network_field "$T_INDEX" "$net_i" "firewall")
        local vlan=$(get_network_field "$T_INDEX" "$net_i" "vlan")

        # Defaults (firewall=0 by default, iptables rules handle security at VM level)
        [[ -z "$bridge" ]] && bridge="vmbr0"
        [[ -z "$firewall" ]] && firewall="0"

        local net_opts="virtio,bridge=${bridge},firewall=${firewall}"
        [[ -n "$vlan" ]] && net_opts+=",tag=${vlan}"

        log_debug "Adding net${net_i}: $net_opts"
        qm set "$vmid" --"net${net_i}" "$net_opts"
    done

    # Add EFI disk for UEFI boot
    log_debug "Adding EFI disk"
    qm set "$vmid" --efidisk0 "$STORAGE_POOL:1,efitype=4m,pre-enrolled-keys=1"

    # Configure hardware devices (TPM, RNG, SPICE)
    configure_hardware_devices "$vmid"

    # Configure SMBIOS (randomize or use specified values)
    configure_smbios "$vmid"
}

# Configure SMBIOS settings for VM (uuid and serial always randomized)
configure_smbios() {
    local vmid="$1"

    # Always generate random uuid and serial
    local uuid=$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid)
    local serial=$(openssl rand -hex 8 | tr '[:lower:]' '[:upper:]')

    log_debug "Generated UUID: $uuid"
    log_debug "Generated Serial: $serial"

    # Build SMBIOS options with random uuid/serial and configured values
    local smbios_opts="uuid=${uuid},serial=${serial}"

    # Sanitize SMBIOS value - Proxmox only allows alphanumeric, underscore, dash
    # Spaces are removed, other special chars removed
    sanitize_smbios_value() {
        local val="$1"
        # Remove spaces and keep only alphanumeric, underscore, dash
        echo "$val" | tr -d ' ' | tr -cd '[:alnum:]_-'
    }

    # Version field is stricter - remove dots too, only allow alphanumeric
    sanitize_smbios_version() {
        local val="$1"
        # Remove dots and spaces, keep only alphanumeric
        echo "$val" | tr -d ' .' | tr -cd '[:alnum:]'
    }

    [[ -n "$SMBIOS_MANUFACTURER" ]] && smbios_opts+=",manufacturer=$(sanitize_smbios_value "$SMBIOS_MANUFACTURER")"
    [[ -n "$SMBIOS_PRODUCT" ]] && smbios_opts+=",product=$(sanitize_smbios_value "$SMBIOS_PRODUCT")"
    [[ -n "$SMBIOS_VERSION" ]] && smbios_opts+=",version=$(sanitize_smbios_version "$SMBIOS_VERSION")"
    [[ -n "$SMBIOS_SKU" ]] && smbios_opts+=",sku=$(sanitize_smbios_value "$SMBIOS_SKU")"
    [[ -n "$SMBIOS_FAMILY" ]] && smbios_opts+=",family=$(sanitize_smbios_value "$SMBIOS_FAMILY")"

    log_debug "Setting SMBIOS: $smbios_opts"
    qm set "$vmid" --smbios1 "$smbios_opts"
}

# Configure hardware devices (TPM, RNG, SPICE enhancements) - idempotent
configure_hardware_devices() {
    local vmid="$1"

    log_info "Configuring hardware devices for VM $vmid"

    local vm_config=$(qm config "$vmid" 2>/dev/null)

    # Add TPM 2.0 if not present
    if ! echo "$vm_config" | grep -q "^tpmstate0:"; then
        log_debug "Adding TPM 2.0"
        qm set "$vmid" --tpmstate0 "$STORAGE_POOL:1,version=v2.0"
    fi

    # Add VirtIO RNG if not present
    if ! echo "$vm_config" | grep -q "^rng0:"; then
        log_debug "Adding VirtIO RNG"
        qm set "$vmid" --rng0 "source=/dev/urandom,max_bytes=1024,period=1000"
    fi

    # Configure SPICE enhancements (folder sharing, video streaming) - NOT SPICE hardware
    if ! echo "$vm_config" | grep -q "^spice_enhancements:"; then
        log_debug "Enabling SPICE enhancements"
        qm set "$vmid" --spice_enhancements "foldersharing=1,videostreaming=all"
    fi

    # Remove SPICE hardware if present (we only want enhancements, not SPICE display/audio/usb)
    if echo "$vm_config" | grep -q "^vga:.*qxl"; then
        log_debug "Removing SPICE VGA (qxl) - reverting to default"
        qm set "$vmid" --vga std
    fi
    if echo "$vm_config" | grep -q "^audio0:.*spice"; then
        log_debug "Removing SPICE audio device"
        qm set "$vmid" --delete audio0
    fi
    if echo "$vm_config" | grep -q "^usb0:.*spice"; then
        log_debug "Removing SPICE USB redirection"
        qm set "$vmid" --delete usb0
    fi
}

prepare_existing_vm() {
    local vmid="$1"

    log_info "Preparing existing VM $vmid for update"

    # Convert from template if necessary
    if is_template "$vmid"; then
        log_info "Converting VM $vmid from template"
        qm set "$vmid" --template 0
    fi

    # Stop if running
    stop_vm "$vmid"

    local vm_config=$(qm config "$vmid" 2>/dev/null)

    # Remove existing disks (scsi1=OS, scsi2=data)
    log_debug "Removing existing OS disk (scsi1)"
    qm set "$vmid" --delete scsi1 2>/dev/null || true

    if echo "$vm_config" | grep -q "^scsi2:"; then
        log_debug "Removing existing data disk (scsi2)"
        qm set "$vmid" --delete scsi2 2>/dev/null || true
    fi

    # Clean up any orphaned/unused disks from previous runs
    local unused_disks=$(echo "$vm_config" | grep "^unused" | cut -d: -f1)
    if [[ -n "$unused_disks" ]]; then
        log_info "Cleaning up orphaned disks"
        for disk in $unused_disks; do
            log_debug "Removing $disk"
            qm set "$vmid" --delete "$disk" 2>/dev/null || true
        done
    fi
}

import_os_disk() {
    local vmid="$1"
    local image_file="$2"
    local disk_size="$3"

    log_info "Importing OS disk for VM $vmid"

    # Import disk - this creates an "unused" disk
    qm importdisk "$vmid" "$image_file" "$STORAGE_POOL"

    # Find the newly created unused disk and attach it
    local vm_config=$(qm config "$vmid" 2>/dev/null)
    local unused_disk=$(echo "$vm_config" | grep "^unused" | tail -1 | sed 's/.*: //')

    if [[ -n "$unused_disk" ]]; then
        # Attach as scsi1 with SSD options
        qm set "$vmid" --scsi1 "${unused_disk},discard=on,iothread=1,ssd=1"
    else
        # Fallback to disk-1 naming
        qm set "$vmid" --scsi1 "$STORAGE_POOL:vm-${vmid}-disk-1,discard=on,iothread=1,ssd=1"
    fi

    # Resize to target size
    log_info "Resizing OS disk to $disk_size"
    qm resize "$vmid" scsi1 "$disk_size"

    # Clean up any remaining unused disks from import
    cleanup_unused_disks "$vmid"
}

# Clean up any orphaned/unused disks
cleanup_unused_disks() {
    local vmid="$1"
    local vm_config=$(qm config "$vmid" 2>/dev/null)
    local unused_disks=$(echo "$vm_config" | grep "^unused" | cut -d: -f1)

    if [[ -n "$unused_disks" ]]; then
        log_debug "Cleaning up orphaned disks"
        for disk in $unused_disks; do
            qm set "$vmid" --delete "$disk" 2>/dev/null || true
        done
    fi
}

create_data_disk() {
    local vmid="$1"
    local disk_size="$2"

    log_info "Creating data disk ($disk_size) for VM $vmid"
    # Convert size like "128G" to just the number for ZFS allocation
    local size_num=$(echo "$disk_size" | grep -oE '^[0-9]+')
    qm set "$vmid" --scsi2 "$STORAGE_POOL:${size_num},discard=on,iothread=1,ssd=1"
}

configure_cloudinit() {
    local vmid="$1"
    local is_new="$2"

    log_info "Configuring cloud-init for VM $vmid"

    # Check if cloud-init drive exists, if not add it
    if ! qm config "$vmid" 2>/dev/null | grep -q "scsi0:.*cloudinit"; then
        log_info "Adding cloud-init drive"
        qm set "$vmid" --scsi0 "$STORAGE_POOL:cloudinit,media=cdrom"
    fi

    # Set cloud-init options individually to handle special characters in passwords
    qm set "$vmid" --ciuser "$T_CI_USER"
    [[ -n "$T_CI_PASSWORD" ]] && qm set "$vmid" --cipassword "$T_CI_PASSWORD"
    [[ -n "$T_CI_NAMESERVER" ]] && qm set "$vmid" --nameserver "$T_CI_NAMESERVER"
    [[ -n "$T_CI_SEARCHDOMAIN" ]] && qm set "$vmid" --searchdomain "$T_CI_SEARCHDOMAIN"

    # Configure ipconfig for each network adapter (ipconfig0, ipconfig1, etc.)
    log_debug "Configuring ipconfig for $T_NET_COUNT network adapter(s)"
    for ((ip_i=0; ip_i<T_NET_COUNT; ip_i++)); do
        local ipconfig=$(build_ipconfig "$T_INDEX" "$ip_i")
        log_debug "Setting ipconfig${ip_i}: $ipconfig"
        qm set "$vmid" --"ipconfig${ip_i}" "$ipconfig"
    done

    # SSH key requires special handling
    if [[ -n "$T_CI_SSHKEY" ]]; then
        echo "$T_CI_SSHKEY" > "/tmp/sshkey_${vmid}.pub"
        qm set "$vmid" --sshkeys "/tmp/sshkey_${vmid}.pub"
        rm -f "/tmp/sshkey_${vmid}.pub"
    fi

    # Set boot order (semicolon-separated in Proxmox)
    qm set "$vmid" --boot "order=scsi1;scsi0;net0"
}

# Configure cluster-level firewall IPSets and Aliases (idempotent - shared across all VMs)
# This creates reusable network definitions at the datacenter/cluster level
configure_cluster_firewall() {
    log_info "Configuring cluster-level firewall IPSets and Aliases (idempotent)"

    local fw_dir="/etc/pve/firewall"
    local cluster_fw="${fw_dir}/cluster.fw"

    # Ensure firewall directory exists
    mkdir -p "$fw_dir"

    # Check if cluster.fw exists and has our marker
    if [[ -f "$cluster_fw" ]] && grep -q "# Managed by Proxmox Template Creator" "$cluster_fw"; then
        log_debug "Cluster firewall already configured (skipping)"
        return 0
    fi

    # Backup existing cluster.fw if it exists and doesn't have our marker
    if [[ -f "$cluster_fw" ]]; then
        log_warn "Backing up existing cluster.fw to cluster.fw.bak"
        cp "$cluster_fw" "${cluster_fw}.bak"
    fi

    # -------------------------------------------------------------------------
    # Create cluster-level firewall config with IPSets and Aliases
    # These are shared across all VMs and can be referenced in VM-level rules
    # -------------------------------------------------------------------------

    cat > "$cluster_fw" << 'CLUSTERFW'
# Managed by Proxmox Template Creator
# Cluster-level firewall configuration with reusable IPSets and Aliases
# These definitions are shared across all VMs in the cluster

[OPTIONS]
enable: 0

[ALIASES]
# RFC 1918 Private Address Space Aliases
rfc1918_class_a 10.0.0.0/8 # RFC1918 Class A Private Network (10.0.0.0 - 10.255.255.255)
rfc1918_class_b 172.16.0.0/12 # RFC1918 Class B Private Network (172.16.0.0 - 172.31.255.255)
rfc1918_class_c 192.168.0.0/16 # RFC1918 Class C Private Network (192.168.0.0 - 192.168.255.255)
# RFC 6598 CGNAT Address Space Alias
rfc6598_cgnat 100.64.0.0/10 # RFC6598 Carrier-Grade NAT (100.64.0.0 - 100.127.255.255)

[IPSET rfc1918] # RFC 1918 Private Address Space - All private IPv4 ranges
10.0.0.0/8 # Class A Private (10.0.0.0 - 10.255.255.255)
172.16.0.0/12 # Class B Private (172.16.0.0 - 172.31.255.255)
192.168.0.0/16 # Class C Private (192.168.0.0 - 192.168.255.255)

[IPSET rfc6598] # RFC 6598 CGNAT Address Space - Carrier-Grade NAT
100.64.0.0/10 # CGNAT Range (100.64.0.0 - 100.127.255.255)
CLUSTERFW

    log_info "Cluster-level firewall IPSets and Aliases configured"
}

# Generate markdown notes for the VM
generate_vm_notes() {
    local vmid="$1"
    local template_name="$2"
    local image_url="$3"

    log_info "Generating VM notes for $vmid"

    # Write notes to temp file to avoid shell escaping issues
    local notes_file="/tmp/vm_notes_${vmid}.md"

    cat > "$notes_file" << EOF
# ${template_name}

## Template Information

| Property | Value |
|----------|-------|
| VMID | ${vmid} |
| Created | $(date -u '+%Y-%m-%d %H:%M:%S UTC') |
| Storage Pool | ${STORAGE_POOL} |
| Timezone | ${T_TIMEZONE} |
EOF

    # Credentials - Only show randomly generated passwords (not static from config)
    if [[ "$T_RANDOM_PASSWORD_GENERATED" == "true" && -n "$T_ROOT_PASSWORD" ]]; then
        cat >> "$notes_file" << EOF

## Credentials (Randomly Generated)

| Account | Password |
|---------|----------|
| root | ${T_ROOT_PASSWORD} |
EOF
    fi

    # Packages (installed on first boot) - One per line
    if [[ ${#T_PACKAGES[@]} -gt 0 ]]; then
        echo "" >> "$notes_file"
        echo "## Packages (First Boot)" >> "$notes_file"
        echo "" >> "$notes_file"
        echo "*The following packages are installed automatically on first boot:*" >> "$notes_file"
        echo "" >> "$notes_file"
        for pkg in "${T_PACKAGES[@]}"; do
            echo "- ${pkg}" >> "$notes_file"
        done
    fi

    # GitHub Scripts - List enabled scripts (only if github.enabled for this template)
    local has_enabled_scripts=false
    if [[ "$T_GITHUB_ENABLED" == "true" ]]; then
        for ((s_idx=0; s_idx<GITHUB_SCRIPTS_COUNT; s_idx++)); do
            local s_enabled=$(get_github_script_field "$s_idx" "enabled")
            if [[ "$s_enabled" == "true" ]]; then
                has_enabled_scripts=true
                break
            fi
        done
    fi

    if [[ "$T_GITHUB_ENABLED" == "true" && "$has_enabled_scripts" == "true" ]]; then
        echo "" >> "$notes_file"
        echo "## GitHub Scripts" >> "$notes_file"
        echo "" >> "$notes_file"
        echo "| Repo Path | Params | Description |" >> "$notes_file"
        echo "|-----------|--------|-------------|" >> "$notes_file"
        for ((s_idx=0; s_idx<GITHUB_SCRIPTS_COUNT; s_idx++)); do
            local s_enabled=$(get_github_script_field "$s_idx" "enabled")
            [[ "$s_enabled" != "true" ]] && continue
            local s_repopath=$(get_github_script_field "$s_idx" "repoPath")
            local s_params=$(get_github_script_field "$s_idx" "params")
            local s_description=$(get_github_script_field "$s_idx" "description")
            echo "| ${s_repopath} | ${s_params:-N/A} | ${s_description:-N/A} |" >> "$notes_file"
        done
    fi

    # Notes section
    echo "" >> "$notes_file"
    echo "## Notes" >> "$notes_file"
    echo "" >> "$notes_file"
    echo "- SSH root login is **enabled**" >> "$notes_file"
    echo "- Password authentication is **enabled**" >> "$notes_file"
    echo "- **iptables firewall** configured on first boot:" >> "$notes_file"
    echo "  - Loopback: INPUT/OUTPUT allowed" >> "$notes_file"
    echo "  - Established/Related: INPUT/OUTPUT allowed" >> "$notes_file"
    echo "  - RFC1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16): INPUT/OUTPUT allowed" >> "$notes_file"
    echo "  - RFC6598 (100.64.0.0/10): INPUT/OUTPUT allowed" >> "$notes_file"
    echo "  - ICMP: INPUT/OUTPUT allowed" >> "$notes_file"
    echo "  - Internet outbound: OUTPUT allowed (all public routable)" >> "$notes_file"
    echo "  - All other inbound: **DROPPED**" >> "$notes_file"
    echo "  - Open ports: \`iptables -I INPUT 1 -p tcp --dport PORT -j ACCEPT && iptables-save > /etc/iptables/rules.v4\`" >> "$notes_file"
    echo "- QEMU guest agent is **installed** (on first boot)" >> "$notes_file"
    if [[ "$T_INSTALL_POWERSHELL" == "true" ]]; then
        echo "- PowerShell is **installed** (via snap)" >> "$notes_file"
    fi

    # Set the description from file
    qm set "$vmid" --description "$(cat "$notes_file")"

    # Cleanup
    rm -f "$notes_file"
}

# Generate and set dynamic tags for VM
# Precedence: per-template tags > global tags > auto-generated tags
set_vm_tags() {
    local vmid="$1"
    local template_name="$2"
    local image_url="$3"

    log_info "Setting VM tags for $vmid"

    local tags=""

    # Check for per-template tags first (highest precedence)
    if [[ -n "$T_TAGS" ]]; then
        log_debug "Using per-template tags: $T_TAGS"
        tags="$T_TAGS"
    # Check for global tags (middle precedence)
    elif [[ -n "$G_TAGS" ]]; then
        log_debug "Using global tags: $G_TAGS"
        tags="$G_TAGS"
    # Fall back to auto-generated tags (lowest precedence)
    else
        log_debug "Using auto-generated tags"
        tags="template"

        # Extract OS info from template name or URL
        local os_name=""
        local os_version=""

        # Try to detect from template name first
        local name_lower=$(echo "$template_name" | tr '[:upper:]' '[:lower:]')
        if [[ "$name_lower" == *"ubuntu"* ]]; then
            os_name="ubuntu"
            # Try to extract version (e.g., 2204, 2404)
            if [[ "$name_lower" =~ ([0-9]{2})\.?([0-9]{2}) ]]; then
                os_version="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
            elif [[ "$name_lower" =~ ([0-9]{4}) ]]; then
                local ver="${BASH_REMATCH[1]}"
                os_version="${ver:0:2}.${ver:2:2}"
            fi
        elif [[ "$name_lower" == *"debian"* ]]; then
            os_name="debian"
            [[ "$name_lower" =~ ([0-9]+) ]] && os_version="${BASH_REMATCH[1]}"
        elif [[ "$name_lower" == *"rocky"* ]]; then
            os_name="rocky"
            [[ "$name_lower" =~ ([0-9]+) ]] && os_version="${BASH_REMATCH[1]}"
        elif [[ "$name_lower" == *"alma"* ]]; then
            os_name="almalinux"
            [[ "$name_lower" =~ ([0-9]+) ]] && os_version="${BASH_REMATCH[1]}"
        elif [[ "$name_lower" == *"centos"* ]]; then
            os_name="centos"
            [[ "$name_lower" =~ ([0-9]+) ]] && os_version="${BASH_REMATCH[1]}"
        elif [[ "$name_lower" == *"fedora"* ]]; then
            os_name="fedora"
            [[ "$name_lower" =~ ([0-9]+) ]] && os_version="${BASH_REMATCH[1]}"
        fi

        # Fallback: detect from URL
        if [[ -z "$os_name" ]]; then
            local url_lower=$(echo "$image_url" | tr '[:upper:]' '[:lower:]')
            if [[ "$url_lower" == *"ubuntu"* ]]; then
                os_name="ubuntu"
            elif [[ "$url_lower" == *"debian"* ]]; then
                os_name="debian"
            elif [[ "$url_lower" == *"rocky"* ]]; then
                os_name="rocky"
            elif [[ "$url_lower" == *"alma"* ]]; then
                os_name="almalinux"
            fi
        fi

        # Build tags
        [[ -n "$os_name" ]] && tags+=";${os_name}"
        [[ -n "$os_version" ]] && tags+=";v${os_version}"

        # Add LTS tag if applicable
        if [[ "$name_lower" == *"lts"* ]]; then
            tags+=";lts"
        fi

        # Add cloud-init tag
        tags+=";cloud-init"
    fi

    qm set "$vmid" --tags "$tags"
}

convert_to_template() {
    local vmid="$1"
    log_info "Converting VM $vmid to template"
    qm template "$vmid"
}

# =============================================================================
# MAIN PROCESSING
# =============================================================================
CURRENT_TEMPLATE=0
TOTAL_TEMPLATES=0

process_template() {
    local index="$1"

    # Get basic template fields from JSON
    local enabled=$(get_template_field "$index" "enabled")
    local vmid=$(get_template_field "$index" "vmid")
    local template_name=$(get_template_field "$index" "name")
    local url=$(get_template_field "$index" "imageUrl")
    local os_disk_size=$(get_template_field "$index" "osDiskSize")
    local data_disk_size=$(get_template_field "$index" "dataDiskSize")

    # Skip disabled templates
    if [[ "$enabled" != "true" ]]; then
        log_info "Skipping disabled template: $template_name ($vmid)"
        return 0
    fi

    # Load per-template configuration (T_ prefixed variables)
    load_template_config "$index"

    ((CURRENT_TEMPLATE++)) || true

    log_info "=========================================="
    log_info "Processing template $CURRENT_TEMPLATE of $TOTAL_TEMPLATES"
    log_info "VMID: $vmid"
    log_info "Template: $template_name"
    log_info "URL: $url"
    log_info "OS Disk: $os_disk_size"
    [[ -n "$data_disk_size" ]] && log_info "Data Disk: $data_disk_size"
    log_info "=========================================="

    # Download image
    local image_file=$(download_image "$url")

    # Convert to qcow2 if needed
    local qcow2_file=$(convert_to_qcow2 "$image_file")

    # Resize disk image and expand OS partition
    resize_image "$qcow2_file" "$os_disk_size"
    expand_os_partition "$qcow2_file"

    # Customize image (packages, users, etc)
    customize_image "$qcow2_file"

    # Check if VM exists
    local is_new="true"
    if vm_exists "$vmid"; then
        is_new="false"
        prepare_existing_vm "$vmid"
        # Update SMBIOS for existing VM (new UUID/serial each time)
        configure_smbios "$vmid"
        # Update hardware devices (TPM, RNG, SPICE) - idempotent
        configure_hardware_devices "$vmid"
    else
        create_vm "$vmid" "$template_name"
    fi

    # Import OS disk
    import_os_disk "$vmid" "$qcow2_file" "$os_disk_size"

    # Create data disk if specified
    [[ -n "$data_disk_size" ]] && create_data_disk "$vmid" "$data_disk_size"

    # Configure cloud-init
    configure_cloudinit "$vmid" "$is_new"

    # Configure cluster-level firewall IPSets (idempotent - only runs once)
    configure_cluster_firewall

    # Set dynamic tags
    set_vm_tags "$vmid" "$template_name" "$url"

    # Generate VM notes with template info, credentials, packages, etc.
    generate_vm_notes "$vmid" "$template_name" "$url"

    # Convert to template
    convert_to_template "$vmid"

    # Cleanup
    log_info "Cleaning up temporary files"
    rm -f "$qcow2_file"

    log_info "Template $template_name ($vmid) created successfully"
}

# =============================================================================
# MAIN
# =============================================================================
count_enabled_templates() {
    local template_count=$(get_template_count)
    local enabled_count=0

    for ((i=0; i<template_count; i++)); do
        local enabled=$(get_template_field "$i" "enabled")
        [[ "$enabled" == "true" ]] && ((enabled_count++)) || true
    done

    echo "$enabled_count"
}

main() {
    log_info "Starting Proxmox template creation"
    log_info "Configuration: $CONFIG_FILE"

    # Load and validate configuration
    load_config
    validate_config

    # Create and enter download directory
    mkdir -p "$DOWNLOAD_DIR"
    cd "$DOWNLOAD_DIR"
    log_debug "Download directory: $DOWNLOAD_DIR"

    local template_count=$(get_template_count)

    # Process templates
    if [[ -n "$SINGLE_VMID" ]]; then
        # Find and process single VMID
        TOTAL_TEMPLATES=1
        local found=false
        for ((i=0; i<template_count; i++)); do
            local vmid=$(get_template_field "$i" "vmid")
            if [[ "$vmid" == "$SINGLE_VMID" ]]; then
                found=true
                process_template "$i"
                break
            fi
        done
        [[ "$found" == "false" ]] && error_exit "VMID $SINGLE_VMID not found in configuration"
    else
        # Count and process all enabled templates
        TOTAL_TEMPLATES=$(count_enabled_templates)
        log_info "Found $TOTAL_TEMPLATES enabled template(s) of $template_count total"

        for ((i=0; i<template_count; i++)); do
            process_template "$i"
        done
    fi

    log_info "All templates processed successfully"
}

main

