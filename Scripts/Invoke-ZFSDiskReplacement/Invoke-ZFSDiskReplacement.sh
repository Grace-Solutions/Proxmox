#!/bin/bash
# Invoke-ZFSDiskReplacement.sh
# Idempotently replaces a failed disk in a ZFS mirror pool with a new spare.
# Handles partition table replication, zpool replace, and resilver monitoring.

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
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local log_entry="$timestamp - $level - $message"

    echo "$log_entry" >&2
    [[ -n "$LOG_FILE" ]] && echo "$log_entry" >> "$LOG_FILE" || true
}

log_info()    { log "INFO" "$@"; }
log_warn()    { log "WARN" "$@"; }
log_error()   { log "ERROR" "$@"; }
log_debug()   { [[ "$LOG_LEVEL" == "DEBUG" ]] && log "DEBUG" "$@" || true; }

format_elapsed() {
    local seconds="$1"
    if [[ "$seconds" -ge 3600 ]]; then
        printf "%dh %dm %ds" $((seconds / 3600)) $(((seconds % 3600) / 60)) $((seconds % 60))
    elif [[ "$seconds" -ge 60 ]]; then
        printf "%dm %ds" $((seconds / 60)) $((seconds % 60))
    else
        printf "%ds" "$seconds"
    fi
}

# =============================================================================
# ERROR HANDLING
# =============================================================================
LAST_ERROR_LINE=""
LAST_ERROR_CMD=""

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
    cat << 'EOF'
Usage: Invoke-ZFSDiskReplacement.sh [OPTIONS]

Idempotently replaces a failed disk in a ZFS mirror pool with a new spare disk.
Replicates the partition table from the healthy mirror member, executes
zpool replace, and optionally monitors the resilver to completion.

REQUIRED:
    -p, --pool POOL         ZFS pool name (e.g. "local-zfs-pool-00001-A")
    -f, --failed DEVICE     Failed disk device name (e.g. "nvme2n1")
    -n, --new DEVICE        New replacement disk device name (e.g. "nvme0n1")

OPTIONS:
        --monitor           Monitor resilver progress until completion
        --monitor-interval S
                            Seconds between resilver status checks (default: 30)
        --dry-run           Show what would be done without executing
    -l, --log-file FILE     Log file path
    -d, --debug             Enable debug logging
    -h, --help              Show this help message

EXAMPLES:
    # Replace failed nvme2n1 with spare nvme0n1 in pool
    Invoke-ZFSDiskReplacement.sh \
        --pool local-zfs-pool-00001-A \
        --failed nvme2n1 \
        --new nvme0n1

    # Dry run to see what would happen
    Invoke-ZFSDiskReplacement.sh \
        --pool local-zfs-pool-00001-A \
        --failed nvme2n1 \
        --new nvme0n1 \
        --dry-run

    # Replace and monitor resilver to completion
    Invoke-ZFSDiskReplacement.sh \
        --pool local-zfs-pool-00001-A \
        --failed nvme2n1 \
        --new nvme0n1 \
        --monitor

IDEMPOTENT BEHAVIOR:
    - If the pool is already ONLINE with no degraded devices, exits successfully.
    - If a resilver is already in progress with the new disk, skips to monitoring.
    - If the pool is DEGRADED, performs the replacement.
    - If the new disk already has the correct partition table, skips partitioning.
EOF
    exit 0
}

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================
POOL_NAME=""
FAILED_DEVICE=""
NEW_DEVICE=""
DRY_RUN="false"
MONITOR="false"
MONITOR_INTERVAL=30

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--pool)              POOL_NAME="$2"; shift 2 ;;
        -f|--failed)            FAILED_DEVICE="$2"; shift 2 ;;
        -n|--new)               NEW_DEVICE="$2"; shift 2 ;;
        --monitor)              MONITOR="true"; shift ;;
        --monitor-interval)     MONITOR_INTERVAL="$2"; shift 2 ;;
        --dry-run)              DRY_RUN="true"; shift ;;
        -l|--log-file)          LOG_FILE="$2"; shift 2 ;;
        -d|--debug)             LOG_LEVEL="DEBUG"; shift ;;
        -h|--help)              usage ;;
        *)                      error_exit "Unknown option: $1. Use --help for usage." ;;
    esac
done

# =============================================================================
# PREREQUISITES
# =============================================================================
ensure_commands() {
    local missing=()
    for cmd in "$@"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        error_exit "Required command(s) not found: ${missing[*]}."
    fi
}

ensure_commands zpool sgdisk lsblk

# Validate required parameters
[[ -z "$POOL_NAME" ]]     && error_exit "Missing required --pool parameter. Use --help for usage."
[[ -z "$FAILED_DEVICE" ]] && error_exit "Missing required --failed parameter. Use --help for usage."
[[ -z "$NEW_DEVICE" ]]    && error_exit "Missing required --new parameter. Use --help for usage."

# Strip /dev/ prefix if provided
FAILED_DEVICE="${FAILED_DEVICE#/dev/}"
NEW_DEVICE="${NEW_DEVICE#/dev/}"

# =============================================================================
# DEVICE RESOLUTION HELPERS
# =============================================================================

# Resolve a device name (e.g. nvme0n1) to its primary /dev/disk/by-id/ path
# Prefers the short manufacturer ID over the nvme-nvme.* eui paths
resolve_by_id() {
    local dev_name="$1"
    local by_id_path=""

    # Find by-id links pointing to this device (exclude partition links)
    by_id_path=$(ls -la /dev/disk/by-id/ 2>/dev/null \
        | grep -E -- "[.][.]/${dev_name}$" \
        | grep -v 'nvme-nvme\.' \
        | grep -v 'eui\.' \
        | awk '{print $9}' \
        | head -1)

    if [[ -z "$by_id_path" ]]; then
        return 1
    fi
    echo "$by_id_path"
}

# Find the by-id reference used by ZFS for a device in a given pool
# ZFS stores the by-id name (without /dev/disk/by-id/ prefix) in its config
find_zfs_device_ref() {
    local pool="$1"
    local search_pattern="$2"
    zpool status "$pool" 2>/dev/null \
        | awk '{print $1}' \
        | grep -F "$search_pattern" \
        | head -1
}

# Find the healthy (ONLINE) member of a mirror vdev in a pool
# Returns the by-id reference as shown in zpool status
find_healthy_mirror_member() {
    local pool="$1"
    local failed_ref="$2"

    local in_mirror="false"
    local mirror_name=""

    # Parse zpool status to find the mirror containing the failed disk
    while IFS= read -r line; do
        local dev_name state
        dev_name=$(echo "$line" | awk '{print $1}')
        state=$(echo "$line" | awk '{print $2}')

        # Track mirror vdevs
        if [[ "$dev_name" =~ ^mirror- ]]; then
            in_mirror="true"
            mirror_name="$dev_name"
            continue
        fi

        # Track replacing vdevs (inside mirror)
        if [[ "$dev_name" =~ ^replacing- ]]; then
            continue
        fi

        # If we're in the mirror and find the failed disk, flag it
        if [[ "$in_mirror" == "true" && "$dev_name" == *"$failed_ref"* ]]; then
            continue
        fi

        # If we're in the mirror and this device is ONLINE and NOT the failed one
        if [[ "$in_mirror" == "true" && "$state" == "ONLINE" && "$dev_name" != *"$failed_ref"* ]]; then
            # Skip if this is the new replacement disk (during resilver)
            echo "$dev_name"
            return 0
        fi

        # Reset when we hit a non-indented line (new vdev)
        if [[ "$dev_name" == "$pool" || "$dev_name" =~ ^[a-z] ]] && [[ "$dev_name" != mirror-* && "$dev_name" != replacing-* ]]; then
            if [[ "$in_mirror" == "true" ]]; then
                in_mirror="false"
            fi
        fi
    done < <(zpool status "$pool" 2>/dev/null | grep -E '^\t  ' | sed 's/^\t  //')

    return 1
}

# Resolve a by-id name (from zpool status) to a /dev/ block device path
byid_to_dev() {
    local by_id_name="$1"
    # Strip any partition suffix to get base device
    local base_name="${by_id_name%%-part[0-9]*}"
    local target
    target=$(readlink -f "/dev/disk/by-id/$base_name" 2>/dev/null) || return 1
    echo "$target"
}

# Check if a disk has a partition table matching the expected ZFS layout
# Returns 0 if partitions exist with BF01 code, 1 otherwise
has_zfs_partitions() {
    local dev="$1"
    sgdisk -p "/dev/$dev" 2>/dev/null | grep -q 'BF01'
}

# Compare partition tables between two devices
# Returns 0 if they match (same number of partitions, same types)
partition_tables_match() {
    local source_dev="$1"
    local target_dev="$2"

    local source_parts target_parts
    source_parts=$(sgdisk -p "/dev/$source_dev" 2>/dev/null | grep '^ ' | awk '{print $1, $6}' | sort)
    target_parts=$(sgdisk -p "/dev/$target_dev" 2>/dev/null | grep '^ ' | awk '{print $1, $6}' | sort)

    [[ "$source_parts" == "$target_parts" ]]
}



# =============================================================================
# RESILVER MONITORING
# =============================================================================
monitor_resilver() {
    local pool="$1"
    local interval="$2"
    local start_time=$SECONDS

    log_info "Monitoring resilver progress (interval: ${interval}s)..."
    log_info "------------------------------------------"

    while true; do
        local status_output
        status_output=$(zpool status "$pool" 2>/dev/null)

        # Check if resilver is still in progress
        if ! echo "$status_output" | grep -q "resilver in progress"; then
            # Check if it completed
            local scan_line
            scan_line=$(echo "$status_output" | grep "scan:" || true)

            if echo "$scan_line" | grep -q "resilvered"; then
                local elapsed=$((SECONDS - start_time))
                log_info "------------------------------------------"
                log_info "Resilver complete!"
                log_info "  $(echo "$scan_line" | sed 's/.*scan: //')"
                log_info "  Monitoring duration: $(format_elapsed $elapsed)"
                return 0
            fi

            # Pool might have gone offline or something unexpected
            local pool_state
            pool_state=$(echo "$status_output" | grep "state:" | awk '{print $2}')
            if [[ "$pool_state" == "ONLINE" ]]; then
                log_info "Pool is ONLINE — resilver appears to have completed"
                return 0
            fi

            log_warn "Resilver no longer in progress but pool state is: $pool_state"
            return 1
        fi

        # Extract progress info from scan line
        local scan_line
        scan_line=$(echo "$status_output" | grep "scan:" | head -1)
        local progress_line
        progress_line=$(echo "$status_output" | grep -E "resilvered," | head -1)

        if [[ -n "$progress_line" ]]; then
            # Extract percentage and ETA
            local pct eta resilvered
            pct=$(echo "$progress_line" | grep -oE '[0-9]+\.[0-9]+% done' || echo "unknown")
            eta=$(echo "$progress_line" | grep -oE '[0-9]+:[0-9]+:[0-9]+ to go' || echo "no estimate")
            resilvered=$(echo "$progress_line" | grep -oE '^[[:space:]]*[0-9.]+[KMGTP]? resilvered' | sed 's/^[[:space:]]*//' || echo "")

            local elapsed=$((SECONDS - start_time))
            log_info "  Progress: $pct | Resilvered: ${resilvered:-unknown} | ETA: $eta | Elapsed: $(format_elapsed $elapsed)"
        fi

        sleep "$interval"
    done
}

# =============================================================================
# MAIN
# =============================================================================
main() {
    local main_start=$SECONDS

    log_info "=========================================="
    log_info "$SCRIPT_NAME"
    log_info "=========================================="
    log_info "Pool:           $POOL_NAME"
    log_info "Failed Device:  $FAILED_DEVICE"
    log_info "New Device:     $NEW_DEVICE"
    log_info "Monitor:        $MONITOR"
    log_info "Dry Run:        $DRY_RUN"
    log_info "=========================================="

    # -------------------------------------------------------------------------
    # Step 1: Validate pool exists
    # -------------------------------------------------------------------------
    log_info "Step 1: Validating pool..."

    if ! zpool status "$POOL_NAME" &>/dev/null; then
        error_exit "Pool '$POOL_NAME' does not exist or is not accessible"
    fi

    local pool_state
    pool_state=$(zpool status "$POOL_NAME" | grep "state:" | awk '{print $2}')
    log_info "  Pool state: $pool_state"

    # -------------------------------------------------------------------------
    # Step 2: Check idempotent states
    # -------------------------------------------------------------------------
    log_info "Step 2: Checking current state..."

    local new_by_id
    new_by_id=$(resolve_by_id "$NEW_DEVICE") || error_exit "Cannot resolve by-id path for $NEW_DEVICE"
    log_debug "  New disk by-id: $new_by_id"

    local failed_by_id
    failed_by_id=$(resolve_by_id "$FAILED_DEVICE") || true
    log_debug "  Failed disk by-id: ${failed_by_id:-not resolvable (may be removed)}"

    # Check if resilver is already in progress with the new disk
    local status_output
    status_output=$(zpool status "$POOL_NAME" 2>/dev/null)

    if echo "$status_output" | grep -q "resilver in progress"; then
        if echo "$status_output" | grep -q "$new_by_id"; then
            log_info "  Resilver already in progress with new disk — skipping to monitoring"
            if [[ "$MONITOR" == "true" ]]; then
                monitor_resilver "$POOL_NAME" "$MONITOR_INTERVAL"
            else
                log_info "  Use --monitor to watch resilver progress"
            fi
            local elapsed=$((SECONDS - main_start))
            log_info "=========================================="
            log_info "Duration: $(format_elapsed $elapsed)"
            log_info "=========================================="
            return 0
        fi
    fi

    # Check if pool is already healthy with new disk online
    if echo "$status_output" | grep -q "$new_by_id" && [[ "$pool_state" == "ONLINE" ]]; then
        log_info "  Pool is ONLINE and new disk is already a member — nothing to do"
        return 0
    fi

    # Check if pool is healthy with no degraded state
    if [[ "$pool_state" == "ONLINE" ]]; then
        log_warn "  Pool is ONLINE — no degraded devices found. Nothing to replace."
        return 0
    fi

    if [[ "$pool_state" != "DEGRADED" ]]; then
        error_exit "Pool state is '$pool_state' — expected DEGRADED for disk replacement"
    fi

    # -------------------------------------------------------------------------
    # Step 3: Identify the failed disk reference in the pool
    # -------------------------------------------------------------------------
    log_info "Step 3: Identifying failed disk in pool..."

    # Find the ZFS device reference for the failed disk
    local failed_zfs_ref=""
    if [[ -n "$failed_by_id" ]]; then
        failed_zfs_ref=$(find_zfs_device_ref "$POOL_NAME" "$failed_by_id") || true
    fi

    # If we can't find it by by-id, search by any partial match on the device serial/name
    if [[ -z "$failed_zfs_ref" ]]; then
        # Try to find any REMOVED/FAULTED/UNAVAIL device in the pool
        failed_zfs_ref=$(zpool status "$POOL_NAME" 2>/dev/null \
            | grep -E 'REMOVED|FAULTED|UNAVAIL' \
            | awk '{print $1}' \
            | head -1)
    fi

    if [[ -z "$failed_zfs_ref" ]]; then
        error_exit "Cannot find a failed/removed device in pool '$POOL_NAME'"
    fi

    local failed_state
    failed_state=$(zpool status "$POOL_NAME" 2>/dev/null \
        | grep "$failed_zfs_ref" \
        | awk '{print $2}' \
        | head -1)

    log_info "  Failed disk ZFS reference: $failed_zfs_ref"
    log_info "  Failed disk state: $failed_state"

    # -------------------------------------------------------------------------
    # Step 4: Find the healthy mirror member
    # -------------------------------------------------------------------------
    log_info "Step 4: Finding healthy mirror member..."

    local healthy_ref
    healthy_ref=$(find_healthy_mirror_member "$POOL_NAME" "$failed_zfs_ref") || \
        error_exit "Cannot find a healthy ONLINE member in the mirror"

    log_info "  Healthy disk ZFS reference: $healthy_ref"

    # Resolve healthy disk to /dev/ path for partition table source
    local healthy_dev
    healthy_dev=$(byid_to_dev "$healthy_ref") || \
        error_exit "Cannot resolve healthy disk '$healthy_ref' to a /dev/ path"

    # Strip /dev/ prefix to get device name
    local healthy_dev_name="${healthy_dev#/dev/}"
    log_debug "  Healthy disk device: $healthy_dev_name"

    # -------------------------------------------------------------------------
    # Step 5: Validate the new disk
    # -------------------------------------------------------------------------
    log_info "Step 5: Validating new disk ($NEW_DEVICE)..."

    # Verify the device exists
    if [[ ! -b "/dev/$NEW_DEVICE" ]]; then
        error_exit "Device /dev/$NEW_DEVICE does not exist or is not a block device"
    fi

    # Verify it's not already in a pool
    local new_in_pool
    new_in_pool=$(zpool status -v 2>/dev/null | grep "$new_by_id" || true)
    if [[ -n "$new_in_pool" ]] && ! echo "$new_in_pool" | grep -qE 'REMOVED|FAULTED|UNAVAIL'; then
        error_exit "New disk $NEW_DEVICE ($new_by_id) appears to already be in a ZFS pool"
    fi

    # Check disk size matches healthy disk
    local new_size healthy_size
    new_size=$(lsblk -bdno SIZE "/dev/$NEW_DEVICE" 2>/dev/null)
    healthy_size=$(lsblk -bdno SIZE "$healthy_dev" 2>/dev/null)
    log_info "  New disk size:     $(numfmt --to=iec "$new_size" 2>/dev/null || echo "$new_size bytes")"
    log_info "  Healthy disk size: $(numfmt --to=iec "$healthy_size" 2>/dev/null || echo "$healthy_size bytes")"

    if [[ "$new_size" -lt "$healthy_size" ]]; then
        error_exit "New disk ($new_size bytes) is smaller than healthy disk ($healthy_size bytes)"
    fi

    # -------------------------------------------------------------------------
    # Step 6: Replicate partition table
    # -------------------------------------------------------------------------
    log_info "Step 6: Checking partition table..."

    if partition_tables_match "$healthy_dev_name" "$NEW_DEVICE"; then
        log_info "  Partition table already matches healthy disk — skipping"
    else
        if has_zfs_partitions "$NEW_DEVICE"; then
            log_warn "  New disk has existing ZFS partitions that don't match — will overwrite"
        fi

        log_info "  Replicating partition table from $healthy_dev_name to $NEW_DEVICE..."
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "  [DRY RUN] Would execute: sgdisk /dev/$healthy_dev_name -R /dev/$NEW_DEVICE"
            log_info "  [DRY RUN] Would execute: sgdisk -G /dev/$NEW_DEVICE"
        else
            sgdisk "/dev/$healthy_dev_name" -R "/dev/$NEW_DEVICE" || \
                error_exit "Failed to replicate partition table"
            sgdisk -G "/dev/$NEW_DEVICE" || \
                error_exit "Failed to randomize GUIDs on new disk"
            log_info "  Partition table replicated and GUIDs randomized"

            # Wait for partition devices to appear
            sleep 2
            partprobe "/dev/$NEW_DEVICE" 2>/dev/null || true
            sleep 1
        fi
    fi

    # Verify partition symlinks exist
    if [[ "$DRY_RUN" != "true" ]]; then
        local new_part1="/dev/disk/by-id/${new_by_id}_1-part1"
        if [[ ! -e "$new_part1" ]]; then
            # Try alternate naming convention
            new_part1="/dev/disk/by-id/${new_by_id}-part1"
        fi
        if [[ ! -e "$new_part1" ]]; then
            error_exit "Cannot find partition 1 by-id link for new disk after partitioning"
        fi
        log_info "  New disk partition 1: $new_part1"
    fi

    # -------------------------------------------------------------------------
    # Step 7: Execute zpool replace
    # -------------------------------------------------------------------------
    log_info "Step 7: Replacing failed disk in pool..."

    # Resolve the new partition path for zpool replace
    local new_part1_path
    if [[ "$DRY_RUN" == "true" ]]; then
        new_part1_path="/dev/disk/by-id/${new_by_id}_1-part1"
    else
        new_part1_path="$new_part1"
    fi

    log_info "  Old device: $failed_zfs_ref"
    log_info "  New device: $new_part1_path"

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "  [DRY RUN] Would execute: zpool replace $POOL_NAME $failed_zfs_ref $new_part1_path"
    else
        zpool replace "$POOL_NAME" "$failed_zfs_ref" "$new_part1_path" || \
            error_exit "zpool replace failed"
        log_info "  zpool replace initiated successfully"
    fi

    # -------------------------------------------------------------------------
    # Step 8: Verify resilver started
    # -------------------------------------------------------------------------
    if [[ "$DRY_RUN" != "true" ]]; then
        log_info "Step 8: Verifying resilver..."
        sleep 2

        status_output=$(zpool status "$POOL_NAME" 2>/dev/null)
        if echo "$status_output" | grep -q "resilver in progress"; then
            log_info "  Resilver in progress"
        elif echo "$status_output" | grep -q "resilvered"; then
            log_info "  Resilver already completed (small pool or fast disk)"
        else
            log_warn "  Could not confirm resilver status — check manually with: zpool status $POOL_NAME"
        fi

        # Show initial pool status
        log_info "------------------------------------------"
        local config_section
        config_section=$(zpool status "$POOL_NAME" 2>/dev/null | sed -n '/config:/,/errors:/p' | head -20)
        while IFS= read -r line; do
            [[ -n "$line" ]] && log_info "  $line"
        done <<< "$config_section"
        log_info "------------------------------------------"
    else
        log_info "Step 8: [DRY RUN] Would verify resilver started"
    fi

    # -------------------------------------------------------------------------
    # Step 9: Monitor (optional)
    # -------------------------------------------------------------------------
    if [[ "$MONITOR" == "true" && "$DRY_RUN" != "true" ]]; then
        monitor_resilver "$POOL_NAME" "$MONITOR_INTERVAL"
    elif [[ "$MONITOR" == "true" && "$DRY_RUN" == "true" ]]; then
        log_info "Step 9: [DRY RUN] Would monitor resilver progress"
    fi

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    local total_elapsed=$((SECONDS - main_start))
    pool_state=$(zpool status "$POOL_NAME" 2>/dev/null | grep "state:" | awk '{print $2}')

    log_info "=========================================="
    log_info "Disk replacement complete"
    log_info "  Pool:      $POOL_NAME"
    log_info "  State:     $pool_state"
    log_info "  Old disk:  $failed_zfs_ref ($failed_state)"
    log_info "  New disk:  $new_by_id"
    log_info "  Duration:  $(format_elapsed $total_elapsed)"
    log_info "=========================================="

    return 0
}

main
exit $?