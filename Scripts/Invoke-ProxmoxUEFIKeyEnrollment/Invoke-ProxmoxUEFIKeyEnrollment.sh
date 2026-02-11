#!/bin/bash
# Invoke-ProxmoxUEFIKeyEnrollment.sh
# Idempotently enrolls Microsoft UEFI CA 2023 certificates on VMs whose EFI disk
# has pre-enrolled-keys but lacks ms-cert=2023.  Handles graceful shutdown, wait,
# enrollment, and conditional restart.

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

log_progress() {
    local current="$1"
    local total="$2"
    shift 2
    local message="$*"
    local pct=0
    [[ "$total" -gt 0 ]] && pct=$((current * 100 / total))
    log "INFO" "[${current}/${total}] (${pct}%) ${message}"
}

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
Usage: Invoke-ProxmoxUEFIKeyEnrollment.sh [OPTIONS]

Idempotently enrolls the Microsoft UEFI CA 2023 certificate on VMs whose EFI
disk has pre-enrolled-keys but lacks ms-cert=2023.  Running VMs are gracefully
shut down, enrolled, and restarted.  Stopped VMs are enrolled and left stopped.

SELECTION (default: all local VMs with eligible EFI disks):
    -i, --vmids LIST        Comma-separated VMID list (e.g. "100,101,5000")
    -c, --config FILE       JSON config file path

OPTIONS:
    -N, --node NODE         Target node (default: local hostname)
        --shutdown-timeout S
                            Seconds to wait for graceful shutdown (default: 120)
        --dry-run           Show what would be done without executing
    -l, --log-file FILE     Log file path
    -d, --debug             Enable debug logging
    -h, --help              Show this help message

EXAMPLES:
    # Enroll all eligible VMs on this node
    Invoke-ProxmoxUEFIKeyEnrollment.sh

    # Enroll specific VMIDs
    Invoke-ProxmoxUEFIKeyEnrollment.sh --vmids "22008,5401,25000"

    # Dry run to see which VMs need enrollment
    Invoke-ProxmoxUEFIKeyEnrollment.sh --dry-run

    # Custom shutdown timeout
    Invoke-ProxmoxUEFIKeyEnrollment.sh --shutdown-timeout 300
EOF
    exit 0
}

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================
CONFIG_FILE=""
VMID_LIST=""
TARGET_NODE=""
SHUTDOWN_TIMEOUT=120
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--vmids)             VMID_LIST="$2"; shift 2 ;;
        -c|--config)            CONFIG_FILE="$2"; shift 2 ;;
        -N|--node)              TARGET_NODE="$2"; shift 2 ;;
        --shutdown-timeout)     SHUTDOWN_TIMEOUT="$2"; shift 2 ;;
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

ensure_commands jq qm

[[ -z "$TARGET_NODE" ]] && TARGET_NODE=$(hostname)

# =============================================================================
# JSON CONFIG PARSING (optional)
# =============================================================================
# Config format:
# {
#   "shutdownTimeout": 120,
#   "vmids": [22008, 5401, 25000]
# }

parse_config() {
    local cfg="$1"
    [[ ! -f "$cfg" ]] && error_exit "Configuration file not found: $cfg"

    local val
    val=$(jq -r '.shutdownTimeout // empty' "$cfg")
    [[ -n "$val" ]] && SHUTDOWN_TIMEOUT="$val"

    local vmids_from_cfg
    vmids_from_cfg=$(jq -r '[.vmids[]? // empty] | map(tostring) | join(",")' "$cfg")
    [[ -z "$VMID_LIST" && -n "$vmids_from_cfg" ]] && VMID_LIST="$vmids_from_cfg"

    log_debug "Config parsed: shutdownTimeout=$SHUTDOWN_TIMEOUT vmids=$VMID_LIST"
}

if [[ -n "$CONFIG_FILE" ]]; then
    parse_config "$CONFIG_FILE"
elif [[ -f "${SCRIPT_DIR}/${SCRIPT_NAME}.json" && -z "$VMID_LIST" ]]; then
    log_info "Auto-loading config: ${SCRIPT_DIR}/${SCRIPT_NAME}.json"
    parse_config "${SCRIPT_DIR}/${SCRIPT_NAME}.json"
fi

# =============================================================================
# VM DISCOVERY — find VMs needing UEFI 2023 enrollment
# =============================================================================

# Check if a single VM needs EFI key enrollment.
# Returns 0 (needs enrollment), 1 (already enrolled / not applicable).
# Sets global NEEDS_ENROLL_REASON with the reason string.
NEEDS_ENROLL_REASON=""

needs_efi_enrollment() {
    local vmid="$1"
    NEEDS_ENROLL_REASON=""

    local config
    config=$(qm config "$vmid" 2>/dev/null) || {
        NEEDS_ENROLL_REASON="cannot read config"
        return 1
    }

    # Extract efidisk0 line
    local efidisk_line
    efidisk_line=$(echo "$config" | grep '^efidisk0:' || true)

    if [[ -z "$efidisk_line" ]]; then
        NEEDS_ENROLL_REASON="no EFI disk"
        return 1
    fi

    # Must have pre-enrolled-keys to be eligible
    if ! echo "$efidisk_line" | grep -q 'pre-enrolled-keys=1'; then
        NEEDS_ENROLL_REASON="EFI disk without pre-enrolled-keys"
        return 1
    fi

    # Only Windows 10/11 VMs need the ms-cert=2023 enrollment
    local ostype
    ostype=$(echo "$config" | grep '^ostype:' | awk '{print $2}' || true)
    if [[ "$ostype" != "win10" && "$ostype" != "win11" ]]; then
        NEEDS_ENROLL_REASON="non-Windows OS ($ostype) — enrollment not applicable"
        return 1
    fi

    # Already has ms-cert=2023 — nothing to do
    if echo "$efidisk_line" | grep -q 'ms-cert=2023'; then
        NEEDS_ENROLL_REASON="already enrolled (ms-cert=2023)"
        return 1
    fi

    NEEDS_ENROLL_REASON="Windows ($ostype) with pre-enrolled-keys but missing ms-cert=2023"
    return 0
}

# Get the current status of a VM (running, stopped, paused, etc.)
get_vm_status() {
    local vmid="$1"
    qm status "$vmid" 2>/dev/null | awk '{print $2}'
}

# Get the VM name from config
get_vm_name() {
    local vmid="$1"
    qm config "$vmid" 2>/dev/null | grep '^name:' | awk '{print $2}'
}

# Check if a VM is a template (returns 0 if template, 1 if not)
is_template() {
    local vmid="$1"
    local tmpl
    tmpl=$(qm config "$vmid" 2>/dev/null | grep '^template:' | awk '{print $2}' || true)
    [[ "$tmpl" == "1" ]]
}

# Gracefully shut down a VM and wait for it to reach "stopped" state.
# Returns 0 on success, 1 on timeout.
shutdown_and_wait() {
    local vmid="$1"
    local timeout="$2"

    log_info "  Sending ACPI shutdown to VM $vmid (timeout: ${timeout}s)..."
    qm shutdown "$vmid" --timeout "$timeout" 2>/dev/null || true

    local elapsed=0
    local poll_interval=3
    while [[ $elapsed -lt $timeout ]]; do
        local status
        status=$(get_vm_status "$vmid")
        if [[ "$status" == "stopped" ]]; then
            log_info "  VM $vmid stopped after $(format_elapsed $elapsed)"
            return 0
        fi
        sleep "$poll_interval"
        elapsed=$((elapsed + poll_interval))
        # Log progress every 15 seconds
        if [[ $((elapsed % 15)) -eq 0 ]]; then
            log_debug "  Waiting for VM $vmid to stop... ${elapsed}s / ${timeout}s (status: $status)"
        fi
    done

    log_error "  VM $vmid did not stop within ${timeout}s"
    return 1
}

# Build the list of VMIDs to process
build_vm_list() {
    if [[ -n "$VMID_LIST" ]]; then
        # User-specified list — just echo them
        echo "$VMID_LIST" | tr ',' '\n'
    else
        # Auto-discover: all qemu VMs on this node
        qm list 2>/dev/null | awk 'NR>1 {print $1}'
    fi
}


# =============================================================================
# MAIN
# =============================================================================
main() {
    local main_start=$SECONDS

    log_info "=========================================="
    log_info "$SCRIPT_NAME"
    log_info "=========================================="
    log_info "Node:             $TARGET_NODE"
    log_info "Shutdown Timeout: ${SHUTDOWN_TIMEOUT}s"
    log_info "Dry Run:          $DRY_RUN"
    log_info "=========================================="

    # Build candidate list
    log_info "Discovering VMs..."
    local all_vmids
    all_vmids=$(build_vm_list)

    local candidate_count=0
    candidate_count=$(echo "$all_vmids" | grep -c '[0-9]' || true)
    log_info "Found $candidate_count candidate VM(s) to evaluate"

    # Filter to only VMs needing enrollment
    local -a eligible_vms=()
    for vmid in $all_vmids; do
        if needs_efi_enrollment "$vmid"; then
            local name
            name=$(get_vm_name "$vmid")
            log_info "  VMID $vmid ($name) — $NEEDS_ENROLL_REASON"
            eligible_vms+=("$vmid")
        else
            log_debug "  VMID $vmid — skipped: $NEEDS_ENROLL_REASON"
        fi
    done

    local total=${#eligible_vms[@]}
    if [[ $total -eq 0 ]]; then
        log_info "No VMs require UEFI 2023 certificate enrollment"
        log_info "=========================================="
        return 0
    fi

    log_info "------------------------------------------"
    log_info "Found $total VM(s) requiring enrollment"
    log_info "------------------------------------------"

    # Process each VM
    local success_count=0
    local skip_count=0
    local fail_count=0
    local current=0

    for vmid in "${eligible_vms[@]}"; do
        current=$((current + 1))
        local name
        name=$(get_vm_name "$vmid")

        log_info "------------------------------------------"
        log_progress "$current" "$total" "VMID $vmid ($name) | Success: $success_count | Skipped: $skip_count | Failed: $fail_count"

        # Detect template status
        local was_template="false"
        if is_template "$vmid"; then
            was_template="true"
            log_info "  VM is a template — will temporarily un-template for enrollment"
        fi

        # Record initial status
        local initial_status
        initial_status=$(get_vm_status "$vmid")
        log_info "  Initial status: $initial_status"

        # Shutdown if running
        if [[ "$initial_status" == "running" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                log_info "  [DRY RUN] Would shutdown VM $vmid and wait up to ${SHUTDOWN_TIMEOUT}s"
            else
                if ! shutdown_and_wait "$vmid" "$SHUTDOWN_TIMEOUT"; then
                    log_error "  Failed to shutdown VM $vmid — skipping enrollment"
                    fail_count=$((fail_count + 1))
                    continue
                fi
            fi
        fi

        # Un-template if needed (qm enroll-efi-keys refuses on templates)
        if [[ "$was_template" == "true" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                log_info "  [DRY RUN] Would execute: qm set $vmid --template 0"
            else
                log_info "  Removing template flag..."
                if ! qm set "$vmid" --template 0 2>&1; then
                    log_error "  Failed to un-template VM $vmid"
                    fail_count=$((fail_count + 1))
                    continue
                fi
            fi
        fi

        # Enroll keys
        if [[ "$DRY_RUN" == "true" ]]; then
            log_info "  [DRY RUN] Would execute: qm enroll-efi-keys $vmid"
        else
            log_info "  Enrolling UEFI 2023 certificate..."
            if qm enroll-efi-keys "$vmid" 2>&1; then
                log_info "  Successfully enrolled UEFI 2023 certificate"
            else
                log_error "  Failed to enroll UEFI 2023 certificate on VM $vmid"
                # Restore template flag even on failure
                if [[ "$was_template" == "true" ]]; then
                    log_warn "  Restoring template flag despite enrollment failure..."
                    qm set "$vmid" --template 1 2>/dev/null || log_warn "  Failed to restore template flag"
                fi
                # Try to restart if it was running before, even on failure
                if [[ "$initial_status" == "running" ]]; then
                    log_warn "  Attempting to restart VM $vmid despite enrollment failure..."
                    qm start "$vmid" 2>/dev/null || log_warn "  Failed to restart VM $vmid"
                fi
                fail_count=$((fail_count + 1))
                continue
            fi
        fi

        # Restore template flag if it was a template
        if [[ "$was_template" == "true" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                log_info "  [DRY RUN] Would execute: qm set $vmid --template 1"
            else
                log_info "  Restoring template flag..."
                if ! qm set "$vmid" --template 1 2>&1; then
                    log_warn "  Failed to restore template flag on VM $vmid"
                fi
            fi
        fi

        # Restart if was running
        if [[ "$initial_status" == "running" ]]; then
            if [[ "$DRY_RUN" == "true" ]]; then
                log_info "  [DRY RUN] Would execute: qm start $vmid"
            else
                log_info "  Restarting VM $vmid..."
                if qm start "$vmid" 2>/dev/null; then
                    log_info "  VM $vmid started"
                else
                    log_warn "  Failed to restart VM $vmid"
                fi
            fi
        else
            log_info "  VM $vmid was stopped — leaving stopped"
        fi

        success_count=$((success_count + 1))
    done

    # Summary
    local total_elapsed=$((SECONDS - main_start))
    log_info "=========================================="
    log_info "Enrollment complete"
    log_info "  Total:      $total"
    log_info "  Successful: $success_count"
    log_info "  Skipped:    $skip_count"
    log_info "  Failed:     $fail_count"
    log_info "  Duration:   $(format_elapsed $total_elapsed)"
    log_info "=========================================="

    return "$fail_count"
}

main
exit $?
