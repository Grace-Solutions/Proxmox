#!/usr/bin/env bash
set -uo pipefail
# Note: -e removed to allow loop to continue on non-fatal errors

# =============================================================================
# Clone-ProxmoxTemplate.sh
# Clone VMs from a template with MAC address preservation on recreation
# =============================================================================

# --- Configuration ---
SOURCE_VMID="${SOURCE_VMID:-9004}"              # Full clone source VMID
START_VMID="${START_VMID:-6300}"                # First new VMID
VM_COUNT="${VM_COUNT:-3}"                       # How many VMs to create
NAME_PREFIX="${NAME_PREFIX:-DOCKER-SWARM-NODE-}"
SNAPSHOT_BEFORE="${SNAPSHOT_BEFORE:-BeforeFirstBoot}"
SNAPSHOT_AFTER="${SNAPSHOT_AFTER:-AfterFirstBoot}"
BOOT_WAIT_SECONDS="${BOOT_WAIT_SECONDS:-10}"    # Wait time after starting VM
FORCE_RECREATE="${FORCE_RECREATE:-false}"       # Set to true to recreate existing VMs

# Optional qm clone args:
# STORAGE="${STORAGE:-local-lvm}"
# FORMAT="${FORMAT:-raw}"
CLONE_EXTRA_ARGS=()

# --- Helper Functions ---
pad4() { printf "%04d" "$1"; }

log_info()  { echo "[INFO]  $(date -Iseconds) - $*"; }
log_warn()  { echo "[WARN]  $(date -Iseconds) - $*" >&2; }
log_error() { echo "[ERROR] $(date -Iseconds) - $*" >&2; }

vm_exists() {
    local vmid="$1"
    qm status "$vmid" &>/dev/null
}

is_template() {
    local vmid="$1"
    qm config "$vmid" 2>/dev/null | grep -q "^template: 1"
}

is_protected() {
    local vmid="$1"
    qm config "$vmid" 2>/dev/null | grep -q "^protection: 1"
}

get_vm_macs() {
    # Get all MAC addresses from a VM's network interfaces
    # Returns: net0=MAC,net1=MAC,... format
    local vmid="$1"
    local macs=""
    
    while IFS=': ' read -r key value; do
        if [[ "$key" =~ ^net[0-9]+$ ]]; then
            # Extract MAC address from network config (format: virtio=XX:XX:XX:XX:XX:XX,bridge=...)
            local mac
            mac=$(echo "$value" | grep -oE '([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | head -1)
            if [[ -n "$mac" ]]; then
                macs+="${key}=${mac} "
            fi
        fi
    done < <(qm config "$vmid" 2>/dev/null)
    
    echo "$macs"
}

apply_mac_addresses() {
    # Apply saved MAC addresses to a VM
    local vmid="$1"
    local macs="$2"
    
    for entry in $macs; do
        local iface="${entry%%=*}"
        local mac="${entry#*=}"
        if [[ -n "$iface" && -n "$mac" ]]; then
            log_info "Applying MAC $mac to $iface on VM $vmid"
            # Get current network config and update MAC
            local current_config
            current_config=$(qm config "$vmid" 2>/dev/null | grep "^${iface}:" | cut -d' ' -f2-)
            if [[ -n "$current_config" ]]; then
                # Replace the MAC in the config
                local new_config
                new_config=$(echo "$current_config" | sed -E "s/([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}/${mac}/")
                qm set "$vmid" --"$iface" "$new_config"
            fi
        fi
    done
}

stop_vm() {
    local vmid="$1"
    local status
    status=$(qm status "$vmid" 2>/dev/null | awk '{print $2}')

    case "$status" in
        running|paused)
            log_info "Stopping VM $vmid (status: $status)..."
            qm stop "$vmid" --timeout 60
            # Wait for VM to fully stop
            local wait_count=0
            while [[ "$(qm status "$vmid" 2>/dev/null | awk '{print $2}')" != "stopped" ]] && [[ $wait_count -lt 30 ]]; do
                sleep 1
                ((wait_count++))
            done
            log_info "VM $vmid stopped"
            ;;
        stopped)
            log_info "VM $vmid is already stopped"
            ;;
        *)
            log_warn "VM $vmid has unknown status: $status"
            ;;
    esac
}

destroy_vm() {
    local vmid="$1"
    
    if ! vm_exists "$vmid"; then
        return 0
    fi
    
    log_info "Destroying VM $vmid..."
    
    if is_protected "$vmid"; then
        log_info "Disabling protection on VM $vmid"
        qm set "$vmid" --protection 0
    fi
    
    if is_template "$vmid"; then
        log_info "Converting VM $vmid from template"
        qm set "$vmid" --template 0
    fi
    
    stop_vm "$vmid"
    qm destroy "$vmid" --purge
}

clone_vm() {
    local source="$1"
    local target="$2"
    local name="$3"
    local saved_macs="$4"
    
    log_info "Cloning VM $source -> $target (name: $name)"
    
    if ! qm clone "$source" "$target" --full 1 --name "$name" "${CLONE_EXTRA_ARGS[@]}"; then
        log_error "Clone failed for VMID=$target"
        return 1
    fi
    
    # Apply saved MAC addresses if we're recreating
    if [[ -n "$saved_macs" ]]; then
        apply_mac_addresses "$target" "$saved_macs"
    fi
    
    # Create pre-boot snapshot
    log_info "Creating snapshot '$SNAPSHOT_BEFORE' on VM $target"
    qm snapshot "$target" "$SNAPSHOT_BEFORE" --description "Baseline snapshot before first boot"
    
    # Start the VM
    log_info "Starting VM $target..."
    qm start "$target"
    
    # Wait for VM to boot
    log_info "Waiting ${BOOT_WAIT_SECONDS}s for VM to boot..."
    sleep "$BOOT_WAIT_SECONDS"
    
    # Create post-boot snapshot (without RAM for smaller size)
    log_info "Creating snapshot '$SNAPSHOT_AFTER' on VM $target (no RAM)"
    qm snapshot "$target" "$SNAPSHOT_AFTER" --description "Snapshot after first boot (no RAM)" --vmstate 0 || true
    
    return 0
}

# --- Argument Parsing ---
while [[ $# -gt 0 ]]; do
    case $1 in
        -f|--force)     FORCE_RECREATE="true"; shift ;;
        -s|--source)    SOURCE_VMID="$2"; shift 2 ;;
        -t|--start)     START_VMID="$2"; shift 2 ;;
        -c|--count)     VM_COUNT="$2"; shift 2 ;;
        -p|--prefix)    NAME_PREFIX="$2"; shift 2 ;;
        -w|--wait)      BOOT_WAIT_SECONDS="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -f, --force           Force recreate existing VMs (preserves MAC addresses)"
            echo "  -s, --source VMID     Source template VMID (default: $SOURCE_VMID)"
            echo "  -t, --start VMID      Starting VMID for clones (default: $START_VMID)"
            echo "  -c, --count N         Number of VMs to create (default: $VM_COUNT)"
            echo "  -p, --prefix PREFIX   VM name prefix (default: $NAME_PREFIX)"
            echo "  -w, --wait SECONDS    Seconds to wait after boot (default: $BOOT_WAIT_SECONDS)"
            echo "  -h, --help            Show this help message"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# --- Main Execution ---
log_info "Clone-ProxmoxTemplate.sh"
log_info "Source VMID: $SOURCE_VMID"
log_info "Starting VMID: $START_VMID"
log_info "VM Count: $VM_COUNT"
log_info "Name Prefix: $NAME_PREFIX"
log_info "Force Recreate: $FORCE_RECREATE"
echo ""

# Verify source VM exists
if ! vm_exists "$SOURCE_VMID"; then
    log_error "Source VM $SOURCE_VMID does not exist!"
    exit 1
fi

success_count=0
fail_count=0

for ((i=0; i<VM_COUNT; i++)); do
    NEW_VMID=$((START_VMID + i))
    VM_NAME="${NAME_PREFIX}$(pad4 "$i")"
    saved_macs=""

    log_info "[$((i+1))/$VM_COUNT] Processing VM $NEW_VMID ($VM_NAME)"

    # Check if VM already exists
    if vm_exists "$NEW_VMID"; then
        if [[ "$FORCE_RECREATE" == "true" ]]; then
            # Stop VM if running
            stop_vm "$NEW_VMID"

            # Save MAC addresses before destroying
            log_info "Saving MAC addresses from existing VM $NEW_VMID"
            saved_macs=$(get_vm_macs "$NEW_VMID")
            if [[ -n "$saved_macs" ]]; then
                log_info "Saved MACs: $saved_macs"
            fi

            # Destroy the existing VM
            destroy_vm "$NEW_VMID"
        else
            log_warn "VM $NEW_VMID already exists, skipping (use --force to recreate)"
            fail_count=$((fail_count + 1))
            continue
        fi
    fi

    # Clone the VM
    if clone_vm "$SOURCE_VMID" "$NEW_VMID" "$VM_NAME" "$saved_macs"; then
        log_info "[$((i+1))/$VM_COUNT] VM $NEW_VMID created successfully"
        success_count=$((success_count + 1))
    else
        log_error "[$((i+1))/$VM_COUNT] Failed to create VM $NEW_VMID"
        fail_count=$((fail_count + 1))
    fi

    echo ""

    # Short delay between VMs to allow Proxmox to catch up
    if [[ $((i+1)) -lt $VM_COUNT ]]; then
        log_info "Waiting 5 seconds before next VM..."
        sleep 5
    fi
done

log_info "=========================================="
log_info "Clone operation complete"
log_info "  Successful: $success_count"
log_info "  Failed:     $fail_count"
log_info "=========================================="

exit $fail_count

