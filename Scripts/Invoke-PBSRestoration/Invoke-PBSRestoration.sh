#!/bin/bash
# Invoke-PBSRestoration.sh
# Restores the latest PBS backup for guests selected by VMID list, notes regex, or JSON config.
# Supports automatic round-robin of available target storages and both VM and CT guest types.

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
    # Clean up temp files
    [[ -n "${BACKUP_CACHE_FILE:-}" && -f "${BACKUP_CACHE_FILE:-}" ]] && rm -f "$BACKUP_CACHE_FILE"
    [[ -n "${CONFIG_TEMP_FILE:-}" && -f "${CONFIG_TEMP_FILE:-}" ]] && rm -f "$CONFIG_TEMP_FILE"
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
Usage: Invoke-PBSRestoration.sh [OPTIONS]

Restores the latest PBS backup for guests selected by VMID list, notes regex,
or JSON configuration. Automatically round-robins across available storages.

SELECTION (at least one required, mutually exclusive):
    -i, --vmids LIST        Comma-separated VMID list (e.g. "100,101,5000")
    -n, --notes-regex PAT   Extended regex matched against backup notes
    -c, --config FILE|URL   JSON config file path or HTTP(S) URL

OPTIONS:
    -s, --pbs-storage NAME  PBS storage name (default: auto — uses first available)
    -t, --target-storage S  Target storage name (default: auto — discovers available)
        --target-storage-mode MODE
                            Storage selection mode: round-robin or single (default: round-robin)
    -N, --node NODE         Target node for restore (default: local hostname)
    -f, --force             Overwrite existing guest with same VMID
    -u, --unique            Assign unique random MAC addresses on restore
        --start             Start guest after successful restore
        --pool POOL         Add restored guest to this pool
        --bwlimit KB/S      I/O bandwidth limit in KiB/s
        --dry-run           Show what would be restored without executing
    -l, --log-file FILE     Log file path
    -d, --debug             Enable debug logging
    -h, --help              Show this help message

EXAMPLES:
    # Restore latest backup for VMIDs 101 and 102
    Invoke-PBSRestoration.sh --vmids "101,102"

    # Restore all guests whose backup notes match a pattern
    Invoke-PBSRestoration.sh --notes-regex "DOCKER-HOST-.*"

    # Dry run with forced overwrite and specific target storage
    Invoke-PBSRestoration.sh -i "5000" --force --target-storage local-zfs-pool-00001 --dry-run

    # Use JSON config for complex selections
    Invoke-PBSRestoration.sh --config Invoke-PBSRestoration.json

    # Use a remote JSON config via URL
    Invoke-PBSRestoration.sh --config "https://example.com/configs/restore.json"
EOF
    exit 0
}

# =============================================================================
# PARSE ARGUMENTS
# =============================================================================
CONFIG_FILE=""
VMID_LIST=""
NOTES_REGEX=""
PBS_STORAGE="auto"
TARGET_STORAGE="auto"
TARGET_STORAGE_MODE="round-robin"
TARGET_NODE=""
FORCE_RESTORE="false"
UNIQUE_MACS="false"
START_AFTER="false"
RESTORE_POOL=""
BW_LIMIT=""
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--vmids)          VMID_LIST="$2"; shift 2 ;;
        -n|--notes-regex)    NOTES_REGEX="$2"; shift 2 ;;
        -c|--config)         CONFIG_FILE="$2"; shift 2 ;;
        -s|--pbs-storage)    PBS_STORAGE="$2"; shift 2 ;;
        -t|--target-storage) TARGET_STORAGE="$2"; shift 2 ;;
        --target-storage-mode) TARGET_STORAGE_MODE="$2"; shift 2 ;;
        -N|--node)           TARGET_NODE="$2"; shift 2 ;;
        -f|--force)          FORCE_RESTORE="true"; shift ;;
        -u|--unique)         UNIQUE_MACS="true"; shift ;;
        --start)             START_AFTER="true"; shift ;;
        --pool)              RESTORE_POOL="$2"; shift 2 ;;
        --bwlimit)           BW_LIMIT="$2"; shift 2 ;;
        --dry-run)           DRY_RUN="true"; shift ;;
        -l|--log-file)       LOG_FILE="$2"; shift 2 ;;
        -d|--debug)          LOG_LEVEL="DEBUG"; shift ;;
        -h|--help)           usage ;;
        *)                   error_exit "Unknown option: $1. Use --help for usage." ;;
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
        error_exit "Required command(s) not found: ${missing[*]}. Install them before running this script."
    fi
}

# Core commands required regardless of config source
ensure_commands jq pvesh qmrestore pct

# HTTP download capability — require at least one of curl or wget
HAS_CURL=false
HAS_WGET=false
command -v curl &>/dev/null && HAS_CURL=true
command -v wget &>/dev/null && HAS_WGET=true

[[ -z "$TARGET_NODE" ]] && TARGET_NODE=$(hostname)

# =============================================================================
# REMOTE CONFIG HELPERS
# =============================================================================
CONFIG_TEMP_FILE=""

is_url() {
    [[ "$1" =~ ^https?:// ]]
}

fetch_remote_config() {
    local url="$1"

    if [[ "$HAS_CURL" != "true" && "$HAS_WGET" != "true" ]]; then
        error_exit "Remote config URL specified but neither curl nor wget is installed."
    fi

    CONFIG_TEMP_FILE=$(mktemp "${TMPDIR:-/tmp}/pbs-restore-config.XXXXXX.json")

    log_info "Downloading remote config: $url"
    if [[ "$HAS_CURL" == "true" ]]; then
        if ! curl -fsSL --max-time 30 -o "$CONFIG_TEMP_FILE" "$url" 2>/dev/null; then
            error_exit "Failed to download config from $url (curl)"
        fi
    else
        if ! wget -q --timeout=30 -O "$CONFIG_TEMP_FILE" "$url" 2>/dev/null; then
            error_exit "Failed to download config from $url (wget)"
        fi
    fi

    # Validate that the downloaded file is valid JSON
    if ! jq empty "$CONFIG_TEMP_FILE" 2>/dev/null; then
        error_exit "Downloaded config is not valid JSON: $url"
    fi

    log_info "Remote config downloaded and validated"
    echo "$CONFIG_TEMP_FILE"
}

# =============================================================================
# JSON CONFIG PARSING (optional)
# =============================================================================
# Config format:
# {
#   "pbsStorage": "auto",                       // auto = first available PBS
#   "targetStorage": "auto",                     // auto = discover available storages
#   "targetStorageMode": "round-robin",          // round-robin or single
#   "force": false,
#   "unique": false,
#   "start": false,
#   "pool": "",
#   "bwlimit": 0,
#   "restorations": [
#     { "enabled": true,  "vmid": 101 },
#     { "enabled": true,  "vmid": 5000 },
#     { "enabled": true,  "notesRegex": "DOCKER-HOST-.*" },
#     { "enabled": false, "notesRegex": "DOCKER-SWARM-.*" }
#   ]
# }

parse_config() {
    local cfg="$1"
    [[ ! -f "$cfg" ]] && error_exit "Configuration file not found: $cfg"

    # Apply config values only if not already set via CLI (CLI takes precedence)
    local val
    val=$(jq -r '.pbsStorage // empty' "$cfg")
    [[ ("$PBS_STORAGE" == "auto" || -z "$PBS_STORAGE") && -n "$val" ]] && PBS_STORAGE="$val"

    val=$(jq -r '.targetStorage // empty' "$cfg")
    [[ ("$TARGET_STORAGE" == "auto" || -z "$TARGET_STORAGE") && -n "$val" ]] && TARGET_STORAGE="$val"

    val=$(jq -r '.targetStorageMode // empty' "$cfg")
    [[ "$TARGET_STORAGE_MODE" == "round-robin" && -n "$val" ]] && TARGET_STORAGE_MODE="$val"

    val=$(jq -r '.force // empty' "$cfg")
    [[ "$FORCE_RESTORE" == "false" && "$val" == "true" ]] && FORCE_RESTORE="true"

    val=$(jq -r '.unique // empty' "$cfg")
    [[ "$UNIQUE_MACS" == "false" && "$val" == "true" ]] && UNIQUE_MACS="true"

    val=$(jq -r '.start // empty' "$cfg")
    [[ "$START_AFTER" == "false" && "$val" == "true" ]] && START_AFTER="true"

    val=$(jq -r '.pool // empty' "$cfg")
    [[ -z "$RESTORE_POOL" && -n "$val" ]] && RESTORE_POOL="$val"

    val=$(jq -r '.bwlimit // empty' "$cfg")
    [[ -z "$BW_LIMIT" && -n "$val" && "$val" != "0" ]] && BW_LIMIT="$val"

    # Build VMID list and notes regex from enabled restorations only
    local vmids_from_cfg notes_patterns
    vmids_from_cfg=$(jq -r '[.restorations[]? | select(.enabled == true and .vmid) | .vmid] | join(",")' "$cfg")
    notes_patterns=$(jq -r '[.restorations[]? | select(.enabled == true and .notesRegex) | .notesRegex] | join("|")' "$cfg")

    # Log skipped (disabled) entries at debug level
    local disabled_count
    disabled_count=$(jq -r '[.restorations[]? | select(.enabled == false)] | length' "$cfg")
    [[ "$disabled_count" -gt 0 ]] && log_debug "Skipped $disabled_count disabled restoration(s) in config"

    [[ -z "$VMID_LIST" && -n "$vmids_from_cfg" ]] && VMID_LIST="$vmids_from_cfg"
    [[ -z "$NOTES_REGEX" && -n "$notes_patterns" ]] && NOTES_REGEX="$notes_patterns"

    log_debug "Config parsed: pbsStorage=$PBS_STORAGE targetStorage=$TARGET_STORAGE targetStorageMode=$TARGET_STORAGE_MODE"
}

if [[ -n "$CONFIG_FILE" ]]; then
    if is_url "$CONFIG_FILE"; then
        CONFIG_FILE=$(fetch_remote_config "$CONFIG_FILE")
    fi
    parse_config "$CONFIG_FILE"
elif [[ -f "${SCRIPT_DIR}/${SCRIPT_NAME}.json" && -z "$VMID_LIST" && -z "$NOTES_REGEX" ]]; then
    # Auto-load co-located config if no selection specified via CLI
    log_info "Auto-loading config: ${SCRIPT_DIR}/${SCRIPT_NAME}.json"
    parse_config "${SCRIPT_DIR}/${SCRIPT_NAME}.json"
fi

# Validate that at least one selection method is provided
if [[ -z "$VMID_LIST" && -z "$NOTES_REGEX" ]]; then
    error_exit "No selection specified. Use --vmids, --notes-regex, or --config. See --help."
fi

# Validate target storage mode
if [[ "$TARGET_STORAGE_MODE" != "round-robin" && "$TARGET_STORAGE_MODE" != "single" ]]; then
    error_exit "Invalid --target-storage-mode '$TARGET_STORAGE_MODE'. Must be 'round-robin' or 'single'."
fi

# =============================================================================
# PBS STORAGE DISCOVERY
# =============================================================================
discover_pbs_storage() {
    local node="$1"
    local pbs_storages
    pbs_storages=$(pvesh get "/nodes/${node}/storage" --output-format json 2>/dev/null | jq -r '
        [.[] | select(.type == "pbs" and .active == 1 and .enabled == 1)] | sort_by(.storage)')

    local count
    count=$(echo "$pbs_storages" | jq 'length')

    if [[ "$count" -eq 0 ]]; then
        error_exit "No active/enabled PBS storage found on node $node"
    fi

    # Always select the first (alphabetically sorted) PBS storage
    local name
    name=$(echo "$pbs_storages" | jq -r '.[0].storage')

    if [[ "$count" -eq 1 ]]; then
        log_info "Auto-detected PBS storage: $name"
    else
        local all_names
        all_names=$(echo "$pbs_storages" | jq -r '.[].storage' | tr '\n' ', ' | sed 's/,$//')
        log_info "Found $count PBS storages ($all_names) — using first: $name"
    fi

    echo "$name"
}

if [[ "$PBS_STORAGE" == "auto" || -z "$PBS_STORAGE" ]]; then
    PBS_STORAGE=$(discover_pbs_storage "$TARGET_NODE")
else
    # Validate the specified PBS storage exists and is active
    local_check=$(pvesh get "/nodes/${TARGET_NODE}/storage" --output-format json 2>/dev/null | \
        jq -r --arg s "$PBS_STORAGE" '[.[] | select(.storage == $s and .type == "pbs" and .active == 1)] | length')
    [[ "$local_check" -eq 0 ]] && error_exit "PBS storage '$PBS_STORAGE' not found or not active on $TARGET_NODE"
    log_info "Using specified PBS storage: $PBS_STORAGE"
fi

# =============================================================================
# TARGET STORAGE DISCOVERY (round-robin pool)
# =============================================================================
declare -a STORAGE_POOL_LIST=()
STORAGE_POOL_INDEX=0

discover_target_storages() {
    local node="$1"
    local content_filter="$2"  # "images" for VMs, "rootdir" for CTs

    pvesh get "/nodes/${node}/storage" --output-format json 2>/dev/null | jq -r --arg cf "$content_filter" '
        [.[] | select(
            .active == 1 and
            .enabled == 1 and
            .type != "pbs" and
            (.content | test($cf))
        )] |
        sort_by(if .type == "dir" then 1 else 0 end, -(.avail // 0)) |
        .[].storage
    '
}

init_storage_pool() {
    local content_type="$1"

    # Explicit storage name (not auto) — use it directly
    if [[ -n "$TARGET_STORAGE" && "$TARGET_STORAGE" != "auto" ]]; then
        STORAGE_POOL_LIST=("$TARGET_STORAGE")
        log_info "Using specified target storage: $TARGET_STORAGE"
        return
    fi

    # Auto-discover available storages
    local storages
    storages=$(discover_target_storages "$TARGET_NODE" "$content_type")

    if [[ -z "$storages" ]]; then
        error_exit "No active/enabled storage found on $TARGET_NODE supporting '$content_type'"
    fi

    mapfile -t STORAGE_POOL_LIST <<< "$storages"

    if [[ "$TARGET_STORAGE_MODE" == "single" ]]; then
        # Single mode: use only the first discovered storage
        STORAGE_POOL_LIST=("${STORAGE_POOL_LIST[0]}")
        log_info "Target storage (single): ${STORAGE_POOL_LIST[0]}"
    else
        # Round-robin mode (default): cycle through all discovered storages
        log_info "Target storage pool (${#STORAGE_POOL_LIST[@]}, round-robin): ${STORAGE_POOL_LIST[*]}"
    fi
}

get_next_storage() {
    local storage="${STORAGE_POOL_LIST[$STORAGE_POOL_INDEX]}"
    STORAGE_POOL_INDEX=$(( (STORAGE_POOL_INDEX + 1) % ${#STORAGE_POOL_LIST[@]} ))
    echo "$storage"
}


# =============================================================================
# BACKUP ENUMERATION AND FILTERING
# =============================================================================
BACKUP_CACHE_FILE=$(mktemp /tmp/pbs-restore-cache.XXXXXX)

fetch_backup_list() {
    local node="$1"
    local storage="$2"

    log_info "Fetching backup list from $storage on $node..."
    pvesh get "/nodes/${node}/storage/${storage}/content" --output-format json 2>/dev/null \
        > "$BACKUP_CACHE_FILE" || error_exit "Failed to fetch backup list from $storage"

    local total
    total=$(jq 'length' "$BACKUP_CACHE_FILE")
    log_info "Found $total total backup(s) on $storage"
}

# Select the latest backup per unique (vmid + notes) combination, filtered by criteria.
# When using --vmids, we pick the latest backup per VMID regardless of notes.
# When using --notes-regex, we pick the latest backup whose notes match, per unique VMID.
# Both can be combined (OR logic): any backup matching either criterion is included.
select_backups() {
    local vmid_filter="$1"    # comma-separated VMIDs or empty
    local notes_filter="$2"   # extended regex or empty

    # Build a jq filter that selects matching backups
    # Then groups by vmid and picks the latest (highest ctime) per group
    local jq_script
    jq_script=$(cat << 'JQEOF'
def matches_vmids($ids):
    if ($ids | length) == 0 then false
    else (.vmid | tostring) as $v | ($ids | any(. == $v))
    end;

def matches_notes($pat):
    if ($pat == "") then false
    else (.notes // "" | test($pat; "i"))
    end;

[.[] | select(
    matches_vmids($vmid_list) or matches_notes($notes_pat)
)] |
group_by(.vmid) |
[.[] | sort_by(-.ctime) | first] |
sort_by(.vmid)
JQEOF
    )

    # Convert comma-separated VMIDs to JSON array
    local vmid_json="[]"
    if [[ -n "$vmid_filter" ]]; then
        vmid_json=$(echo "$vmid_filter" | tr ',' '\n' | jq -R . | jq -s .)
    fi

    jq --argjson vmid_list "$vmid_json" \
       --arg notes_pat "${notes_filter:-}" \
       "$jq_script" "$BACKUP_CACHE_FILE"
}

# =============================================================================
# GUEST EXISTENCE CHECK
# =============================================================================
guest_exists() {
    local vmid="$1"
    qm status "$vmid" &>/dev/null 2>&1 || pct status "$vmid" &>/dev/null 2>&1
}

stop_guest() {
    local vmid="$1"
    local subtype="$2"
    local guest_label
    [[ "$subtype" == "qemu" ]] && guest_label="VM" || guest_label="CT"

    if [[ "$subtype" == "qemu" ]]; then
        local status
        status=$(qm status "$vmid" 2>/dev/null | awk '{print $2}')
        if [[ "$status" == "running" || "$status" == "paused" ]]; then
            log_info "  Stopping $guest_label $vmid (status: $status)..."
            local stop_start=$SECONDS
            qm stop "$vmid" --timeout 120 2>/dev/null || true
            local wait_count=0
            while [[ "$(qm status "$vmid" 2>/dev/null | awk '{print $2}')" != "stopped" ]] && [[ $wait_count -lt 60 ]]; do
                sleep 1
                ((wait_count++))
            done
            log_info "  Stopped $guest_label $vmid in $(format_elapsed $((SECONDS - stop_start)))"
        else
            log_info "  $guest_label $vmid already stopped (status: ${status:-unknown})"
        fi
    elif [[ "$subtype" == "lxc" ]]; then
        local status
        status=$(pct status "$vmid" 2>/dev/null | awk '{print $2}')
        if [[ "$status" == "running" ]]; then
            log_info "  Stopping $guest_label $vmid (status: $status)..."
            local stop_start=$SECONDS
            pct stop "$vmid" 2>/dev/null || true
            local wait_count=0
            while [[ "$(pct status "$vmid" 2>/dev/null | awk '{print $2}')" != "stopped" ]] && [[ $wait_count -lt 60 ]]; do
                sleep 1
                ((wait_count++))
            done
            log_info "  Stopped $guest_label $vmid in $(format_elapsed $((SECONDS - stop_start)))"
        else
            log_info "  $guest_label $vmid already stopped (status: ${status:-unknown})"
        fi
    fi
}

destroy_guest() {
    local vmid="$1"
    local subtype="$2"
    local guest_label
    [[ "$subtype" == "qemu" ]] && guest_label="VM" || guest_label="CT"

    log_info "  Destroying $guest_label $vmid..."
    local destroy_start=$SECONDS

    # Remove protection if set
    if [[ "$subtype" == "qemu" ]]; then
        qm set "$vmid" --protection 0 2>/dev/null || true
        qm destroy "$vmid" --purge 1 2>/dev/null || error_exit "Failed to destroy VM $vmid"
    elif [[ "$subtype" == "lxc" ]]; then
        pct set "$vmid" --protection 0 2>/dev/null || true
        pct destroy "$vmid" --purge 2>/dev/null || error_exit "Failed to destroy CT $vmid"
    fi

    log_info "  Destroyed $guest_label $vmid in $(format_elapsed $((SECONDS - destroy_start)))"
}

# =============================================================================
# RESTORE EXECUTION
# =============================================================================
restore_guest() {
    local volid="$1"
    local vmid="$2"
    local subtype="$3"
    local storage="$4"
    local notes="$5"

    local guest_label
    [[ "$subtype" == "qemu" ]] && guest_label="VM" || guest_label="CT"
    local restore_start=$SECONDS

    log_info "Restoring $guest_label $vmid from $volid -> storage: $storage"
    log_info "  Notes: $notes"

    # Handle existing guest
    if guest_exists "$vmid"; then
        if [[ "$FORCE_RESTORE" == "true" ]]; then
            log_warn "  $guest_label $vmid already exists — force mode enabled, removing"
            stop_guest "$vmid" "$subtype"
            destroy_guest "$vmid" "$subtype"
        else
            log_error "  $guest_label $vmid already exists. Use --force to overwrite."
            return 1
        fi
    fi

    # Build restore command
    local -a cmd_args=()

    if [[ "$subtype" == "qemu" ]]; then
        cmd_args=(qmrestore "$volid" "$vmid")
        cmd_args+=(--storage "$storage")
        [[ "$FORCE_RESTORE" == "true" ]] && cmd_args+=(--force 1)
        [[ "$UNIQUE_MACS" == "true" ]] && cmd_args+=(--unique 1)
        [[ "$START_AFTER" == "true" ]] && cmd_args+=(--start 1)
        [[ -n "$RESTORE_POOL" ]] && cmd_args+=(--pool "$RESTORE_POOL")
        [[ -n "$BW_LIMIT" ]] && cmd_args+=(--bwlimit "$BW_LIMIT")
    elif [[ "$subtype" == "lxc" ]]; then
        cmd_args=(pct restore "$vmid" "$volid")
        cmd_args+=(--storage "$storage")
        [[ "$FORCE_RESTORE" == "true" ]] && cmd_args+=(--force 1)
        [[ "$UNIQUE_MACS" == "true" ]] && cmd_args+=(--unique 1)
        [[ "$START_AFTER" == "true" ]] && cmd_args+=(--start 1)
        [[ -n "$RESTORE_POOL" ]] && cmd_args+=(--pool "$RESTORE_POOL")
        [[ -n "$BW_LIMIT" ]] && cmd_args+=(--bwlimit "$BW_LIMIT")
    else
        log_error "Unknown guest subtype '$subtype' for VMID $vmid"
        return 1
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY RUN] Would execute: ${cmd_args[*]}"
        return 0
    fi

    log_info "  Executing restore for $guest_label $vmid..."
    log_debug "Command: ${cmd_args[*]}"
    if "${cmd_args[@]}"; then
        local elapsed=$((SECONDS - restore_start))
        log_info "  Restore of $guest_label $vmid completed in $(format_elapsed $elapsed)"
        return 0
    else
        local elapsed=$((SECONDS - restore_start))
        log_error "  Restore of $guest_label $vmid failed after $(format_elapsed $elapsed)"
        return 1
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
    log_info "Node:         $TARGET_NODE"
    log_info "PBS Storage:  $PBS_STORAGE"
    log_info "Target Store: $TARGET_STORAGE"
    log_info "Storage Mode: $TARGET_STORAGE_MODE"
    log_info "Force:        $FORCE_RESTORE"
    log_info "Unique MACs:  $UNIQUE_MACS"
    log_info "Start After:  $START_AFTER"
    log_info "Dry Run:      $DRY_RUN"
    [[ -n "$VMID_LIST" ]]      && log_info "VMID Filter:  $VMID_LIST"
    [[ -n "$NOTES_REGEX" ]]    && log_info "Notes Regex:  $NOTES_REGEX"
    [[ -n "$RESTORE_POOL" ]]   && log_info "Pool:         $RESTORE_POOL"
    [[ -n "$BW_LIMIT" ]]       && log_info "BW Limit:     ${BW_LIMIT} KiB/s"
    log_info "=========================================="

    # Fetch all backups from PBS
    fetch_backup_list "$TARGET_NODE" "$PBS_STORAGE"

    # Select backups matching criteria
    log_info "Selecting backups matching criteria..."
    local selected_json
    selected_json=$(select_backups "$VMID_LIST" "$NOTES_REGEX")

    local restore_count
    restore_count=$(echo "$selected_json" | jq 'length')

    if [[ "$restore_count" -eq 0 ]]; then
        log_warn "No backups matched the specified criteria"
        log_info "  VMIDs: ${VMID_LIST:-<none>}"
        log_info "  Notes regex: ${NOTES_REGEX:-<none>}"
        exit 0
    fi

    log_info "Selected $restore_count backup(s) for restoration:"

    # Display selection summary
    echo "$selected_json" | jq -r '.[] | "  VMID \(.vmid) | \(.subtype) | \(.notes // "no notes") | \(.volid)"' | \
        while IFS= read -r line; do log_info "$line"; done

    # Determine content type for storage pool init
    # Check if we have any LXC guests — if so, we need rootdir support
    local has_lxc has_qemu
    has_lxc=$(echo "$selected_json" | jq '[.[] | select(.subtype == "lxc")] | length')
    has_qemu=$(echo "$selected_json" | jq '[.[] | select(.subtype == "qemu")] | length')

    # Initialize storage pool based on guest types
    # For mixed workloads, prefer storages that support both images and rootdir
    if [[ "$has_qemu" -gt 0 && "$has_lxc" -gt 0 ]]; then
        init_storage_pool "images.*rootdir|rootdir.*images"
    elif [[ "$has_lxc" -gt 0 ]]; then
        init_storage_pool "rootdir"
    else
        init_storage_pool "images"
    fi

    # Restore each selected backup
    local success_count=0
    local fail_count=0
    local current=0

    for row in $(echo "$selected_json" | jq -r '.[] | @base64'); do
        current=$((current + 1))
        local volid vmid subtype notes ctime_epoch ctime_human

        volid=$(echo "$row" | base64 -d | jq -r '.volid')
        vmid=$(echo "$row" | base64 -d | jq -r '.vmid')
        subtype=$(echo "$row" | base64 -d | jq -r '.subtype')
        notes=$(echo "$row" | base64 -d | jq -r '.notes // "no notes"')
        ctime_epoch=$(echo "$row" | base64 -d | jq -r '.ctime')
        ctime_human=$(date -u -d "@${ctime_epoch}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "$ctime_epoch")

        local target_storage
        target_storage=$(get_next_storage)

        log_info "------------------------------------------"
        log_progress "$current" "$restore_count" "VMID $vmid ($subtype) | Success: $success_count | Failed: $fail_count"
        log_info "  Backup:  $volid"
        log_info "  Date:    $ctime_human"
        log_info "  Notes:   $notes"
        log_info "  Storage: $target_storage"

        local item_start=$SECONDS
        if restore_guest "$volid" "$vmid" "$subtype" "$target_storage" "$notes"; then
            success_count=$((success_count + 1))
        else
            fail_count=$((fail_count + 1))
        fi
        local item_elapsed=$((SECONDS - item_start))
        log_info "  Item $vmid finished in $(format_elapsed $item_elapsed)"
    done

    # Summary
    local total_elapsed=$((SECONDS - main_start))
    log_info "=========================================="
    log_info "Restoration complete"
    log_info "  Total:      $restore_count"
    log_info "  Successful: $success_count"
    log_info "  Failed:     $fail_count"
    log_info "  Duration:   $(format_elapsed $total_elapsed)"
    log_info "=========================================="

    return $fail_count
}

main