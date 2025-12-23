#!/usr/bin/env bash
set -euo pipefail

# --- Config ---
SOURCE_VMID="${SOURCE_VMID:-9004}"          # Full clone source VMID
START_VMID="${START_VMID:-6300}"            # First new VMID
VM_COUNT="${VM_COUNT:-3}"                  # How many VMs to create
NAME_PREFIX="${NAME_PREFIX:-DOCKER-SWARM-NODE-}"
SNAPSHOT_NAME="${SNAPSHOT_NAME:-BeforeFirstBoot}"

# Optional qm clone args:
# STORAGE="${STORAGE:-local-lvm}"           # uncomment if you want to force storage
# FORMAT="${FORMAT:-raw}"                   # optional, depends on storage
# CLONE_EXTRA_ARGS=(--storage "$STORAGE")   # add more qm clone args here
CLONE_EXTRA_ARGS=()

pad4() { printf "%04d" "$1"; }

echo "Cloning $VM_COUNT VM(s) from source VMID=$SOURCE_VMID starting at VMID=$START_VMID ..."
for ((i=0; i<VM_COUNT; i++)); do
  NEW_VMID=$((START_VMID + i))
  VM_NAME="${NAME_PREFIX}$(pad4 "$i")"

  echo "[$((i+1))/$VM_COUNT] qm clone $SOURCE_VMID -> $NEW_VMID (name: $VM_NAME)"
  if qm clone "$SOURCE_VMID" "$NEW_VMID" --full 1 --name "$VM_NAME" "${CLONE_EXTRA_ARGS[@]}"; then
    echo "[$((i+1))/$VM_COUNT] clone OK, creating snapshot '$SNAPSHOT_NAME' on VMID=$NEW_VMID"
    qm snapshot "$NEW_VMID" "$SNAPSHOT_NAME" --description "Baseline snapshot before first boot"
  else
    echo "[$((i+1))/$VM_COUNT] clone FAILED for VMID=$NEW_VMID; skipping snapshot" >&2
  fi
done

echo "Done."
