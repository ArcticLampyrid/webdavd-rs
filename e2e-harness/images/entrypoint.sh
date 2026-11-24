#!/usr/bin/env bash
# Boot the guest VM in /vm/base.qcow2, wait until it powers off, and report the result.
#
# Input:
#   /payload/seed/        cloud-init seed (meta-data, user-data), given to the guest as a "cidata" ISO.
#
# Environment:
#   E2E_HTTP_SOCKET       Unix socket of the harness HTTP server (necessary).
#   E2E_HTTP_GUEST_ADDR   guest address that forwards to E2E_HTTP_SOCKET, e.g. 10.0.2.100:8000 (necessary).
#   E2E_TIMEOUT           seconds from boot to power-off (default: 600).
#   E2E_EXTRA_DISKS       comma-separated sizes of blank virtio data disks, e.g. "128M,350M".
#   E2E_ALLOW_TCG         set to 1 to use software emulation if /dev/kvm is not available.
#   E2E_VM_MEMORY         guest memory in MiB (default: 2048).
#   E2E_VM_CPUS           number of guest CPUs (default: 2).
#   E2E_STREAM_CONSOLE    set to 1 to copy the guest console to stdout while the guest runs.
#
# Exit status:
#   0 if the guest printed the line "E2E_HARNESS_EXIT:0" on its serial console,
#   then powered off in time. Else 1, and the guest console goes to stderr
#   (if it did not go to stdout already).
#
# The guest gets no access to the container filesystem: the root disk is a
# copy-on-write overlay. The guest has the network of the container through
# QEMU user networking (NAT), and nothing can connect to the guest.
set -euo pipefail

readonly CONSOLE=/tmp/console.log
readonly OVERLAY=/tmp/overlay.qcow2
readonly SEED_ISO=/tmp/seed.iso
readonly TIMEOUT=${E2E_TIMEOUT:-600}
# Printed by the runner in the guest (see e2e-harness/src/cloud_init.rs).
readonly SENTINEL=E2E_HARNESS_EXIT

log() {
    echo "entrypoint: $*" >&2
}

# Print the guest console, then exit with an error.
fail() {
    log "$*"
    if [[ -f $CONSOLE && ${E2E_STREAM_CONSOLE:-0} != 1 ]]; then
        log "guest console:"
        cat "$CONSOLE" >&2
    fi
    exit 1
}

qemu_args=(
    -nodefaults
    -display none
    # The Debian kernel does not boot without a display adapter.
    -vga std
    # A reboot ends the run: the guest must power off.
    -no-reboot
    -m "${E2E_VM_MEMORY:-2048}"
    -smp "${E2E_VM_CPUS:-2}"
    -serial "file:$CONSOLE"
)

add_accelerator() {
    if [[ -c /dev/kvm && -w /dev/kvm ]]; then
        qemu_args+=(-accel kvm -cpu host)
    elif [[ ${E2E_ALLOW_TCG:-0} == 1 ]]; then
        log "/dev/kvm is not available, use software emulation (slow)"
        qemu_args+=(-accel tcg -cpu max)
    else
        fail "/dev/kvm is not available: run the container with --privileged, or set E2E_ALLOW_TCG=1"
    fi
}

# The root disk is first, so it is vda (Linux) or vtbd0 (FreeBSD).
add_disks() {
    local -a sizes
    local i
    qemu-img create -q -f qcow2 -F qcow2 -b /vm/base.qcow2 "$OVERLAY"
    qemu_args+=(-drive "file=$OVERLAY,if=virtio,format=qcow2")

    IFS=, read -r -a sizes <<<"${E2E_EXTRA_DISKS:-}"
    for i in "${!sizes[@]}"; do
        qemu-img create -q -f raw "/tmp/disk$i.raw" "${sizes[i]}"
        qemu_args+=(-drive "file=/tmp/disk$i.raw,if=virtio,format=raw")
    done

    genisoimage -quiet -output "$SEED_ISO" -volid cidata -joliet -rock /payload/seed
    qemu_args+=(-drive "file=$SEED_ISO,if=ide,media=cdrom,format=raw")
}

# Each guest connection to E2E_HTTP_GUEST_ADDR starts one socat to the harness server.
add_network() {
    [[ -n ${E2E_HTTP_SOCKET:-} && -n ${E2E_HTTP_GUEST_ADDR:-} ]] \
        || fail "E2E_HTTP_SOCKET and E2E_HTTP_GUEST_ADDR are necessary"
    [[ -S $E2E_HTTP_SOCKET ]] || fail "$E2E_HTTP_SOCKET is not a socket"
    local netdev="user,id=n0"
    netdev+=",guestfwd=tcp:$E2E_HTTP_GUEST_ADDR-cmd:socat STDIO UNIX-CONNECT:$E2E_HTTP_SOCKET"
    # No option ROM: the guest boots from disk, not from the network.
    qemu_args+=(-netdev "$netdev" -device "virtio-net-pci,netdev=n0,romfile=")
}

# The status in the last sentinel line of the console, or nothing.
guest_status() {
    { grep -aoE "^$SENTINEL:[0-9]+" "$CONSOLE" || true; } | tail -n 1 | cut -d: -f2
}

trap 'exit 143' TERM
trap 'exit 130' INT

add_accelerator
add_disks
add_network

log "boot guest (time limit ${TIMEOUT}s)"
# In the background, so that the traps work while QEMU runs.
timeout --kill-after=10 "$TIMEOUT" qemu-system-x86_64 "${qemu_args[@]}" &
qemu_pid=$!
if [[ ${E2E_STREAM_CONSOLE:-0} == 1 ]]; then
    # tail stops after QEMU, when it has copied the last output.
    tail --follow=name --retry --pid="$qemu_pid" "$CONSOLE" 2>/dev/null &
    tail_pid=$!
fi
qemu_status=0
wait "$qemu_pid" || qemu_status=$?
[[ -z ${tail_pid:-} ]] || wait "$tail_pid" || true

case $qemu_status in
    124 | 137) fail "the guest did not power off in ${TIMEOUT}s" ;;
esac
status=$(guest_status)
[[ -n $status ]] || fail "the guest stopped without a result (QEMU exit status $qemu_status)"
[[ $status == 0 ]] || fail "a step failed with exit status $status"
log "all steps passed"
