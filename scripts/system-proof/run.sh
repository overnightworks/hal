#!/bin/bash
# The container proof of `hal setup`'s system step (#40, cells 1-13), of its secrets step (S1) and of the agents'
# account (#331, cells A1-1 to A1-9), of the mail of `hal check` (#390, cells D1-D8), of rsyslog's removal (#422, cells R0-R7) and of a real Docker engine and the journal as its default log driver (DK1-DK7, #432): a throwaway Ubuntu 26.04 with systemd as PID 1, never the live PC, never the
# real /etc or ~/.secrets.
#
#   flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \
#       scripts/system-proof/run.sh <edge checkout> <evidence dir> <part>
#
# <part> is `fresh` (the first container: install, fresh, both reboots and their stages), `prepared` (the second:
# install, prepared, both sudos) or `shapes` (the third: one convergence, then the foreign account shapes of A1-3); each
# call runs and judges only its own container's cells. <edge checkout> is a clone whose `origin/main` (or $EDGE_REF)
# carries tunnel/; only `git archive` reads it. Give each part its own evidence dir (`<evidence dir>/fresh`,
# `<evidence dir>/prepared`, `<evidence dir>/shapes`): each call truncates cells.txt and containers.txt there.
# The script takes no lock: the fleet form above does. CAP 1800 plus K 30 stays within 1830, and K 30 is more than the
# teardown of a cut run needs (it left no container within 30 s). Measured under that form on a loaded machine, in
# seconds after the lock was taken: `shapes` 881, `fresh` 924, `prepared` 383, each exit 0 with every cell held. The
# slowest part keeps 876 s of the 1800 s cap, 576 s of the 1500 s a part may take. The wait for a low load and every
# stage run inside the cap, so the cap bounds them, and the EXIT trap runs on its TERM.
# It keeps the container ids in the evidence dir and removes its container, with its volumes and nothing else, on exit.
# The sudo password is generated per run.
set -euo pipefail

edge_checkout=${1:?the edge checkout to read tunnel/ from}
evidence=${2:?the directory for the evidence}
part=${3:?the part to run: fresh, prepared or shapes}
case $part in
    fresh | prepared | shapes) ;;
    *) echo "usage: run.sh <edge checkout> <evidence dir> <fresh|prepared|shapes>" >&2; exit 2 ;;
esac
edge_ref=${EDGE_REF:-origin/main}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(git -C "$here" rev-parse --show-toplevel)
image=home-tools-system-proof
mkdir -p "$evidence"

until LC_ALL=C awk -v cores="$(nproc)" '{ exit !($1 <= 1.5 * cores) }' /proc/loadavg; do sleep 30; done

context=$(mktemp -d)
: >"$evidence/containers.txt"
cleanup() {  # the logs of every container are copied out first, so a failing proof keeps its evidence
    local container name
    while read -r container; do
        name=$(docker inspect --format '{{.Name}}' "$container" 2>/dev/null) || name=$container
        docker cp "$container:/proof/evidence" "$evidence/${name#/}" >/dev/null 2>&1 || true
        docker rm --force --volumes "$container" >/dev/null 2>&1 || true
    done <"$evidence/containers.txt"
    rm -rf "$context"
}
trap cleanup EXIT

mkdir -p "$context/context"
(cd "$repo" && timeout 300 uv build --wheel --out-dir "$context/context" >/dev/null)
git -C "$edge_checkout" archive "$edge_ref" tunnel | tar -x -C "$context/context"
cp "$here/Dockerfile" "$context/"
cp "$here/drive.sh" "$here/terminal.exp" "$context/context/"
timeout 1800 docker build --quiet --tag "$image" "$context" >/dev/null

password=$(head -c 18 /dev/urandom | base64 | tr -d '/+=')

wait_for_boot() {  # wait_for_boot <container>: until systemd reports running or degraded (units may have failed)
    # `is-system-running --wait` exits 1 at once while PID 1 has no bus yet, so it cannot be the wait: after a
    # restart it returned before the boot began, and the proof then read a system no unit had started in.
    local container=$1
    timeout 120 docker exec "$container" bash -c \
        'until [[ $(systemctl is-system-running 2>/dev/null) =~ ^(running|degraded)$ ]]; do sleep 1; done'
    return
}

start_container() {  # start_container <name>: systemd as PID 1, the tester's password set for this run only
    local name=$1 container
    # The engine inside stores its images and its snapshots in anonymous volumes: overlay does not work on overlay. cleanup removes both with the container.
    container=$(docker run --detach --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock --tmpfs /tmp \
        --volume /var/lib/docker --volume /var/lib/containerd \
        --name "home-tools-system-proof-$name-$$" "$image")
    echo "$container" >>"$evidence/containers.txt"
    wait_for_boot "$container"
    printf 'tester:%s\n' "$password" | docker exec --interactive "$container" chpasswd
    echo "$container"
}

stage() {  # stage <container> <name>: one stage of drive.sh, its cell lines on stdout and in the evidence
    local container=$1 name=$2
    # The value reaches the container from docker's own environment, never from its arguments.
    PROOF_PASSWORD="$password" timeout 3600 docker exec --env PROOF_PASSWORD "$container" /proof/drive.sh "$name" \
        | tee -a "$evidence/cells.txt"
}

reboot() {
    local container=$1
    timeout 120 docker restart "$container" >/dev/null
    wait_for_boot "$container"
}

: >"$evidence/cells.txt"
container=$(start_container "$part")
stage "$container" install
if [[ $part == fresh ]]; then
    stage "$container" fresh
    reboot "$container"
    stage "$container" after-marker-reboot
    reboot "$container"
    stage "$container" after-unmarked-reboot
elif [[ $part == prepared ]]; then
    stage "$container" prepared
    stage "$container" sudo-classic
    stage "$container" sudo-rs
else
    stage "$container" shapes
fi

judge() {  # judge <part> <cells file>: every cell of the part printed a held line and none printed a failed one
    # fresh: cells 1, 3-13 and 7o, S1, A1-1 and A1-2 and A1-4 to A1-9, D1-D8, R0-R7, DK1-DK7, T1-T5, T5b; prepared: cell 2 and P1-P10 under both sudos (suffix c and r); shapes: A1-3
    local part=$1 cells=$2 cell missing=() expected
    case $part in
        fresh) expected=({1,3,4,5,6,7,7o,8,9,10,11,12,13} S1 A1-{1,2,4,5,6,7,8,9} D{1..8} R{0..7} DK{1..7} T{1..5} T5b) ;;
        prepared) expected=(2 P{1..10}{c,r}) ;;
        shapes) expected=(A1-3) ;;
        *) echo "unknown part: $part (expected fresh, prepared or shapes)" >&2; return 2 ;;
    esac
    for cell in "${expected[@]}"; do
        grep -q "^cell $cell: held: " "$cells" || missing+=("$cell")
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "no held line for cell(s): ${missing[*]}" >&2
        return 1
    fi
    if grep -q ': FAILED: ' "$cells"; then
        grep ': FAILED: ' "$cells" >&2
        return 1
    fi
    return 0
}

judge "$part" "$evidence/cells.txt"
