#!/bin/bash
set -euo pipefail
repo_root="$(cd -- "$(dirname -- "$0")/.." && pwd -P)"
workspace="$(dirname -- "$repo_root")"
state="$workspace/.android-build/grapheneos-17-state"
command -v podman >/dev/null || {
    printf '%s\n' 'Install rootless Podman through qube administration; Fedora can remain the host.' >&2
    exit 2
}
mkdir -p "$state/containers" "$state/run" "$state/home" "$state/tmp"
podman_cmd=(podman --root "$state/containers" --runroot "$state/run")
action="${1:-}"
shift || true
if [[ "$action" == build-image && $# == 0 ]]; then
    base_image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["debian_image"])' "$repo_root/grapheneos/inputs.json")"
    "${podman_cmd[@]}" pull "$base_image"
    "${podman_cmd[@]}" build --pull=never --tag localhost/mp01-builder:debian12 \
        --file "$repo_root/grapheneos/Containerfile" "$repo_root/grapheneos"
    "${podman_cmd[@]}" image inspect --format '{{.Id}}' localhost/mp01-builder:debian12 > "$state/builder-image-id"
    exit 0
fi
case "$action" in
    sync|fetch-prebuilts) network=slirp4netns ;;
    preflight|prepare|verify-source|build|audit-signers|audit-avb) network=none ;;
    *) printf '%s\n' 'Usage: grapheneos/container.sh build-image|preflight|fetch-prebuilts|sync|prepare|verify-source|build|audit-signers|audit-avb [arguments]' >&2; exit 2 ;;
esac
image_id="$(cat "$state/builder-image-id")"
[[ "$image_id" =~ ^(sha256:)?[a-f0-9]{64}$ ]] || { printf '%s\n' 'Invalid builder image ID' >&2; exit 2; }
runner=(python3 grapheneos/build.py "$action")
if [[ "$action" == audit-avb ]]; then
    runner=(python3 grapheneos/audit-avb.py)
elif [[ "$action" == audit-signers ]]; then
    runner=(python3 grapheneos/audit-signers.py)
fi
exec "${podman_cmd[@]}" run --rm --pull=never --network="$network" \
    --workdir "/workspace/$(basename -- "$repo_root")" \
    --userns=keep-id --user "$(id -u):$(id -g)" --cap-drop=all \
    --security-opt=no-new-privileges --security-opt=label=disable \
    --read-only --tmpfs /tmp:rw,nosuid,nodev \
    --volume "$workspace:/workspace:rw" \
    --env HOME=/workspace/.android-build/grapheneos-17-state/home \
    --env TMPDIR=/workspace/.android-build/grapheneos-17-state/tmp \
    --env "MP01_BUILDER_IMAGE_ID=$image_id" \
    "$image_id" "${runner[@]}" "$@"
