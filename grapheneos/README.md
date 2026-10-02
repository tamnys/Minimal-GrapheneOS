# MP01 OS: GrapheneOS 17 bring-up

This is an experimental MP01-specific product based on GrapheneOS `2026091900`.
It has not been compiled or booted. It is not an official GrapheneOS release,
does not gain Pixel hardware security, and does not update the installed MP01
kernel, modem or vendor firmware. Changes are submitted through this project's
registered qpublish target.

The pinned upstream manifest contains 1,057 exact project commits, including
toolchains and upstream prebuilts. `inputs.json` also pins the manifest commit,
release tag object, repo tool, Debian image digest, Debian package snapshot,
build timestamp/number, and the official inkOS v0.1 APK URL, size and SHA256.
An explicit download step places the APK in project-local state and verifies
its digest before offline source preparation. The APK is from the
[inkOS v0.1 release](https://github.com/gezimos/inkOS/releases/tag/v0.1),
whose source is tagged `v0.1` at commit
`a578fef2a42ebdccb6cec29449f13b5d6381f332` under GPLv3. The pinned
binary SHA256 is
`64a3cd323ba484640cb0ba6d6d4ad1855048f0460ad852ef1f610439fa6445f8`.
The upstream GrapheneOS release tag's SSH
signature was verified against GrapheneOS's HTTPS-published public
`allowed_signers` file, now pinned by SHA256. Sync repeats that verification
and requires both the exact tag object and manifest commit. No operator SSH
credentials or private signing keys are used for public tag verification.

RestlessOS `d7755a60d2d3f17a64cbe267574c83d6af4e1b2b` is a reference only.
None of its patch stack or private vendor manifest is imported. One patch
excludes Auditor for `TARGET_PRODUCT=mp01`, since supported hardware attestation
is unavailable. The second scopes Android's HOME fallback to the MP01 system
product: after per-user setup completes, it chooses the pinned inkOS home
activity if that system app is installed and no qualified role holder remains.
Before setup, other products, and missing inkOS use upstream behavior. Existing
qualified user-selected home roles are retained. Launcher3QuickStep and its
work-app and all-app actions are unchanged. Both patches have before/after
commits and digests locked in `patches/series.json`; applying them with the
fixed preparation identity reproduces the recorded result commits. Other
GrapheneOS products keep Auditor.

The product inherits upstream GSI layout and GrapheneOS app/framework defaults,
including GmsCompat, Seedvault and Vanadium. Only the existing MP01 services,
keyboard files and byte-pinned inkOS package are imported into the Android
checkout from this repository and its verified project-local prebuilt cache.
The LineageOS product, partner-GMS/microG packages, privileged F-Droid extension,
root integration, permissive-domain patches and network-allow fallbacks are
outside the import list. `OFFICIAL_BUILD` is absent from the build environment,
so GrapheneOS's Updater is excluded. Existing service action names, permission
checks, refresh profiles and defaults logic are preserved. TrebleApp/IMS and
hardware overlay integration still require selective porting and device tests.

The private e-ink socket now replies per command. `OK` means the daemon completed
the target node write; `ERR` covers invalid commands and failed writes. The
init-mediated `clean_a2` and `anti_flicker` properties return `ACCEPTED` only:
the daemon cannot confirm init's later debugfs write, so the Android command
runner does not report those operations as successful. Device validation must
establish an observable result before these controls can pass acceptance.

## Builder

Fedora hosts are supported. Install **rootless Podman** using the normal qube
administration path. Run from the registered `Minimal-GrapheneOS` checkout:

```bash
python3 grapheneos/build.py preflight --phase sync
bash grapheneos/container.sh build-image
bash grapheneos/container.sh preflight --phase sync
bash grapheneos/container.sh fetch-prebuilts
bash grapheneos/container.sh sync
```

The host preflight reports that it is outside the container; it also provides
useful resource measurements. The container recipe uses a digest-pinned Debian
12 image and signed Debian snapshots at `20260919T000000Z`. The date validity
check is disabled for the historical snapshots, while package signature checks
remain enabled. Debian's `repo` launcher comes from the snapshot's `contrib`
component; the full repo implementation is pinned separately to an exact Git
commit and verified after initialization. The exact installed package inventory
is retained in the image. Verify the builder and source-sync preflight in the
selected environment before preparing a full Android build.

Podman storage, source, caches, home, temporary data and logs are project-local.
Only the project workspace is mounted; host credential directories and private
signing material are not mounted. SELinux container labeling is disabled for
this trusted source build so that Podman does not recursively relabel the shared
Fedora workspace; capabilities are dropped and the container root is read-only.
Source sync and the explicit `fetch-prebuilts` step use rootless `slirp4netns`
networking; verification and compilation run with networking disabled. The
prebuilt fetch stores the verified APK at
`.android-build/grapheneos-17-state/prebuilts/inkos_v0.1.apk`; subsequent
offline preparation checks the pinned size and SHA256 before import.
This container is a dependency environment, not a sandbox for untrusted code.
The Android product's SELinux policy is unaffected by host container labeling.

The source checkout is `.android-build/grapheneos-17`. Preparation verifies
every upstream URL, revision and manifest copy/link instruction, hashes tracked
files against their pinned Git trees, rejects hidden index flags and ignored
files, applies only the locked patch series, and exports only committed
hardware files. The prepared graph and hardware-file hashes are written into
a new receipt. Existing independent source commits or modifications stop sync.
Changes to a previously imported hardware layer require preserving and removing
those three imported directories explicitly before preparing again.
Fresh source initialization requests depth-one Git history to bound download
size; exact pinned commits, release-tag signature and source graph are still
verified. Existing full-history projects are not converted to shallow clones.
If a sync is interrupted, the next `sync` retains every completed pinned
project. It finishes only initialized projects whose locked commit is missing
with a depth-one fetch of the manifest's upstream tag, verifies that the tag
resolves to the exact locked commit, and then uses repo's optimized fetch to
skip retained objects. Each recovery fetch has its own transcript and disk
samples. The monitor stops a fetch or sync below the 240 GiB packaging and
reserve floor; incomplete Git `tmp_pack_*` files are not treated as source
commits or removed automatically.

After the pinned source has finished syncing, use the offline preparation command
when a newly locked compatibility patch needs to be applied to that same checkout:

```bash
bash grapheneos/container.sh preflight --phase prepare
bash grapheneos/container.sh prepare
```

`prepare` has no network access and does not run `repo init`, `repo sync` or
`git fetch`. Run `fetch-prebuilts` first if its cache is missing. It checks the
local signed GrapheneOS tag against the pinned
public signer, the manifest and repo tool commits, every project URL and clean
revision, and the expected source layout. It accepts a project only at its
pinned base or at a prefix of the locked patch series, applies the remaining
patches with exact result-commit checks, and writes a new preparation receipt.
Preserve the previous receipt as evidence. An unexpected local commit, edit or
file stops preparation.

Full builds require **32 GiB currently allocated RAM** and 28 GiB available RAM,
with at most four jobs. A configured balloon maximum is not counted as an
allocation. A qube maximum of 48 GiB is preferable to an exact 32 GiB ceiling
because guest overhead reduces usable memory. The source preflight starts at
420 GiB free (180 source + 150 output + 24 packaging + 16 compiler cache + 50
reserve). On a retry, it credits allocated bytes in an initialized checkout
with the pinned manifest and repo tool, up to the 180 GiB source allowance.
Previous `out` files do not count as source. The remaining free-space
requirement never falls below 240 GiB, which is also the floor monitored during
source sync. A build on an already synced tree requires 240 GiB free. These are
conservative budgets, not measured Android 17 peak usage. A disk monitor also
terminates compilation before it consumes the packaging/reserve allowance.
LTO/CFI, hardened_malloc, stack hardening and exec-based spawning are not disabled
to fit this builder.

After a fresh MP01 inventory has been captured with
[`tools/device/inventory.py`](../tools/device/inventory.py) and reviewed using
the [device inventory procedure](../docs/device-inventory.md), use the exact
receipt path printed by the latest successful sync or prepare.
Paths inside the container begin
with `/workspace`:

```bash
bash grapheneos/container.sh build --variant userdebug --jobs 4 \
  --receipt /workspace/.android-build/grapheneos-17-state/prepared-TIMESTAMP.json \
  --device-inventory /workspace/logs/mp01-inventory-TIMESTAMP/inventory.json
```

Use `--variant user` for production-policy testing. Both variants produce only
unsigned/development target-files and otatools. The runner uses fresh output,
captures stdout/stderr, propagates command/log failures, and rechecks the source
graph and hardware layer after compilation. It records the image identity,
dependency inventory digest, source receipt, device inventory digest, resource
samples and output hashes. Preserve previous output before explicitly removing
`out` for another formal build. Increment the locked build timestamp/number for
a second release; do not overwrite a release record.

## Signing gate profiles

See [the signing audit interfaces](SIGNING.md) for development,
initial-installation and upgrade signer checks and the separate returned-image
AVB identity check. Passing either gate never authorizes flashing.

## Outstanding hardware gates

The current vendor contract, recovery route and system partition capacity must
be established on the actual MP01. In particular:

- Validate 32/64-bit vendor ABI requirements, VNDK/VINTF and Android 17 kernel
  capabilities. Do not suppress compatibility checks or silently change base.
- Inspect sysfs/vendor alternatives to `clean_a2` and `anti_flicker` before
  deciding on a production debugfs exception. Existing userdebug-only grants
  are preserved. Production use of those two controls is currently blocked;
  broad debugfs grants or userdebug-wide policy compilation are forbidden.
- Test hardened_malloc address-space requirements, stack hardening, exec-based
  spawning and debugging restrictions against the retained kernel/vendor.
- Complete carrier, encryption, network/VPN, app and update acceptance evidence
  using the [acceptance and handoff checklist](../docs/grapheneos-17-acceptance.md).
- After a clean setup, check inkOS is the HOME role holder; select QuickStep as
  home in Settings, then reboot and update to confirm the choice remains. Check
  that setup still starts normally and a new secondary user's first setup also
  selects inkOS after completion.

No flashing executor is enabled at this stage. The installation procedure must
be finalized from the measured partition/recovery contract and authenticated
signed artifacts. The [device inventory procedure](../docs/device-inventory.md)
records the prerequisites for that work.
