# MP01 signing gate profiles

`audit-signers.py --help` exposes three profiles independently of the preserved
LineageOS signer gate. It reuses the existing immutable target-files snapshot,
APK signature verifier and APEX inspection implementation.
Run it through the pinned builder with networking disabled, for example
`bash grapheneos/container.sh audit-signers --help`. A candidate invocation
must supply the signed target-files, the independently authenticated public
policy SHA256, a trusted vendor-baseline SHA256, otatools, the direct Java and
apksigner JAR paths with their pinned SHA256 values, and a new output path.
For an upgrade, also supply the independently authenticated previous report
and its SHA256. The builder wrapper does not supply any trust anchor or private
release key.

| Profile | Meaning |
| --- | --- |
| `development` | Inventory and verify package signatures; never a release baseline |
| `initial-installation` | Require a `user` build and exact new project public signing policy, without comparing against LineageOS |
| `upgrade` | Additionally require the trusted prior MP01 report, same installed signer identities, advancing build time, no SDK/package downgrades, and the same vendor baseline |

Signer reports use `mp01-signer-profile-v2`. APK identities record both
`version_code` and `version_code_major` from the compiled manifest; upgrade
checks compare [Android's combined long version code](https://developer.android.com/reference/android/content/pm/PackageInfo#getLongVersionCode()). A v1 report lacks the
major version evidence and cannot be an upgrade baseline. The public signer
manifest v2 likewise records the major code; historical v1 manifests remain
readable for comparison but do not establish release continuity.

These are **signer gates**, not full artifact audits or flash authorizations.
Every report sets `flash_authorized: false`. Image filesystem/AVB consistency,
framework security configuration, encryption, enforcing SELinux, vendor
compatibility and hardware results remain independent release requirements.
A whole-artifact GrapheneOS release auditor has not yet been implemented. The
signer and AVB checks here are deliberately narrower and cannot by themselves
qualify an image for installation.

The inherited GSI board configuration names AOSP test AVB keys for `system`
and `boot` (`build/make/target/board/BoardConfigGsiCommon.mk`). Those defaults
may appear in unsigned target-files and are **not** project release keys.
The separate signing environment must explicitly replace every applicable AVB
key when producing a release. Before an initial-installation or upgrade
candidate can be approved, the release audit must verify the returned image's
AVB footer/hashtree and compare its actual public key with independently
authenticated project public material. Rewritten `META/misc_info.txt` paths or
a passing APK/APEX signer gate do not establish that image identity.

`audit-avb.py` is a separate, fail-closed check for a **returned signed**
`system.img`. Run it in the pinned Debian builder with an independently
authenticated image SHA256, project AVB public-key **blob** SHA256 and avbtool
SHA256. The tool must be the pinned `external/avb/avbtool.py` from the source
graph. The expected public-key digest is over avbtool's binary
`extract_public_key` output, not a PEM file or APK certificate. For example:

```bash
bash grapheneos/container.sh audit-avb \
  --image /workspace/releases/SIGNED/system.img \
  --image-sha256 EXPECTED_SIGNED_IMAGE_SHA256 \
  --expected-public-key-sha256 AUTHENTICATED_PROJECT_AVB_KEY_SHA256 \
  --avbtool /workspace/.android-build/grapheneos-17/external/avb/avbtool.py \
  --avbtool-sha256 PINNED_AVBTOOL_SHA256 \
  --output /workspace/releases/SIGNED/avb-audit.json
```

The checker makes private snapshots, requires a signed AVB footer and one
`system` SHA256 hashtree, rejects disabled verification flags and known bundled
AVB test keys, verifies the image with avbtool, and compares the embedded key
to the supplied project key digest. Its report always has
`flash_authorized: false`. The caller must authenticate the expected digests
outside the candidate bundle; typing hashes calculated from the candidate is
not a trust anchor. This image-level check does not establish the whole-bundle
vbmeta chain, device boot-chain trust, rollback protection,
image-to-target-files consistency, or installation approval. Those remain
whole-artifact and on-device release gates.

Create persistent private release keys in the separate signing environment.
Only public policy and returned signed artifacts belong here. The public policy
schema is `mp01-signing-policy-v1`, with `product: mp01`, a nonempty
`project_certificates` array of SHA256 certificate digests and an exhaustive
`packages` object keyed by `apk:PACKAGE` / `apex:PACKAGE`. Every entry contains
`authority` (`project` or `upstream-presigned`), `signer_cert_sha256`,
`container_cert_sha256`, `payload_pubkey_sha256`, and `file_sha256`. APK-only
container/payload fields are `-`; `file_sha256` is null for project-signed
packages and an exact upstream archive digest for presigned packages. The
Android platform must be project-signed. The ten pinned upstream public Android
test certificates are rejected for candidates. The policy's hash and previous
report's hash must arrive through authenticated release metadata, independently
of the candidate bundle; computing a hash from an untrusted adjacent file does
not establish trust. No project release policy or private key is created here.

## Release bundle integrity binding

`audit-bundle.py` is a separate, host-side integrity gate. It needs only Python
standard-library modules and may run before the MP01 is connected. Arrange a
candidate directory with `bundle-manifest.json` and the files named in that
manifest. Obtain the manifest's SHA256 through authenticated release metadata
**outside** that directory; calculating the expected hash from the candidate
directory itself does not authenticate it. The trusted manifest then pins each
artifact's exact SHA256. Use a new report path:

```bash
python3 grapheneos/audit-bundle.py \
  --bundle-root /private/mp01-release-candidate \
  --manifest-sha256 AUTHENTICATED_MANIFEST_SHA256 \
  --output /private/mp01-reports/bundle-binding.json
```

The manifest schema is `mp01-bundle-binding-v1`, with exactly `schema`,
`profile` (`initial-installation` or `upgrade`), and `artifacts`. Every artifact
entry has exactly `path` and lowercase `sha256`. Paths are relative to the
candidate directory, are ordinary files, and cannot traverse symlinks or `..`.
The following artifact roles are required:

| Role | Bound evidence |
| --- | --- |
| `signed_target_files`, `system_image` | Returned signed target-files and standalone `system.img`; the ZIP's `IMAGES/system.img` must hash identically to the standalone image |
| `unsigned_target_files`, `build_provenance` | Original unsigned build output and the formal build result that hashes it |
| `signer_report`, `avb_report` | Passing release-profile package signer report and signed-system AVB report; both must name the same signed image and set `flash_authorized: false` |
| `source_receipt`, `source_lock`, `prepared_manifest` | Preparation receipt, locked `grapheneos/inputs.json`, and the receipt's prepared `.xml` file |
| `signing_policy`, `vendor_baseline` | Public policy and vendor-baseline document named by the signer report's digests |

For `upgrade`, add `previous_signer_report`; the current signer report must
name its SHA256. The gate also checks the MP01 `user` build identity, the source
receipt and build provenance link, and the build timestamp across provenance
and signed target-files. Duplicate JSON keys, unexpected manifest fields,
artifact substitution, path traversal and inconsistent cross-report hashes
fail closed. The report records all verified hashes and always sets
`flash_authorized: false`.

This is **integrity and evidence binding only**. An authenticated manifest
binds bytes but does not independently prove that the signer or AVB tools ran,
validate the full AVB chain, attest the source or signing environment, inspect
the complete image filesystem, prove vendor compatibility, or confirm that an
image matches the installed MP01. Keep the original signer and AVB reports,
independent trust material and device results. A complete release audit and
device-specific installation approval are still required before flashing.
