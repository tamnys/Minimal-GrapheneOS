# MP01 signing gate profiles

`audit-signers.py --help` exposes three profiles independently of the preserved
LineageOS signer gate. It reuses the existing immutable target-files snapshot,
APK signature verifier and APEX inspection implementation.

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
