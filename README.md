# Minimal-GrapheneOS

Minimal-GrapheneOS is an independent, experimental Android OS project for the
MP01. It adapts GrapheneOS's Android 17 source to the phone's physical keyboard,
e-ink display, and lighting hardware. The aim is an MP01 that keeps its distinctive
controls and inkOS experience while gaining the privacy, app isolation, and
supported hardening of a GrapheneOS-derived system. This is not an official
GrapheneOS release.

## Design

The project starts from GrapheneOS release `2026091900`. An exact source lock,
small compatibility patch set, and MP01 hardware layer keep upstream changes
separate from device-specific work. RestlessOS is a compatibility reference,
not the product base. Project code and build definitions live in this repository;
the locked GrapheneOS source and official inkOS release are external inputs.

The MP01 product uses the phone's existing kernel and vendor firmware. Its
hardware layer covers keyboard mappings, e-ink refresh controls and profiles,
frontlight and keyboard lighting, and the inkOS home experience. The integration
is designed to preserve existing app permissions and later user choices. The
product is configured to retain GrapheneOS's app and framework components where
supported, including sandboxed Play compatibility, profiles, backup integration,
and Vanadium. It excludes root integration, microG, signature spoofing, and a
privileged F-Droid extension.

Source preparation and builds use a pinned Debian 12 container with project-local
inputs and logs. Release signing is separate from the development environment.
The initial update design uses verified, computer-assisted USB installation of
project-signed releases; automatic OS updates are a later goal.

## Aims

The production target is an encrypted, unrooted, SELinux-enforcing `user` build
with working calls, messaging, networking, power management, and MP01 controls.
Release acceptance requires testing on the actual device, including app privacy
controls, carrier behavior, recovery, and a data-preserving update between two
signed releases. The project also documents app migration and phone handoff
procedures, including compatibility limits and independent account recovery.

The MP01's unlocked bootloader and existing vendor firmware limit the security
claims this project can make. Device-specific compatibility and security results
are recorded as evidence, rather than assumed from GrapheneOS support on Pixel
devices.

For implementation and validation details, see the [source and build workflow](grapheneos/README.md),
[MP01 device inventory](docs/device-inventory.md),
[signing and image audits](grapheneos/SIGNING.md), and
[production acceptance and phone handoff](docs/grapheneos-17-acceptance.md).
