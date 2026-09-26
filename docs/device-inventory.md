# MP01 device inventory and recovery prerequisite

The first GrapheneOS-derived MP01 build needs a fresh read-only inventory of
the **actual MP01**. No phone has been inventoried for this product yet. Capture
on the dedicated device-test qube when the phone is available; the development
qube does not need USB access. Keep the Pixel detached or select the MP01 by
its explicit adb serial. The collector rejects a device whose vendor model is
not `MP01`, including a Pixel. It never roots, reboots, flashes, erases, writes
properties, or writes hardware nodes.

Use a private output directory outside the Git checkout. In the device-test
qube, work from a local copy of this repository and run the collector with an
installed adb executable:

```bash
adb devices -l
python3 tools/device/inventory.py \
  --adb /absolute/path/to/adb \
  --serial MP01_SERIAL \
  --output /private/project-logs/mp01-inventory-TIMESTAMP
```

Replace the placeholders with the selected MP01 serial and paths in that
qube. Use a new output directory for each capture. Its permissions are 0700,
and individual evidence files are 0600. Copy the complete directory back to
project-local private `logs/` using the approved inter-qube transfer path.
Record the source qube, serial, capture time, file hashes, and any transfer
errors. Do not commit raw captures: properties and service output may contain
device or account identifiers.

The JSON report records firmware and vendor fingerprints, Android and security
patch levels, CPU ABI, verified-boot state, encryption properties, partition and
mount information, kernel and VINTF observations, input/display devices, light
nodes, and candidate e-ink interfaces. It captures VINTF fragment XML contents
with their filenames and runs read-only `lpdump` to observe dynamic-partition
metadata when the tool is available. Command exit codes and stderr are retained:
a missing VINTF directory, unavailable `lpdump`, or denied read is a gap to
review, not proof that a capability is absent or that a partition is safe to
flash. A device may legitimately have no ODM VINTF directory or no fragments;
interpret those observations against its vendor layout. The fixed remote
commands are listed in the collector; inspect them before each capture. The
report marks itself `CAPTURED_REQUIRES_REVIEW` because it is evidence to analyze,
not a compatibility or installation verdict.

Before a build, review the report and raw files together. In particular:

1. Confirm the MP01 vendor identity, firmware/kernel baseline, 32/64-bit ABI,
   actual partition and slot layout, available dynamic-partition metadata, image
   capacity, and known recovery route. `lpdump` output alone is not a flash plan.
2. Read the top-level VINTF files and any captured fragments to determine the
   vendor VNDK/VINTF level, kernel requirements, and whether Android 17 can
   satisfy them without skipping compatibility checks.
3. Review encryption, keystore, SELinux, and verified-boot observations. Test
   these properties functionally later; service listings and properties alone
   do not prove they work.
4. Map the actual frontlight, keyboard-light, and display controls. Check
   vendor/sysfs alternatives before considering a narrow init-mediated path
   for `clean_a2` and `anti_flicker`.
5. Preserve matching recovery material and rehearse the non-booting recovery
   procedure before installation. A retained image hash alone is not a tested
   recovery path.

The build runner checks the report's schema, MP01 vendor identity, required
ABI/vendor fields, and hashes of captured evidence. It does **not** establish
that the vendor stack works with the new system. If those fields are absent,
stop and investigate the device rather than editing the report to pass the
gate. AT&T in the USA is the primary cellular target; T-Mobile in the USA is
an additional target when service is available. Neither carrier passes until
on-device calls, messages, data, and sleep/IMS checks are run.

An inventory is not permission to flash. Installation requires an independently
verified signed bundle, exact device and partition checks, and an operator
review of the listed partition operations. Preserve `userdata` and `metadata`
for ordinary updates. A data wipe or clean install requires explicit
confirmation for that particular flashing session.
