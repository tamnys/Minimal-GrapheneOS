# MP01 production acceptance and phone handoff

All rows below are **NOT RUN** on GrapheneOS-derived MP01 software. A host unit
test, source review or an audit of another image does not change that status.
Record the exact signed release, source/audit digests, vendor/kernel baseline,
device inventory, date, carrier, test steps and evidence for every result. The
[device inventory procedure](device-inventory.md) records the initial hardware
contract but does not pass these functional checks.
Use the production `mp01-cur-user` build for acceptance. Keep the unlocked
bootloader limitation explicit; do not claim Pixel-equivalent verified boot,
hardware attestation, firmware support or rollback protection.

## Device and security matrix

| Area | Required checks and evidence |
| --- | --- |
| Boot/recovery | Repeated cold boots; boot timing; recover a non-booting system using matching material; record any untested recovery limitation |
| Keyboard | Every physical key, symbol, modifier, long press and existing shortcut; correct system-owned map without FinQwerty |
| Display | Refresh-button single/double press, each named refresh mode, per-app profiles, manual full refresh, contrast and threshold controls |
| Lighting | Warm/cool frontlight and keyboard light across full supported ranges; invalid values denied; failures reported |
| Setup/defaults | inkOS selection and light defaults; repeated boot, app upgrade and restored settings must not overwrite user choices |
| Power | Suspend/resume, charging, overnight standby, wake notifications and battery baseline |
| Hardware | Audio, camera, Wi-Fi, Bluetooth, available sensors and biometrics; document actual missing features |
| AT&T USA | Calls, SMS, MMS with attachments, mobile data, IMS/VoLTE and incoming calls after extended sleep |
| T-Mobile USA | Repeat the same carrier matrix when that SIM/service is available; do not infer success from AT&T results |
| Encryption | Encrypted userdata across reboot; credential-protected storage unavailable before unlock; metadata encryption behavior recorded accurately |
| Keystore | Key creation, encryption/signing, reboot persistence and authentication-bound use; report actual TEE/StrongBox availability |
| SELinux | Enforcing at boot and after workloads, no permissive domains, no broad debugfs exception, inspect denials without suppressing them indiscriminately |
| E-ink access | Unprivileged app and shell cannot control private socket/properties/nodes; only authorized service works; unrelated debugfs and direct daemon access remain denied |
| Network | Per-app denial and VPN lockdown on IPv4 and IPv6; reboot, VPN failure, reconnect and kernel/BPF failure paths cannot silently allow traffic |
| Framework privacy | Storage Scopes, Contact Scopes, profiles, sandboxed Play and app permission controls behave as intended |
| Hardening | hardened_malloc, hardened stacks, exec-based app spawning and native debugging restrictions tested against actual kernel/vendor; exceptions record component, failure, lost protection and regression coverage |
| VINTF/compatibility | Scoped CTS/VTS and system/vendor compatibility; no skipped security test is recorded as a pass |
| Display privacy | Lock/shutdown frame and retained sensitive content after suspend/crash/power loss; document physical e-ink limitations |
| Updates | Two consecutive project-signed releases, same public project keys, apps/messages/settings/authentication preserved after USB update |
| Stability | Overnight standby and seven supervised days with crashes, battery drain, missed calls/notifications and display failures compared against baseline |

The two debugfs-backed controls require a device-specific interface decision.
First record all supported sysfs/vendor alternatives. If none exists, add an
MP01-only init-mediated exception for exactly `clean_a2` and `anti_flicker` with
production policy and on-device negative access tests. Do not compile all
SELinux policy as userdebug, disable neverallows or grant a generic debugfs
type. The existing daemon's permission checks and protocol names must remain
compatible; a successful property write alone is not a successful hardware
operation.

## App compatibility

| App | MP01 production result | Handoff mechanism to verify |
| --- | --- | --- |
| Signal | NOT RUN | Pixel primary, MP01 linked phone; history/media and companion limitations; independent recovery backup |
| WhatsApp | NOT RUN | Pixel primary, MP01 companion; historical media, inactivity and primary-device requirements |
| WeChat | NOT RUN | Native migration in both directions; messages, attachments, authentication and repeated transfers |
| Telegram | NOT RUN | Cloud synchronization and sessions; explicitly inventory nonportable Secret Chats/local-only state |
| Messenger | NOT RUN | Secure Storage access/recovery and history on both phones |
| SMS/MMS | NOT RUN | Provider export/import both ways; deduplication, new messages, attachments and subscription handling; RCS outside initial scope |
| Found | NOT RUN | Independent MP01 enrollment/access; use Pixel if unsupported |
| PayPal | NOT RUN | Independent MP01 enrollment/access; use Pixel if unsupported |
| Robinhood | NOT RUN | Independent MP01 enrollment/access; use Pixel if unsupported |
| Venmo | NOT RUN | Independent MP01 enrollment/access; use Pixel if unsupported |

Do not transfer hardware-bound credentials by copying app directories. Keep
financial enrollment and account recovery separate from message migration.
Record exact app versions and signing identities so updates do not mix
incompatible distributions. App-level mechanisms and account policies must be
verified during testing; the table is a test plan, not a portability claim.

## Recurring handoff procedure to measure

The target is **15–30 minutes after the initial archive transfer**. Keep the
Pixel as the initial Signal/WhatsApp primary. A custom migration application
and automatic OS OTA are deferred.

1. Unlock both phones, check their backup/recovery state, and record the start
   time. Complete an independent backup before any app migration that replaces
   history. Inventory unsynchronized new messages and local-only data.
2. Let linked/synchronized apps catch up. Verify Signal, WhatsApp, Telegram and
   Messenger with recent sent/received messages and attachments. Record all
   companion-device or history limitations rather than assuming parity.
3. Use the tested native WeChat migration and tested SMS/MMS export/import
   procedure. Verify message counts, duplicates, attachment samples and newly
   received content. Do not restore a stale database over newer history.
4. Move the SIM, verify calling/SMS/data and the carrier's IMS state on the
   destination, and check notifications after sleep. Account registration and
   primary/linked roles need not follow the physical SIM automatically.
5. Verify passwords/authentication using supported app mechanisms and the
   separately enrolled financial apps. Keep unsupported financial apps on the
   Pixel with working independent account recovery.
6. Record the end time, remaining gaps and both phones' backup status. Keep the
   standby primary accessible as required by the tested app versions.

Complete **two full round trips**. Create new messages on each phone between
transfers and repeat at least one SMS/MMS import to test deduplication. Include
attachments and nonportable-history cases. Neither a one-way migration nor
initial account login is sufficient evidence.

| Trial | Pixel → MP01 time/result | New MP01 messages verified | MP01 → Pixel time/result | New Pixel messages verified | Duplicate/attachment evidence |
| --- | --- | --- | --- | --- | --- |
| Round trip 1 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |
| Round trip 2 | NOT RUN | NOT RUN | NOT RUN | NOT RUN | NOT RUN |

For the seven-day supervised trial, record each day's standby duration,
battery start/end, calls/SMS expected/received, message notification delays,
crashes and display issues. Mark the build ready only after production policy,
recovery, data-preserving update and handoff gates pass. Track GrapheneOS stable
rebases separately from vendor/kernel maintenance; the Pixel's official updates
remain independent of the MP01 release schedule.
