#!/usr/bin/env python3
"""Capture a read-only MP01 contract. Never root, reboot, flash, or write a node."""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PROPERTIES = [
    'ro.product.vendor.model', 'ro.product.vendor.manufacturer', 'ro.product.vendor.device',
    'ro.product.odm.model', 'ro.product.model', 'ro.product.manufacturer', 'ro.product.device',
    'ro.build.fingerprint', 'ro.vendor.build.fingerprint', 'ro.bootimage.build.fingerprint',
    'ro.build.version.release', 'ro.build.version.sdk', 'ro.build.version.security_patch',
    'ro.vendor.build.security_patch', 'ro.bootimage.build.version.security_patch',
    'ro.vendor.build.version.sdk', 'ro.product.first_api_level', 'ro.board.first_api_level',
    'ro.board.api_level', 'ro.vndk.version', 'ro.vendor.vndk.version',
    'ro.product.cpu.abilist', 'ro.product.cpu.abilist32', 'ro.product.cpu.abilist64',
    'ro.board.platform', 'ro.hardware', 'ro.boot.bootloader', 'ro.boot.verifiedbootstate',
    'ro.boot.flash.locked', 'ro.boot.vbmeta.device_state', 'ro.boot.slot_suffix',
    'ro.boot.dynamic_partitions', 'ro.treble.enabled', 'ro.crypto.state', 'ro.crypto.type',
    'ro.crypto.volume.filenames_mode', 'ro.crypto.volume.metadata.encryption',
    'ro.build.type', 'ro.debuggable', 'ro.secure', 'gsm.version.baseband',
]

# All remote shell text is fixed here, never interpolated from a device response.
COMMANDS = {
    'kernel': ['shell', 'uname -a; cat /proc/version; getconf PAGESIZE'],
    'kernel-config': ['exec-out', 'cat', '/proc/config.gz'],
    'cpu': ['shell', 'cat /proc/cpuinfo'],
    'partitions': ['shell', 'cat /proc/partitions; ls -l /dev/block/by-name /dev/block/bootdevice/by-name'],
    'mounts': ['shell', 'cat /proc/mounts; cat /vendor/etc/fstab* /odm/etc/fstab*'],
    'vintf': ['shell', 'ls -l /vendor/etc/vintf /odm/etc/vintf; cat /vendor/etc/vintf/manifest.xml /vendor/etc/vintf/compatibility_matrix.xml'],
    'hal-services': ['shell', 'lshal'],
    'binder-services': ['shell', 'service list'],
    'selinux': ['shell', 'getenforce; cat /sys/fs/selinux/enforce; id'],
    'input': ['shell', 'cat /proc/bus/input/devices; dumpsys input'],
    'display': ['shell', 'dumpsys display'],
    'lights': ['shell', 'ls -lZ /sys/class/leds; for n in /sys/class/leds/*; do readlink -f "$n"; ls -lZ "$n"/brightness "$n"/max_brightness; cat "$n"/max_brightness; done'],
    'display-nodes': ['shell', "find /sys/devices/platform /sys/class -maxdepth 10 \\( -name clean_a2 -o -name anti_flicker -o -name 'epd_*' -o -name eink_cpld_registers \\) -print"],
    'legacy-display-nodes': ['shell', 'ls -lZ /sys/kernel/debug/eink_debug /sys/kernel/debug/eink_debug/clean_a2 /sys/kernel/debug/eink_debug/anti_flicker'],
    'power': ['shell', 'dumpsys battery; cat /sys/power/state'],
}


class InventoryError(ValueError):
    pass


def run(adb, serial, arguments):
    return subprocess.run([str(adb), '-s', serial, *arguments], capture_output=True, timeout=45)


def identify(adb, serial):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}', serial):
        raise InventoryError('Invalid USB serial')
    values = {}
    for name in ['ro.product.vendor.model', 'ro.product.model', 'ro.product.manufacturer']:
        result = run(adb, serial, ['shell', 'getprop', name])
        if result.returncode:
            raise InventoryError('Cannot read device identity; connect and authorize the selected MP01')
        values[name] = result.stdout.decode('utf-8', errors='strict').strip()
    # Vendor identity survives a system product name. Do not infer an MP01 from
    # MediaTek/arm64 alone, and never fall back to the first attached phone.
    if values['ro.product.vendor.model'] != 'MP01' or 'pixel' in ' '.join(values.values()).lower():
        raise InventoryError('Selected USB device is not an identified MP01; no inventory collected')
    return values


def collect(adb, serial, output):
    identity = identify(adb, serial)
    if output.exists():
        raise InventoryError('Use a new output directory for each capture')
    output.mkdir(parents=True, mode=0o700)
    os.chmod(output, 0o700)
    props = {}
    observations = {}
    for name in PROPERTIES:
        try:
            result = run(adb, serial, ['shell', 'getprop', name])
            props[name] = {'value': result.stdout.decode(errors='replace').strip(),
                           'exit_code': result.returncode,
                           'stderr': result.stderr.decode(errors='replace').strip()}
        except subprocess.TimeoutExpired:
            props[name] = {'error': 'timeout'}
    for name, arguments in COMMANDS.items():
        try:
            result = run(adb, serial, arguments)
            entry = {'command': arguments, 'exit_code': result.returncode}
            for label, data in [('stdout', result.stdout), ('stderr', result.stderr)]:
                filename = name + '.' + label
                path = output / filename
                path.write_bytes(data)
                path.chmod(0o600)
                entry[label] = {'file': filename, 'sha256': hashlib.sha256(data).hexdigest()}
            observations[name] = entry
        except subprocess.TimeoutExpired:
            observations[name] = {'command': arguments, 'error': 'timeout'}
    # Detect a disconnect/replacement before finalizing the capture.
    if identify(adb, serial) != identity:
        raise InventoryError('Device identity changed during capture; evidence is incomplete')
    report = {'schema': 'mp01-device-inventory-v1',
              'captured_at': dt.datetime.now(dt.timezone.utc).isoformat(),
              'serial_sha256': hashlib.sha256(serial.encode()).hexdigest(),
              'identity': identity, 'properties': props, 'observations': observations,
              'cellular_test_targets': [{'carrier': 'AT&T', 'country': 'USA', 'priority': 'primary'},
                                        {'carrier': 'T-Mobile', 'country': 'USA', 'priority': 'additional'}],
              'status': 'CAPTURED_REQUIRES_REVIEW',
              'limitations': ['Read-only observations are not keystore, encryption or VINTF functional tests.',
                              'Missing/denied nodes are unknown, not evidence of unsupported hardware.',
                              'Confirm recovery and partition operations before any installation.']}
    path = output / 'inventory.json'
    path.write_text(json.dumps(report, indent=2) + '\n')
    path.chmod(0o600)
    return path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--adb', type=Path, required=True)
    p.add_argument('--serial', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    try:
        print(collect(args.adb.resolve(), args.serial, args.output.absolute()))
        return 0
    except (InventoryError, OSError, subprocess.TimeoutExpired) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
