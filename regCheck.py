#!/usr/bin/env python3
"""
Simple one-shot registry scanner: scans a hive/subpath once and prints each key visited with its LastWriteTime (UTC).

Defaults: HKLM\SOFTWARE. Run elevated to inspect HKLM fully. The script is read-only to the registry.

Usage (PowerShell):
  python .\regCheck.py

To adjust the scanned hive/subpath, edit the constants below or import and call `scan_once(hive_name, subpath)`.
"""

from __future__ import annotations
import sys
import winreg
from datetime import datetime, timezone
from typing import Optional

# Simple defaults
DEFAULT_HIVE = "HKLM"
DEFAULT_SUBPATH = "SOFTWARE"

# FILETIME epoch difference: number of 100-ns intervals between 1601-01-01 and 1970-01-01
_EPOCH_AS_FILETIME = 116444736000000000


def filetime_to_datetime(ft: int) -> datetime:
    try:
        ft = int(ft)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    if ft <= 0:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    us = (ft - _EPOCH_AS_FILETIME) / 10
    sec = us / 1_000_000
    return datetime.fromtimestamp(sec, tz=timezone.utc)


def hive_root_from_name(name: str):
    mapping = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
        "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
        "HKCR": winreg.HKEY_CLASSES_ROOT,
        "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
        "HKU": winreg.HKEY_USERS,
        "HKEY_USERS": winreg.HKEY_USERS,
    }
    key = mapping.get(name.upper())
    if key is None:
        raise ValueError(f"Unknown hive name: {name}")
    return key


def scan_once(hive_name: str = DEFAULT_HIVE, subpath: str = DEFAULT_SUBPATH, max_depth: Optional[int] = None):
    """Scan the hive/subpath once and print each key visited and its LastWriteTime (UTC)."""
    hive = hive_root_from_name(hive_name)

    # helper: try common registry view/access flags (64-bit, 32-bit, default)
    def open_key_try_views(hive_const, path):
        key_read = winreg.KEY_READ
        wow64_64 = getattr(winreg, "KEY_WOW64_64KEY", 0)
        wow64_32 = getattr(winreg, "KEY_WOW64_32KEY", 0)
        candidates = []
        if wow64_64:
            candidates.append(key_read | wow64_64)
        if wow64_32:
            candidates.append(key_read | wow64_32)
        # lastly, try the default KEY_READ
        candidates.append(key_read)

        last_exc = None
        for access in candidates:
            try:
                return winreg.OpenKey(hive_const, path, 0, access)
            except FileNotFoundError:
                # path doesn't exist in this view — bubble this up explicitly
                raise
            except Exception as e:
                last_exc = e
                continue
        if last_exc:
            raise last_exc

    try:
        root = open_key_try_views(hive, subpath)
    except Exception as e:
        print(f"Failed to open {hive_name}\\{subpath}: {e}", file=sys.stderr)
        return
    # debug: report root opened
    print(f"Opened root: {hive_name}\\{subpath}")

    # Simple DFS stack: tuples of (relative_path, depth, handle, parent_path, parent_ts)
    # parent_ts is a datetime or None for root
    stack = [(subpath, 0, root, None, None)]

    opened_count = 1
    failed_keys: list[tuple[str, str]] = []
    anomalies: list[tuple[str, str, str, str, float]] = []
    # threshold in seconds to ignore tiny differences (0 = flag any child strictly newer)
    anomaly_threshold_seconds = 0.0

    while stack:
        cur_path, depth, handle, parent_path, parent_ts = stack.pop()
        # debug: show which frame we're processing
        #print(f"Processing: {cur_path} (depth {depth})")
        try:
            info = winreg.QueryInfoKey(handle)
            # QueryInfoKey returns a tuple; the last element is the last_modified FILETIME.
            # Use the last element (info[-1]) to be robust across Python/Windows versions.
            last_modified = int(info[-1])
            ts = filetime_to_datetime(last_modified)
            # if we have a parent timestamp, check for anomaly: child newer than parent
            if parent_ts is not None:
                try:
                    delta = (ts - parent_ts).total_seconds()
                    if delta > anomaly_threshold_seconds:
                        # record anomaly: (parent_path, child_path, parent_ts_iso, child_ts_iso, delta_seconds)
                        anomalies.append((parent_path or "", cur_path, parent_ts.isoformat(), ts.isoformat(), delta))
                except Exception:
                    # if parent_ts isn't a datetime for any reason, skip anomaly check
                    pass
            #print(f"{cur_path}  LastWriteUTC: {ts.isoformat()}")
        except Exception as e:
            # record the error and continue
            failed_keys.append((cur_path, str(e)))
            try:
                winreg.CloseKey(handle)
            except Exception:
                pass
            continue

        # enumerate children
        idx = 0
        while True:
            try:
                name = winreg.EnumKey(handle, idx)
            except OSError:
                break
            idx += 1
            child_rel = f"{cur_path}\\{name}"
            try:
                child_handle = open_key_try_views(hive, child_rel)
                opened_count += 1
            except FileNotFoundError:
                # key doesn't exist in this view — record and continue
                failed_keys.append((child_rel, "Not found in view"))
                continue
            except Exception as e:
                # record child open failure (permission or other)
                failed_keys.append((child_rel, str(e)))
                continue
            if max_depth is None or depth + 1 <= max_depth:
                # pass current key's path and ts as the parent info for the child
                stack.append((child_rel, depth + 1, child_handle, cur_path, ts))
            else:
                try:
                    winreg.CloseKey(child_handle)
                except Exception:
                    pass

        try:
            winreg.CloseKey(handle)
        except Exception:
            pass

    # final summary (after traversal)
    print(f"Scan complete. Opened keys: {opened_count}.")
    if anomalies:
        print(f"Anomalies ({len(anomalies)}):")
        for parent, child, p_ts, c_ts, delta in anomalies:
            print(f"  {parent} -> {child}: parent={p_ts}, child={c_ts}, delta_seconds={delta:.3f}")
    if failed_keys:
        print(f"Failed keys ({len(failed_keys)}):", file=sys.stderr)
        for k, err in failed_keys:
            print(f"  {k}: {err}", file=sys.stderr)


if __name__ == "__main__":
    print(f"Starting one-shot scan of {DEFAULT_HIVE}\\{DEFAULT_SUBPATH} (read-only).")
    scan_once()