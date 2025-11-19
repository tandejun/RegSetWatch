#!/usr/bin/env python3
"""
Simple one-shot registry scanner: scans a hive/subpath once and prints each key visited with its LastWriteTime (UTC).

Defaults: HKLM\SOFTWARE. Run elevated to inspect HKLM fully. The script is read-only to the registry.

Usage (PowerShell):
  python .\regCheck.py

To adjust the scanned hive/subpath, edit the constants below or import and call `scan_once(hive_name, subpath)`.
"""

from __future__ import annotations

# Helper: Convert Frida registry path (e.g. \REGISTRY\MACHINE\SYSTEM\MountedDevices) to hive/key format
def frida_path_to_hive_and_key(frida_path: str):
    path = frida_path.lstrip("\\")
    parts = path.split("\\")
    if len(parts) < 3:
        raise ValueError("Invalid registry path format")
    if parts[0].upper() == "REGISTRY":
        if parts[1].upper() == "MACHINE":
            hive = "HKLM"
        elif parts[1].upper() == "USER":
            hive = "HKU"
        elif parts[1].upper() == "CLASSES_ROOT":
            hive = "HKCR"
        elif parts[1].upper() == "CURRENT_USER":
            hive = "HKCU"
        else:
            raise ValueError(f"Unknown hive: {parts[1]}")
        key_path = "\\".join(parts[2:])
        return hive, key_path
    else:
        raise ValueError("Unknown registry root")
import sys
import argparse
import time
import winreg
from datetime import datetime, timezone
from typing import Optional
import csv
import uuid

# Simple defaults
DEFAULT_HIVE = "HKLM"
DEFAULT_SUBPATH = "SOFTWARE"

# FILETIME epoch difference: number of 100-ns intervals between 1601-01-01 and 1970-01-01
_EPOCH_AS_FILETIME = 116444736000000000


def filetime_to_datetime(ft: int) -> datetime: # converts Windows FILETIME to datetime in UTC
    # this func converts a Windows FILETIME (number of nanoseconds since 1601-01-01T00:00:00 UTC) to a datetime in UTC (number of seconds since 1970-01-01T00:00:00 UTC)
    try:
        ft = int(ft)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc) # returns a datetime representing 0 seconds since unix epoch (1970-01-01T00:00:00 UTC)
    if ft <= 0:
        return datetime.fromtimestamp(0, tz=timezone.utc) # returns a datetime representing 0 seconds since unix epoch (1970-01-01T00:00:00 UTC)
    us = (ft - _EPOCH_AS_FILETIME) / 10 # number of microseconds since unix epoch (1970-01-01T00:00:00 UTC)
    sec = us / 1_000_000 # number of seconds since unix epoch (1970-01-01T00:00:00 UTC)
    return datetime.fromtimestamp(sec, tz=timezone.utc) # returns datetime in UTC


def hive_root_from_name(name: str): # function to map hive name to winreg constant
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


def open_key_try_views(hive_const, path):
    """Open a registry key trying common view/access flag combinations.

    Tries KEY_READ | KEY_WOW64_64KEY, KEY_READ | KEY_WOW64_32KEY (when available),
    then KEY_READ. Returns an open key handle or raises the most informative
    exception (prefers PermissionError-like exceptions over FileNotFoundError).
    """
    key_read = winreg.KEY_READ  # open for read-only
    wow64_64 = getattr(winreg, "KEY_WOW64_64KEY", 0)
    wow64_32 = getattr(winreg, "KEY_WOW64_32KEY", 0)
    candidates = []
    if wow64_64:
        candidates.append(key_read | wow64_64) # try 64-bit view first
    if wow64_32:
        candidates.append(key_read | wow64_32) # try 32-bit view next
    candidates.append(key_read) 

    last_non_notfound_exc = None
    for access in candidates:
        try:
            return winreg.OpenKey(hive_const, path, 0, access) # returns an open key handle
        except FileNotFoundError:
            continue
        except Exception as e:
            last_non_notfound_exc = e
            continue # try next access flag combination

    if last_non_notfound_exc is not None:
        raise last_non_notfound_exc
    raise FileNotFoundError(f"Key not found in any view: {path}")


def scan_once(hive_name: str = DEFAULT_HIVE, subpath: str = DEFAULT_SUBPATH):
    """Scan the hive/subpath once and print each key visited and its LastWriteTime (UTC)."""
    hive = hive_root_from_name(hive_name) # get winreg constant from hive_name
    # use module-level open_key_try_views helper (see defined above)

    try:
        root = open_key_try_views(hive, subpath) # open the root key to start scanning
    except Exception as e:
        print(f"Failed to open {hive_name}\\{subpath}: {e}", file=sys.stderr)
        return
    # debug: report root opened
    print(f"Opened root: {hive_name}\\{subpath}")

    # Simple DFS stack: tuples of (relative_path, depth, handle, parent_path, parent_ts)
    # parent_ts is a datetime or None for root
    stack = [(subpath, 0, root, None, None)]

    opened_count = 1 # opened root key so it starts at 1
    failed_keys: list[tuple[str, str]] = [] # stores key path and error message for failed opens
    anomalies: list[tuple[str, str, str, str, float]] = [] # same parameter list as stack 
    csv_rows = []
    # threshold in seconds to ignore tiny differences (0 = flag any child strictly newer)
    anomaly_threshold_seconds = 30.0 
    scan_id = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + str(uuid.uuid4())[:8]
    scan_time_utc = datetime.now(timezone.utc).isoformat()

    while stack:
        cur_path, depth, handle, parent_path, parent_ts = stack.pop()
        try:
            info = winreg.QueryInfoKey(handle)
            last_modified = int(info[-1])
            ts = filetime_to_datetime(last_modified)
            readable_ts = ts.strftime('%Y-%m-%d %H:%M:%S')
            readable_parent_ts = parent_ts.strftime('%Y-%m-%d %H:%M:%S') if parent_ts else ""
            # For each child, compare to parent
            if parent_ts is not None:
                try:
                    delta = (ts - parent_ts).total_seconds()
                    anomaly_flag = delta > anomaly_threshold_seconds
                    if anomaly_flag:
                        anomalies.append((parent_path or "", cur_path, parent_ts.isoformat(), ts.isoformat(), delta))
                    csv_rows.append({
                        "scan_id": scan_id,
                        "scan_time_utc": scan_time_utc,
                        "hive": hive_name,
                        "key_path": cur_path,
                        "lastwrite_iso": readable_ts,
                        "parent_path": parent_path or "",
                        "parent_lastwrite_iso": readable_parent_ts,
                        "delta_seconds": delta,
                        "anomaly_flag": anomaly_flag
                    })
                
                except Exception as e:
                    csv_rows.append({
                        "scan_id": scan_id,
                        "scan_time_utc": scan_time_utc,
                        "hive": hive_name,
                        "key_path": cur_path,
                        "lastwrite_iso": readable_ts,
                        "parent_path": parent_path or "",
                        "parent_lastwrite_iso": readable_parent_ts,
                        "delta_seconds": "",
                        "anomaly_flag": False
                    })
                
            # For root key, just record
            else:
                csv_rows.append({
                    "scan_id": scan_id,
                    "scan_time_utc": scan_time_utc,
                    "hive": hive_name,
                    "key_path": cur_path,
                    "lastwrite_iso": readable_ts,
                    "parent_path": "",
                    "parent_lastwrite_iso": "",
                    "delta_seconds": "",
                    "anomaly_flag": False
                })
        except Exception as e:
            failed_keys.append((cur_path, str(e)))
            csv_rows.append({
                "scan_id": scan_id,
                "scan_time_utc": scan_time_utc,
                "hive": hive_name,
                "key_path": cur_path,
                "lastwrite_iso": "",
                "parent_path": parent_path or "",
                "parent_lastwrite_iso": readable_parent_ts,
                "delta_seconds": "",
                "anomaly_flag": False
            })
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
            if cur_path:
                child_rel = f"{cur_path}\\{name}"
            else:
                child_rel = name
            try:
                child_handle = open_key_try_views(hive, child_rel)
                opened_count += 1
            except FileNotFoundError:
                failed_keys.append((child_rel, "Not found in view"))
                continue
            except Exception as e:
                failed_keys.append((child_rel, str(e)))
                continue
            stack.append((child_rel, depth + 1, child_handle, cur_path, ts))

        try:
            winreg.CloseKey(handle)
        except Exception:
            pass

    # Instead of writing CSV here, return csv_rows for aggregation
    print(f"Scan complete. Successful keys: {opened_count}. Failed keys: {len(failed_keys)}.")
    return {"opened_count": opened_count, "failed_keys": failed_keys, "anomalies": anomalies, "csv_rows": csv_rows}


def check_key_timestomped(hive_name: str, key_path: str, threshold_seconds: float = 2.0):
    """Check whether a single registry key is "timestomped" relative to its parent.

    Arguments:
      hive_name: hive short name, e.g. 'HKLM', 'HKCU', 'HKU', 'HKCR', long form name is ok too
      key_path: relative path under the hive (use empty string for hive root)
      threshold_seconds: tolerance in seconds; child newer than parent by > threshold

        Returns a dict with keys:
            - anomaly_detected: True/False/None (None when no parent exists)
            - parent_ts, child_ts: ISO datetimes or None
            - delta_seconds: float or None
            - error: optional error string when the check could not be performed
    """
    print(f"Checking LastWriteTime for {hive_name}\\{key_path or '<root>'} with threshold {threshold_seconds} seconds")
    try:
        hive = hive_root_from_name(hive_name)
    except Exception as e:
        return {"anomaly_detected": None, "error": str(e)}

    # key_path empty means hive root; hive root has no parent so we can't check
    if not key_path:
        return {"anomaly_detected": None, "error": "Hive root has no parent to compare against"} # if key path is empty
    # open the target key
    try:        
        key_handle = open_key_try_views(hive, key_path)
    except Exception as e:
        return {"anomaly_detected": None, "error": f"Failed to open key {hive_name}\\{key_path}: {e}"}

    # find parent path: split off the last component
    if "\\" in key_path:
        parent_path = key_path.rsplit("\\", 1)[0] # split off last component
    else:
        parent_path = ""  # parent is the hive root

    # open parent (always open via helper; empty parent_path -> root handle)
    try:
        parent_handle = open_key_try_views(hive, parent_path)
    except Exception as e:
        try:
            winreg.CloseKey(key_handle)
        except Exception:
            pass
        return {"anomaly_detected": None, "error": f"Failed to open parent {hive_name}\\{parent_path}: {e}"}

    try:
        child_info = winreg.QueryInfoKey(key_handle)  # open handle to child (target) key
        child_ft = int(child_info[-1])  # read last element to get last modified time
        child_ts = filetime_to_datetime(child_ft)  # convert from windows filetime to datetime in UTC
        print("Checking child key:", key_path or "<root>", "| LastWrite:", child_ts.strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        try:
            winreg.CloseKey(key_handle)
        except Exception:
            pass
        try:
            winreg.CloseKey(parent_handle)
        except Exception:
            pass
        return {"anomaly_detected": None, "error": f"Failed to query child key: {e}"}

    try:
        parent_info = winreg.QueryInfoKey(parent_handle)
        parent_ft = int(parent_info[-1])
        parent_ts = filetime_to_datetime(parent_ft)
        print("Checking parent key: ", parent_path or "<root>", "| LastWrite:", parent_ts.strftime('%Y-%m-%d %H:%M:%S'))
    except Exception as e:
        try:
            winreg.CloseKey(key_handle)
        except Exception:
            pass
        try:
            winreg.CloseKey(parent_handle)
        except Exception:
            pass
        return {"anomaly_detected": None, "error": f"Failed to query parent key: {e}"}

    # compute delta
    try:
        delta = (child_ts - parent_ts).total_seconds()
        anomaly_detected = delta > threshold_seconds
    except Exception as e:
        anomaly_detected = None
        delta = None

    # cleanup
    try:
        winreg.CloseKey(key_handle)
    except Exception:
        pass
    try:
        winreg.CloseKey(parent_handle)
    except Exception:
        pass

    return {
        "anomaly_detected": anomaly_detected,
        "parent_ts": parent_ts.isoformat(),
        "child_ts": child_ts.isoformat(),
        "delta_seconds": delta,
    }


def main():
    parser = argparse.ArgumentParser(description="Registry hive scanner and LastWriteTime anomaly (Timestomping) detector")
    parser.add_argument("--daemon", action="store_true", help="Run as a background process, scanning periodically")
    parser.add_argument("--interval", type=int, default=30, help="Scan interval in minutes (for daemon mode, default of 30 minutes)")
    parser.add_argument("--manual", type=str, help="Full registry path to manually scan (e.g. HKLM\\SOFTWARE\\Microsoft)")
    args = parser.parse_args()

    targets = [
        ("HKLM", ""),
        ("HKCU", ""),
        ("HKU", ""),              # entire HKEY_USERS root (use carefully)
        ("HKCR", ""),             # classes root
    ]

    def run_full_scan_and_write_csv():
        all_csv_rows = []
        for hive, subpath in targets:
            print(f"============================ Scanning {hive}\\{subpath or '<root>'} ==============================")
            res = scan_once(hive, subpath)
            if not res:
                continue
            succ = res.get("opened_count", 0)
            failed = len(res.get("failed_keys", []))
            stomped = len(res.get("anomalies", []))
            print(f"Summary for {hive}\\{subpath or '<root>'}: successful={succ}, failed={failed}, anomaly detected in timestamps={stomped}")
            all_csv_rows.extend(res.get("csv_rows", []))
        # Write CSV after all hives are scanned
        csv_file = "scan_output.csv"
        fieldnames = ["scan_id","scan_time_utc","hive","key_path","lastwrite_iso","parent_path","parent_lastwrite_iso","delta_seconds","anomaly_flag"]
        with open(csv_file, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in all_csv_rows:
                writer.writerow(row)
        print(f"[INFO] CSV written to {csv_file} with {len(all_csv_rows)} rows.")

    if args.daemon:
        print(f"[INFO] Starting daemon mode: scan every {args.interval} minute(s). Press Ctrl+C to exit.")
        try:
            while True:
                scan_time = datetime.now(timezone.utc).isoformat()
                print(f"\n[INFO] Scan started at {scan_time}")
                run_full_scan_and_write_csv()
                print(f"[INFO] Scan complete. Sleeping {args.interval} minute(s)...")
                time.sleep(args.interval * 60)
        except KeyboardInterrupt:
            print("[INFO] Daemon stopped by user.")
    else:
        # If manual scan argument is provided, parse and run single-key check
        if args.manual:
            # Split at first backslash
            if '\\' in args.manual:
                hive, key_path = args.manual.split('\\', 1)
                res = check_key_timestomped(hive, key_path)
                if "error" in res:
                    print("Manual check result:", res)
                else:
                    if res["anomaly_detected"] is True:
                        print("Manual check result: Anomaly detected.")
                    elif res["anomaly_detected"] is False:
                        print("Manual check result: No anomaly detected.")
                    else:
                        print("Manual check result: Unable to determine anomaly status.")
                    print({k: v for k, v in res.items() if k != "anomaly_detected"})
            else:
                print("Invalid manual path format. Use e.g. HKLM\\SOFTWARE\\Microsoft")
        

if __name__ == "__main__":
    main()
  
