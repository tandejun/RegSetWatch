import frida
import wmi
import json
import threading
from datetime import datetime
# Add import for regCheck's helper and check function
import sys
import os
sys.path.append(os.path.dirname(__file__))
from regCheck import frida_path_to_hive_and_key, check_key_timestomped

# APIs you want to hook
HOOKS = {
    "ntdll.dll": [
        "NtCreateKey",
        "NtOpenKey",
        "NtSetValueKey",
        "NtDeleteKey",
        "NtDeleteValueKey",
        "NtQueryValueKey",
        "NtEnumerateValueKey"
    ]
}

SPECIAL_HOOK = {
    "ntdll.dll": ["NtSetInformationKey"]
}

# Merge normal and special hooks for injection
ALL_HOOKS = {}
for module, funcs in HOOKS.items():
    if module not in ALL_HOOKS:
        ALL_HOOKS[module] = []
    ALL_HOOKS[module].extend(funcs)

for module, funcs in SPECIAL_HOOK.items():
    if module not in ALL_HOOKS:
        ALL_HOOKS[module] = []
    # Add only if it's not already in the list
    for func in funcs:
        if func not in ALL_HOOKS[module]:
            ALL_HOOKS[module].append(func)
# -----------------------------------

FRIDA_JS = """
'use strict';

const hooks = %HOOKS%;

// --- Debug: list loaded modules ---
try {
    const loaded = Process.enumerateModules().map(m => m.name);
} catch (e) {
    send({
        type: "debug",
        event: "module_info_error",
        error: e.toString()
    });
}

// ---------------------------------------
// Helper functions
// ---------------------------------------
function send_warning(payload) {
    send({ type: "warning", payload: payload });
}

function send_call(api, moduleName, args) {
    send({
        type: "api",
        api: api,
        module: moduleName,
        timestamp: Date.now(),
        pid: Process.id,
        processName: Process.enumerateModules()[0].name,
        args: args
    });
}

// ---------------------------------------
// Function to find out key that was timestomped
// ---------------------------------------
function getKeyPathFromHandle(handle) {
    try {
        const h = ptr(handle);

        if (h.isNull() || h.equals(ptr(-1))) {
            return "<invalid-handle>";
        }

        const ObjectNameInformation = 1;
        const ntdll = Process.getModuleByName("ntdll.dll");
        const NtQueryObject = new NativeFunction(
            ntdll.getExportByName("NtQueryObject"),
            "uint",
            ["pointer", "uint", "pointer", "uint", "pointer"]
        );

        let bufSize = 1024;
        let tries = 0;
        
        // Determine architecture to handle struct padding correctly
        const is64Bit = Process.pointerSize === 8;
        
        while (tries++ < 3) {
            const buf = Memory.alloc(bufSize);
            const returnLenPtr = Memory.alloc(4);

            const status = NtQueryObject(h, ObjectNameInformation, buf, bufSize, returnLenPtr);

            // STATUS_SUCCESS
            if (status === 0) {
                // UNICODE_STRING Structure:
                // [0x00] USHORT Length
                // [0x02] USHORT MaximumLength
                // [0x04] (padding on x64)
                // [0x04/0x08] PWSTR Buffer (Pointer)
                
                const nameLenBytes = buf.readU16();
                
                // Calculate offset to the Buffer pointer based on architecture
                // x86: offset 4, x64: offset 8
                const bufferPtrOffset = is64Bit ? 8 : 4;
                
                const namePtr = buf.add(bufferPtrOffset).readPointer();

                if (nameLenBytes === 0 || namePtr.isNull()) {
                    return "<empty>";
                }

                const charCount = Math.floor(nameLenBytes / 2);
                
                try {
                    return namePtr.readUtf16String(charCount) || "<unknown-key-path>";
                } catch (readErr) {
                    // detailed error debugging
                    return `<error-reading-string: ${readErr.message}>`;
                }
            }

            // STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
            if ((status >>> 0) === 0xC0000004) {
                const required = returnLenPtr.readU32();
                // Sanity check buffer size (e.g., max 64KB to prevent OOM)
                if (required > bufSize && required < 65536) {
                    bufSize = required + 32; // add slight padding
                    continue;
                } 
                return "<buffer-too-large-or-invalid>";
            }

            return `<unknown-ntstatus: ${status.toString(16)}>`;
        }

        return "<failed-after-retries>";
    } catch (e) {
        return `<exception-resolving-path: ${e.toString()}>`;
    }
}


// ---------------------------------------
// Hook function for Frida 17.5.1
// ---------------------------------------
function hookApi(moduleName, funcName) {

    // Inform Python that we are trying to hook
    //send({ type: "hooked", api: funcName });

    let moduleObj = null;
    let addr = null;

    try {
        // Load module object first (Frida 17+ syntax)
        moduleObj = Process.getModuleByName(moduleName);

        // Get export address using module.getExportByName()
        addr = moduleObj.getExportByName(funcName);
    }
    catch (e) {
        return;
    }

    try {
        Interceptor.attach(addr, {
            onEnter(args) {
                // Special: NtSetInformationKey
                if (funcName === "NtSetInformationKey") {
                    let keyHandle = "<unreadable>";
                    let infoClass = "<unreadable>";
                    let keyInfo = "<unreadable>";
                    let infoLen = "<unreadable>";

                    try { keyHandle = args[0].toString(); } catch (_) {}
                    try { infoClass = args[1].toInt32(); } catch (_) {}
                    try { keyInfo = args[2].toString(); } catch (_) {}
                    try { infoLen = args[3].toInt32(); } catch (_) {}

                    const keyPath = getKeyPathFromHandle(args[0]);

                    send_warning({
                        api: funcName,
                        module: moduleName,
                        timestamp: Date.now(),
                        pid: Process.id,
                        processName: Process.enumerateModules()[0].name,
                        key_path: keyPath,
                        params: {
                            KeyHandle: keyHandle,
                            KeyInformationClass: infoClass,
                            KeyInformation: keyInfo,
                            KeyInformationLength: infoLen
                        }
                    });
                    return;
                    }

                // Normal argument logging
                let argVals = [];
                for (let i = 0; i < 4; i++) {
                    try {
                        argVals.push(args[i] ? args[i].toString() : null);
                    } catch (_) {
                        argVals.push("<unreadable>");
                    }
                }

                //send_call(funcName, moduleName, argVals);
            },

            onLeave(retval) {
                let r = "<unreadable>";
                try { r = retval.toString(); } catch (_) {}
            }
        });
    }
    catch (e) {
        send({
            type: "debug",
            event: "attach_failed",
            api: funcName,
            module: moduleName,
            error: e.toString()
        });
    }
}

// ---------------------------------------
// Install all hooks
// ---------------------------------------
for (const moduleName in hooks) {
    for (const funcName of hooks[moduleName]) {
        hookApi(moduleName, funcName);
    }
}
"""

# Storage for all API calls
api_log = []


def on_message(message, data):

    if message["type"] != "send":
        return

    payload = message["payload"]
    print(payload)

    if payload["type"] == "hooked":
        return
        #print(f"[+] Hooked API: {payload['api']}")
        
    # Normal API call
    if payload["type"] == "api":
        entry = {
            "timestamp": datetime.fromtimestamp(payload["timestamp"] / 1000).isoformat(),
            "pid": payload["pid"],
            "process": payload["processName"],
            "module": payload["module"],
            "api": payload["api"],
        }
        api_log.append(entry)

        #print(f"[PID {entry['pid']} - {entry['process']}] {entry['module']}!{entry['api']}")
        return

    # Special WARNING for NtSetInformationKey
    if payload["type"] == "warning":
        p = payload["payload"]
        key_path = p.get('key_path', '<unknown>')
        if p['params']['KeyInformationClass'] == 0:
            print("\n⚠️ WARNING — Possible NtSetInformationKey Timestomping DETECTED")
            print(f"Process: {p['processName']} (PID {p['pid']})")
            print(f"Registry Key: {key_path}")
            print("Parameters:")
            print(f"  KeyHandle           : {p['params']['KeyHandle']}")
            print(f"  KeyInformationClass : {p['params']['KeyInformationClass']}")
            print(f"  KeyInformation      : {p['params']['KeyInformation']}")
            print(f"  KeyInfoLength       : {p['params']['KeyInformationLength']}\n")

            # Call regCheck's timestomp check
            try:
                hive, rel_key = frida_path_to_hive_and_key(key_path)
                result = check_key_timestomped(hive, rel_key)
                print(f"Timestomp check result: {result}")

                # Run a one-time full scan of all hives and output to CSV
                from regCheck import scan_once

                all_csv_rows = []
                targets = ["HKLM", "HKCU", "HKU", "HKCR"]
                for hive_name in targets:
                    print(f"[FRIDA_LOCAL] Scanning {hive_name}\\<root>")
                    res = scan_once(hive_name, "")
                    if res:
                        all_csv_rows.extend(res.get("csv_rows", []))
                csv_file = "frida_scan_output.csv"
                fieldnames = ["scan_id","scan_time_utc","hive","key_path","lastwrite_iso","parent_path","parent_lastwrite_iso","delta_seconds","anomaly_flag"]
                import csv
                with open(csv_file, "w", newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    for row in all_csv_rows:
                        writer.writerow(row)
                print(f"\n[FRIDA_LOCAL] Full registry scan CSV written to {csv_file} with {len(all_csv_rows)} rows.")

            except Exception as e:
                print(f"[ERROR] Could not check timestomp: {e}")


def inject(pid):
    try:
        session = frida.attach(pid)
        script = session.create_script(FRIDA_JS.replace("%HOOKS%", json.dumps(ALL_HOOKS)))
        script.on("message", on_message)
        script.load()
        print(f"[+] Injected into PID {pid}")
    except Exception as e:
        print(f"[-] Failed to inject into {pid}: {e}")


def monitor():
    print("[*] Monitoring new processes...")
    watcher = wmi.WMI().Win32_Process.watch_for("creation")
    
    # List of processes to ignore
    IGNORE_LIST = [
        "python.exe",
        "py.exe",
        "frida-helper.exe",
        "frida-helper-x86.exe",
        "frida-helper-x86_64.exe",
        "conhost.exe",
        "wmiprvse.exe",
        "svchost.exe",
        "consent.exe"
    ]

    while True:
        new_proc = watcher()
        pid = new_proc.ProcessId
        name = new_proc.Name
        
        if name.lower() in IGNORE_LIST:
            continue # Skip this process

        print(f"[+] New process detected: {name} (PID={pid})")

        threading.Thread(target=inject, args=(pid,), daemon=True).start()


if __name__ == "__main__":
    monitor()
