import frida
import wmi
import json
import threading
from datetime import datetime

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
    const loaded = Process.enumerateModulesSync().map(m => m.name);
    send({
        type: "debug",
        event: "module_info",
        loaded_modules: loaded
    });
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
        processName: Process.name,
        args: args
    });
}

// ---------------------------------------
// Hook function for Frida 17.5.1
// ---------------------------------------
function hookApi(moduleName, funcName) {

    // Inform Python that we are trying to hook
    send({ type: "hooked", api: funcName });

    let moduleObj = null;
    let addr = null;

    try {
        // Load module object first (Frida 17+ syntax)
        moduleObj = Process.getModuleByName(moduleName);

        // Get export address using module.getExportByName()
        addr = moduleObj.getExportByName(funcName);

        send({
            type: "debug",
            event: "resolved",
            api: funcName,
            module: moduleName,
            addr: addr.toString()
        });
    }
    catch (e) {
        send({
            type: "debug",
            event: "resolve_failed",
            api: funcName,
            module: moduleName,
            error: e.toString()
        });
        return;
    }

    try {
        send({
            type: "debug",
            event: "attaching",
            api: funcName,
            module: moduleName,
            addr: addr.toString()
        });

        Interceptor.attach(addr, {
            onEnter(args) {

                send({
                    type: "debug",
                    event: "onEnter",
                    api: funcName,
                    module: moduleName
                });

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

                    send_warning({
                        api: funcName,
                        module: moduleName,
                        timestamp: Date.now(),
                        pid: Process.id,
                        processName: Process.name,
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

                send_call(funcName, moduleName, argVals);
            },

            onLeave(retval) {
                let r = "<unreadable>";
                try { r = retval.toString(); } catch (_) {}
                send({
                    type: "debug",
                    event: "onLeave",
                    api: funcName,
                    module: moduleName,
                    retval: r
                });
            }
        });

        send({
            type: "debug",
            event: "attached",
            api: funcName,
            module: moduleName
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
        print(f"[+] Hooked API: {payload['api']}")
        
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

        print(f"[PID {entry['pid']} - {entry['process']}] {entry['module']}!{entry['api']}")
        return

    # Special WARNING for NtSetInformationKey
    if payload["type"] == "warning":
        p = payload["payload"]

        print("\n⚠️ WARNING — NtSetInformationKey DETECTED")
        print(f"Process: {p['processName']} (PID {p['pid']})")
        print("Parameters:")
        print(f"  KeyHandle           : {p['params']['KeyHandle']}")
        print(f"  KeyInformationClass : {p['params']['KeyInformationClass']}")
        print(f"  KeyInformation      : {p['params']['KeyInformation']}")
        print(f"  KeyInfoLength       : {p['params']['KeyInformationLength']}\n")


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
