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
ALL_HOOKS = {**HOOKS, **SPECIAL_HOOK}

FRIDA_JS = """
'use strict';

const hooks = %HOOKS%;

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

function hookApi(moduleName, funcName) {
    send({ type: "hooked", api: funcName });
    let addr = null;
    try {
        addr = Module.getExportByName(moduleName, funcName);
    } catch (e) {
        return;
    }

    Interceptor.attach(addr, {
        onEnter(args) {

            // Special case: NtSetInformationKey warning
            if (funcName === "NtSetInformationKey") {
                send_warning({
                    api: funcName,
                    module: moduleName,
                    timestamp: Date.now(),
                    pid: Process.id,
                    processName: Process.name,
                    params: {
                        KeyHandle: args[0].toString(),
                        KeyInformationClass: args[1].toInt32(),
                        KeyInformation: args[2].toString(),
                        KeyInformationLength: args[3].toInt32()
                    }
                });
                return;
            }

            // Generic registry syscall logging
            send_call(funcName, moduleName, [
                args[0].toString(),
                args[1] ? args[1].toString() : null,
                args[2] ? args[2].toString() : null,
                args[3] ? args[3].toString() : null
            ]);
        }
    });
}

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

    while True:
        new_proc = watcher()
        pid = new_proc.ProcessId
        name = new_proc.Name

        print(f"[+] New process detected: {name} (PID={pid})")

        threading.Thread(target=inject, args=(pid,), daemon=True).start()


if __name__ == "__main__":
    monitor()
