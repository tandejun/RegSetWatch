// --- Notify host when agent loads ---
send({ status: "hook_init", pid: Process.id, name: Process.name });

(function () {
    const KeyWriteTimeInformation = 8;
    const DEBOUNCE_MS = 2000;
    const lastAlert = {};

    function nowMs() { return (new Date()).getTime(); }

    function safeFindExport(moduleName, exportName) {
        try {
            return Module.findExportByName(moduleName, exportName);
        } catch (e) {
            return null;
        }
    }

    const pNtSetInformationKey = safeFindExport("ntdll.dll", "NtSetInformationKey");
    send({ status: "hook_check", export: "NtSetInformationKey", found: !!pNtSetInformationKey });

    if (!pNtSetInformationKey) {
        send({ status: "error", event: "NtSetInformationKey_not_found" });
        return;
    }

    try {
        Interceptor.attach(pNtSetInformationKey, {
            onEnter(args) {
                try {
                    const infoClass = args[1].toInt32();
                    if (infoClass !== KeyWriteTimeInformation) {
                        return; // not what we care about
                    }

                    // Basic sanity checks: buffer ptr and length
                    const bufPtr = args[2];
                    const bufLen = args[3].toInt32();

                    if (bufPtr.isNull() || bufLen < 8) {
                        // Likely not a valid LARGE_INTEGER write-time payload
                        return;
                    }

                    // Read the 64-bit value at the buffer pointer (LARGE_INTEGER / FILETIME)
                    let writeTime = null;
                    try {
                        // Memory.readS64 may return a number (may lose precision for large 64-bit values,
                        // but is fine for simple non-zero checks and logging).
                        writeTime = Memory.readS64(bufPtr);
                    } catch (e) {
                        // If reading fails, bail out to avoid false positives
                        return;
                    }

                    if (writeTime === 0) {
                        // zero write time is suspicious/likely not a timestomp attempt
                        return;
                    }

                    // Debounce per-handle to avoid floods
                    const handleKey = args[0].toString();
                    const ts = nowMs();
                    if (lastAlert[handleKey] && (ts - lastAlert[handleKey] < DEBOUNCE_MS)) {
                        return;
                    }
                    lastAlert[handleKey] = ts;

                    // Send a compact detection payload
                    send({
                        status: "detection",
                        event: "RegistryTimestomp",
                        pid: Process.id,
                        infoClass: infoClass,
                        keyHandle: handleKey,
                        writeTime: writeTime.toString()
                    });

                } catch (inner) {
                    // avoid letting hook crash; report and continue
                    send({ status: "error", event: "onEnter_failed", message: String(inner) });
                }
            }
        });
    } catch (attachErr) {
        send({ status: "error", event: "attach_failed", message: String(attachErr) });
    }
})();
