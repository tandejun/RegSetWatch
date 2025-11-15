#!/usr/bin/env python3
"""
Robust Frida registry timestomp detector (single-file).

- Polls for ntdll.dll exports (multiple APIs).
- Attempts multiple export lookup methods.
- Falls back to advapi32 registry APIs if ntdll exports aren't found.
- CLI: --attach, --attach-name, --spawn, --list, --log, --timeout
"""
import frida, argparse, sys, time, json, platform
from datetime import datetime

FRIDA_SCRIPT = r"""
// Robust Frida JS for registry timestomp detection + fallbacks

function safeHexDump(ptr, len) {
    try {
        if (!ptr || ptr.isNull()) return "<null>";
        if (typeof hexdump === 'function') {
            return hexdump(ptr, {length: len || 32, header: false, ansi: false});
        }
        var _len = len || 32;
        var bytes = Memory.readByteArray(ptr, _len);
        if (!bytes) return "<no-bytes>";
        var u8 = new Uint8Array(bytes);
        var s = [];
        for (var i = 0; i < u8.length; i++) {
            var h = u8[i].toString(16);
            if (h.length === 1) h = '0'+h;
            s.push(h);
        }
        return s.join(' ');
    } catch (e) {
        return "<safeHexDump error: " + e + ">";
    }
}

function tryParseFiletime(ptr) {
    if (!ptr || ptr.isNull()) return null;
    try {
        var low = ptr.readU32();
        var high = ptr.add(4).readU32();
        var asBig = BigInt(high >>> 0) << 32n | BigInt(low >>> 0);
        var ms = Number(asBig / 10000n) - 11644473600000;
        return (new Date(ms)).toISOString();
    } catch (e) { return null; }
}

function makeLog(obj) {
    try { send(JSON.stringify(obj)); } catch(e) { send("LOGERR:" + e + " -- " + JSON.stringify(obj)); }
}

function hookExportByAddr(moduleName, exportName, addr) {
    try {
        return Interceptor.attach(addr, {
            onEnter: function (args) {
                this.api = exportName;
                this.ts = (new Date()).toISOString();
                this.proc = Process.name;
                this.pid = Process.id;
                try {
                    // attempt to read typical NtSetInformationKey args
                    if (exportName.indexOf("SetInformationKey") >= 0) {
                        this.infoClass = (args[1] && args[1].toInt32) ? args[1].toInt32() : (args[1] ? args[1] : null);
                        this.infoPtr = args[2];
                        this.infoLen = (args[3] && args[3].toInt32) ? args[3].toInt32() : (args[3] ? args[3] : 0);
                    } else {
                        this.infoPtr = args[1] || ptr('0x0');
                        this.infoLen = 0;
                        this.infoClass = null;
                    }
                    var hexd = "<no-buffer>";
                    if (this.infoPtr && !this.infoPtr.isNull()) {
                        hexd = safeHexDump(this.infoPtr, Math.min(this.infoLen || 32, 256));
                    }
                    var parsed = (this.infoLen >= 8) ? tryParseFiletime(this.infoPtr) : null;
                    makeLog({ ts:this.ts, type:"call", api:exportName, pid:this.pid, proc:this.proc, infoClass:this.infoClass, infoLen:this.infoLen, parsedFiletime: parsed, hexdump: hexd });
                } catch(e) {
                    makeLog({ ts:(new Date()).toISOString(), type:"error", api:exportName, err: String(e) });
                }
            },
            onLeave: function(ret) {
                try { makeLog({ ts:(new Date()).toISOString(), type:"ret", api: exportName + ".return", pid: Process.id, proc: Process.name, retval: ret ? ret.toString() : null }); }
                catch(e) { makeLog({ ts:(new Date()).toISOString(), type:"error", api: exportName + ".return", err: String(e) }); }
            }
        });
    } catch(e) {
        return null;
    }
}

function hookExport(moduleName, exportName) {
    try {
        var addr = null;
        // Try getExportByName
        try { addr = Module.getExportByName(moduleName, exportName); } catch(e) { addr = null; }
        // Try findExportByName fallback
        if (!addr) {
            try { addr = Module.findExportByName(moduleName, exportName); } catch(e) { addr = null; }
        }
        // Try enumerateExportsSync
        if (!addr) {
            try {
                var exps = Module.enumerateExportsSync(moduleName);
                for (var i=0;i<exps.length;i++) {
                    if (exps[i] && exps[i].name === exportName) { addr = exps[i].address; break; }
                }
            } catch(e) { }
        }
        if (addr) {
            return hookExportByAddr(moduleName, exportName, addr);
        }
        return null;
    } catch(e) { return null; }
}

function tryHookingNowWithFallback() {
    var hooked = [];
    var need = ["NtSetInformationKey","ZwSetInformationKey","NtFlushKey","ZwFlushKey"];
    for (var i=0;i<need.length;i++) {
        var n = need[i];
        var h = hookExport("ntdll.dll", n);
        if (h) hooked.push(n);
    }
    // If none found, try advapi32 higher-level registry APIs as fallback
    if (hooked.length === 0) {
        var advapis = ["RegSetValueExW","RegSetValueExA","RegSetKeyValueW","RegSetKeyValueA"];
        for (var j=0;j<advapis.length;j++) {
            var name = advapis[j];
            try {
                var a = null;
                try { a = Module.getExportByName("advapi32.dll", name); } catch(e) { a = null; }
                if (!a) {
                    try { a = Module.findExportByName("advapi32.dll", name); } catch(e) { a = null; }
                }
                if (!a) {
                    try {
                        var exps = Module.enumerateExportsSync("advapi32.dll");
                        for (var k=0;k<exps.length;k++) { if (exps[k] && exps[k].name === name) { a = exps[k].address; break; } }
                    } catch(e) {}
                }
                if (a) {
                    Interceptor.attach(a, {
                        onEnter: function(args) { makeLog({ ts:(new Date()).toISOString(), type:"advapi_call", api:name, pid:Process.id, proc:Process.name }); },
                        onLeave: function(ret) { makeLog({ ts:(new Date()).toISOString(), type:"advapi_ret", api:name, pid:Process.id, proc:Process.name, retval: ret ? ret.toString() : null }); }
                    });
                    hooked.push("advapi:"+name);
                }
            } catch(e){}
        }
    }
    return hooked;
}

// Robust wait-and-hook with diagnostics
var POLL_INTERVAL_MS = 200;
var POLL_TIMEOUT_MS = 5000;
var waited = 0;
function enumerateModuleNames(moduleName) {
    try {
        var ex = Module.enumerateExportsSync(moduleName);
        var names = [];
        for (var i=0;i<ex.length;i++){ if (ex[i] && ex[i].name) names.push(ex[i].name); }
        return names;
    } catch(e) { return null; }
}

function doWaitAndHook() {
    var hooked = tryHookingNowWithFallback();
    if (hooked && hooked.length>0) {
        makeLog({ ts:(new Date()).toISOString(), type:"info", info:"Hooked exports (immediate)", hooked: hooked });
        return;
    }
    var iv = setInterval(function() {
        waited += POLL_INTERVAL_MS;
        var hooked2 = tryHookingNowWithFallback();
        if (hooked2 && hooked2.length>0) {
            clearInterval(iv);
            makeLog({ ts:(new Date()).toISOString(), type:"info", info:"Hooked exports (after wait)", hooked: hooked2 });
            return;
        }
        if (waited >= POLL_TIMEOUT_MS) {
            clearInterval(iv);
            // diagnostic: can we enumerate module exports?
            var names = null;
            try { names = enumerateModuleNames("ntdll.dll"); } catch(e) { names = null; }
            if (names && names.length>0) {
                makeLog({ ts:(new Date()).toISOString(), type:"diag", err:"Module present but expected exports not found", exports_count: names.length, exports_sample: names.slice(0,200) });
            } else {
                makeLog({ ts:(new Date()).toISOString(), type:"diag", err:"Module not present or cannot enumerate exports: ntdll.dll" });
            }
        }
    }, POLL_INTERVAL_MS);
}

doWaitAndHook();
"""

# ---------- Python controller helpers ----------
def is_windows():
    return platform.system().lower() == "windows"

def list_processes_and_hint():
    try:
        try:
            device = frida.get_local_device()
        except frida.ServerNotRunningError:
            print("[!] frida-server not found. Please start frida-server.exe (as admin).")
            sys.exit(1)
        procs = device.enumerate_processes()
    except Exception as e:
        print("[!] enumerate processes failed:", e, file=sys.stderr)
        return
    print("PID    Name                              Arch   LikelyHookable")
    print("-"*70)
    protected = {"lsass.exe","winlogon.exe","csrss.exe","smss.exe","services.exe","system"}
    for p in procs:
        name = getattr(p, "name", "<unknown>")
        pid = getattr(p, "pid", -1)
        arch = getattr(p, "arch", "unknown")
        likely = "Yes"
        if name.lower() in protected or pid <=4:
            likely = "No/protected"
        elif pid < 100:
            likely = "Possibly(Admin)"
        print(f"{pid:6}  {name:34.34}  {arch:6}  {likely}")

def on_message(message, data, logfile_handle):
    if message['type'] == 'send':
        payload = message['payload']
        try:
            obj = json.loads(payload)
        except Exception:
            print("RAW:", payload)
            if logfile_handle:
                logfile_handle.write("RAW: " + str(payload) + "\n")
            return
        t = obj.get('type', '')
        if t == 'diag':
            s = f"{obj.get('ts','')}\t[DIAG]\t{obj.get('err')}"
            if 'exports_count' in obj:
                s += f" exports_count={obj['exports_count']}"
            if 'exports_sample' in obj:
                s += "\nexports_sample: " + ", ".join(obj['exports_sample'][:80])
            print(s)
            if logfile_handle:
                logfile_handle.write(s + "\n")
                if 'exports_sample' in obj:
                    logfile_handle.write("exports_sample: " + ", ".join(obj['exports_sample'][:80]) + "\n")
            return
        if t == 'info':
            line = f"{obj.get('ts','')}\t[INFO]\t{obj.get('info')} hooked={obj.get('hooked')}"
            print(line)
            if logfile_handle:
                logfile_handle.write(line + "\n")
            return
        # generic call/ret logs
        if t in ('call','ret','advapi_call','advapi_ret'):
            try:
                if t == 'call':
                    hdr = f"{obj.get('ts','')}\t[CALL]\t{obj.get('api')} pid={obj.get('pid')} proc={obj.get('proc')}"
                    if obj.get('infoClass') is not None: hdr += f" infoClass={obj.get('infoClass')}"
                    if obj.get('infoLen') is not None: hdr += f" infoLen={obj.get('infoLen')}"
                    if obj.get('parsedFiletime'): hdr += f" parsedFiletime={obj.get('parsedFiletime')}"
                    print(hdr)
                    if obj.get('hexdump'): print(obj.get('hexdump'))
                    if logfile_handle: logfile_handle.write(hdr + "\n" + (obj.get('hexdump') or "") + "\n")
                else:
                    line = f"{obj.get('ts','')}\t[{t.upper()}]\t{obj.get('api')} pid={obj.get('pid')} proc={obj.get('proc')} retval={obj.get('retval', '')}"
                    print(line)
                    if logfile_handle: logfile_handle.write(line + "\n")
            except Exception as e:
                print("Log format error:", e)
                if logfile_handle: logfile_handle.write("Log format error: " + str(e) + "\n")
            return
        # fallback print
        print(json.dumps(obj))
        if logfile_handle: logfile_handle.write(json.dumps(obj) + "\n")
    elif message['type'] == 'error':
        print("[FRIDA ERROR]", message.get('stack', message))
        if logfile_handle:
            logfile_handle.write("[FRIDA ERROR] " + str(message) + "\n")

def main():
    ap = argparse.ArgumentParser(description="Robust Frida registry timestomp detector")
    group = ap.add_mutually_exclusive_group(required=True)
    group.add_argument("--attach", type=int, help="PID to attach")
    group.add_argument("--attach-name", type=str, help="Process name to attach (first match)")
    group.add_argument("--spawn", type=str, help="Spawn and instrument program (full path)")
    group.add_argument("--list", action="store_true", help="List processes")
    ap.add_argument("--args", type=str, default="", help="Args for spawn")
    ap.add_argument("--log", type=str, default="", help="Append logs to file")
    ap.add_argument("--timeout", type=int, default=0, help="Seconds to run (0 indefinite)")
    args = ap.parse_args()

    if args.list:
        list_processes_and_hint()
        return

    logfile_handle = None
    if args.log:
        try:
            logfile_handle = open(args.log, "a", encoding="utf-8", buffering=1)
        except Exception as e:
            print("[!] Could not open log:", e)

    session = None
    try:
        if args.attach:
            session = frida.attach(args.attach)
        elif args.attach_name:
            try:
                device = frida.get_local_device()
            except frida.ServerNotRunningError:
                print("[!] frida-server not found. Please start frida-server.exe (as admin).")
                sys.exit(1)

            procs = device.enumerate_processes()
            pid = None
            for p in procs:
                if p.name.lower() == args.attach_name.lower():
                    pid = p.pid; break
            if pid is None:
                print("Process not found:", args.attach_name); sys.exit(1)
            session = frida.attach(pid)
        elif args.spawn:
            spawn_args = [args.spawn] + (args.args.split() if args.args else [])
            pid = frida.spawn(spawn_args)
            session = frida.attach(pid)
            frida.resume(pid)

        script = session.create_script(FRIDA_SCRIPT)
        script.on('message', lambda m,d: on_message(m,d, logfile_handle))
        script.load()
        print("[*] Script loaded and hooks in place. Monitoring... (Ctrl-C to stop)")

        if args.timeout and args.timeout > 0:
            time.sleep(args.timeout)
        else:
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nInterrupted by user")
    except Exception as e:
        print("Error:", e)
    finally:
        if logfile_handle:
            logfile_handle.close()
        try:
            if session:
                session.detach()
        except:
            pass

if __name__ == "__main__":
    main()
