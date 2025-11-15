import frida
import sys
import time
import os
import concurrent.futures

# === Load JS Agent Code ===
try:
    with open(os.path.join(os.path.dirname(__file__), "agent.js"), "r", encoding="utf-8") as f:
        agent_code = f.read()
except FileNotFoundError:
    print("[!] Error: 'agent.js' not found in the same directory.")
    print("Please create the 'agent.js' file.")
    sys.exit(1)
except Exception as e:
    print(f"[!] Error loading 'agent.js': {e}")
    sys.exit(1)


# === Main Logic ===
def main():
    print("[*] Starting RegSetWatch POC...")
    print("[*] Monitoring for new processes (Windows mode, no gating)...")

    try:
        device = frida.get_local_device()
    except Exception as e:
        print(f"[!] Failed to get Frida device: {e}")
        sys.exit(1)

    # Try to enable spawn gating; if not supported fall back to polling
    use_spawn_gating = False
    try:
        device.enable_spawn_gating()
        use_spawn_gating = True
        print("[*] Spawn gating enabled (will receive spawn_added events).")
    except Exception:
        print("[*] Spawn gating not supported on this device. Falling back to polling for new processes.")

    # If spawn gating supported, register the event handler. Otherwise start poller.
    if use_spawn_gating:
        device.on("spawn_added", on_spawn_added)
    else:
        import threading

        # build initial set of existing PIDs
        try:
            seen_pids = {p.pid for p in device.enumerate_processes()}
        except Exception:
            seen_pids = set()

        def poll_for_new_processes():
            while True:
                try:
                    procs = {p.pid: p for p in device.enumerate_processes()}
                    for pid, proc in procs.items():
                        if pid not in seen_pids:
                            seen_pids.add(pid)
                            # create a tiny spawn-like object for on_spawn_added
                            class _Spawn:
                                def __init__(self, pid, identifier):
                                    self.pid = pid
                                    self.identifier = identifier
                            fake = _Spawn(pid, proc.name)
                            on_spawn_added(fake)
                except Exception:
                    # transient errors: keep polling
                    pass
                time.sleep(1)

        t = threading.Thread(target=poll_for_new_processes, daemon=True)
        t.start()

    INACTIVITY_TIMEOUT = 30
    MAX_WORKERS = 8
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS)

    HOOK_NAMES = {"setregtime64.exe"} # whitelist (None = all)
    SKIP_NAMES = {"svchost.exe", "lsass.exe", "VGAuthService.exe", "vm3dservice.exe"}  # blacklist

    # === Worker: handle new spawned process ===
    def handle_spawn(spawn):
        start_time = time.time()
        last_event = start_time
        
        session = None  # Define session in the outer scope for finally block
        script = None   # Define script in the outer scope for finally block

        def on_message_worker(message, data):
            nonlocal last_event
            last_event = time.time()
            if message["type"] == "send":
                payload = message["payload"]
                if payload.get("status") == "detection":
                    print(f"\n[{spawn.pid}] Registry timestomping detected!")
                    print(f"  Event: {payload.get('event')}")
                    print("------------------------------------------------------------")
                else:
                    print(f"[{spawn.pid}] {payload}")
            else:
                print(f"[{spawn.pid}] {message}")

        try:
            # --- This is the key change ---
            # We are attaching to an *already running* process
            session = device.attach(spawn.pid)
            print(f"[+] Attached to {spawn.identifier} (PID {spawn.pid})")

            script = session.create_script(agent_code)
            script.on("message", on_message_worker)
            script.load()
            print(f"[+] Agent injected into {spawn.identifier}")

            # --- REMOVED device.resume(spawn.pid) ---
            # The process was never suspended, so we don't resume it.

            # Monitor until exit or inactivity
            while True:
                alive = any(p.pid == spawn.pid for p in device.enumerate_processes())
                if not alive:
                    print(f"[+] PID {spawn.pid} exited; cleaning up.")
                    break

                if time.time() - last_event > INACTIVITY_TIMEOUT:
                    print(f"[-] PID {spawn.pid} inactive for {INACTIVITY_TIMEOUT}s; unloading.")
                    break
                time.sleep(1)

        except (frida.PermissionDeniedError, frida.ProcessNotFoundError):
            print(f"[!] Permission denied or process gone for PID {spawn.pid}. Skipping.")
            # --- REMOVED device.resume(spawn.pid) ---
            
        except Exception as e:
            print(f"[!] Worker failed for PID {spawn.pid}: {e}")
            # --- REMOVED device.resume(spawn.pid) ---
            
        finally:
            # Cleanup
            try:
                if script is not None:
                    script.unload()
            except Exception:
                pass  # Ignore cleanup errors
            try:
                if session is not None:
                    session.detach()
            except Exception:
                pass  # Ignore cleanup errors
            print(f"[+] Worker cleanup complete for PID {spawn.pid}.")

    # === Event: New process spawned ===
    def on_spawn_added(spawn):
        try:
            proc_name = os.path.basename(spawn.identifier).lower()
        except Exception:
            proc_name = spawn.identifier.lower()

        if HOOK_NAMES and proc_name not in HOOK_NAMES:
            print(f"[-] Skipping {proc_name} (not in whitelist)")
            # --- REMOVED device.resume(spawn.pid) ---
            return

        if proc_name in SKIP_NAMES:
            print(f"[-] Skipping {proc_name} (blacklisted)")
            # --- REMOVED device.resume(spawn.pid) ---
            return

        print(f"[+] New spawn detected: {proc_name} (PID {spawn.pid})")
        try:
            # Submit the spawn handling to the thread pool
            executor.submit(handle_spawn, spawn)
        except Exception as e:
            print(f"[!] Failed to submit worker for PID {spawn.pid}: {e}")
            # --- REMOVED device.resume(spawn.pid) ---

    # === Attach handler ===
    device.on("spawn_added", on_spawn_added)

    # === Keep Alive ===
    print("[*] Ready. Press Ctrl+C to stop.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Shutting down gracefully...")
        device.off("spawn_added", on_spawn_added)
        executor.shutdown(wait=True, cancel_futures=True)
        print("[*] All workers terminated.")


if __name__ == "__main__":
    main()