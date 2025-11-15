import frida
import sys
import os

# === Configuration ===
# !!! UPDATE THIS PATH to the full path of your .exe !!!
TARGET_PROGRAM = r"SetRegTime64.exe"

# These are the arguments from your command
TARGET_ARGS = [
    r"\Registry\Machine\System\mounteddevices",
    "1944:12:24:00:00:00:000:0000",
    "-n"
]

def main():
    print(f"[*] Spawning '{os.path.basename(TARGET_PROGRAM)}' in a suspended state...")
    
    try:
        device = frida.get_local_device()
        
        spawn_command = [TARGET_PROGRAM] + TARGET_ARGS
        
        # 1. Spawn the program, but tell it to stay suspended
        pid = device.spawn(spawn_command)
        
        print(f"\n[SUCCESS] Process is suspended with PID: {pid}")
        print(f"  Command: {spawn_command}")

    except frida.ProcessNotFoundError:
        print(f"\n[!] Error: Could not find process. Is the path correct?")
        print(f"  -> {TARGET_PROGRAM}")
        sys.exit(1)
    except frida.PermissionDeniedError:
        print("\n[!] Error: Permission denied. Run this script as Administrator.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] An unexpected error occurred: {e}")
        sys.exit(1)

    print("\n[*] This script is now holding the process suspended.")
    print("[*] You can now attach your agent or a debugger to this PID.")
    print("[*] Press Ctrl+C in this window to terminate this script (which will also terminate the suspended process).")

    try:
        # Keep this script alive. If this script exits,
        # the suspended process it spawned will be terminated by the OS.
        sys.stdin.read()
    except KeyboardInterrupt:
        print("\n[*] Exiting. The suspended process will be terminated.")
        try:
            # Try to gracefully kill the child process
            device.kill(pid)
        except Exception:
            pass # It might already be gone

if __name__ == "__main__":
    main()