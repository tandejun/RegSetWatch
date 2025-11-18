import frida
import sys

# --- Configuration ---
EXE_PATH = r"C:\Users\ICT3215\Desktop\SetRegTime64.exe"

EXE_ARGS = [
    r"\Registry\Machine\System\mounteddevices",
    "1976:04:01:00:00:00:000:0000",
    "-n"
]
# ---------------------

spawned_pid = 0

try:
    command_line = [EXE_PATH] + EXE_ARGS

    print(f"[*] Spawning command in a suspended state:")
    print(f"    > \"{command_line[0]}\" {' '.join(command_line[1:])}")

    # spawn in suspended mode
    spawned_pid = frida.spawn(command_line)

    print(f"\n[+] SUCCESS!")
    print(f"[+] Process spawned with PID: {spawned_pid}")
    print(f"[+] The process is now suspended.")

    print("\nAttach your debugger or Frida script to this PID now.")
    print("Press [Enter] to RESUME the process and exit this script.")

    # Wait for user input before resuming
    input()

    print(f"[*] Resuming process {spawned_pid}...")
    frida.resume(spawned_pid)
    print("[+] Process resumed normally. This script will now exit.")

except frida.PermissionDeniedError:
    print("[-] ERROR: Permission denied. Try running as Administrator.")
except Exception as e:
    print(f"[-] Unexpected error: {e}")

finally:
    # ❗️ DO NOT KILL THE PROCESS
    #     We only resume it, and then leave it running.
    pass
