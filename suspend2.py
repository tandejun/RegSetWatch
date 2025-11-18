import frida
import sys

# --- Configuration ---
# ❗️ Replace this with the *full path* to your executable
EXE_PATH = r"C:\Users\ICT3215\Desktop\Project\SetRegTime-master\SetRegTime64.exe" 

# These are the arguments that will be passed to the executable
EXE_ARGS = [
    r"\Registry\Machine\System\test2",  # Arg 1: The registry key path
    "1976:04:01:00:00:00:000:0000",   # Arg 2: The new timestamp
    "-n"                             # Arg 3: The '-n' flag
]
# ---------------------

# We'll store the PID here to clean it up later
spawned_pid = 0

try:
    # Create the full command list: [executable, arg1, arg2, ...]
    command_line = [EXE_PATH] + EXE_ARGS
    
    print(f"[*] Spawning command in a suspended state:")
    # Pretty-print the command for verification
    print(f"    > \"{command_line[0]}\" {' '.join(command_line[1:])}")
    
    # frida.spawn() creates the process and leaves it suspended
    spawned_pid = frida.spawn(command_line)
    
    print(f"\n[+] SUCCESS!")
    print(f"[+] Process spawned with PID: {spawned_pid}")
    print(f"[+] The process is now suspended and waiting.")
    
    print("\nAttach your debugger or Frida script to this PID now.")
    print("Press [Enter] here to terminate the process and exit.")
    
    # This input() call blocks the script, keeping it alive.
    # While this script is waiting, the spawned process remains suspended.
    input()

except frida.PermissionDeniedError:
    print(f"[-] ERROR: Permission denied.")
    print(f"    Try running this script as an Administrator.")
except Exception as e:
    print(f"[-] An unexpected error occurred: {e}")

finally:
    # This ensures that when you press Enter (or if the script crashes),
    # we clean up the suspended process we created.
    if spawned_pid > 0:
        try:
            print(f"[*] Cleaning up... Terminating process {spawned_pid}.")
            # Attach to the PID just to kill it
            frida.attach(spawned_pid).kill()
            print("[+] Process terminated.")
        except Exception as e:
            # This might fail if you already killed/resumed it with another tool
            print(f"[-] Could not kill process {spawned_pid} (it may already be gone): {e}")