# RegSetWatch
Windows Agent for Automated Detection of Registry Timestomping

## How to run for one time use? (Recommended to try it out first)
1. Install the required dependencies using requirements.txt (pip install -r requirements.txt)
2. Open CMD as admin, execute frida-server.exe
3. Open another CMD as admin, run frida-local.py
4. Attempt to registry timestomping, an alert will be generated in frida-local.py. You may use an existing POC built by Joakim Schicht [(https://github.com/jschicht/SetRegTime)]
5. Optional: You may setup for logging by modifying parameters in frida-local.py 

## How to setup for constant monitoring?
1. Clone this repository
2. Execute the bat file (Run as Adminstrator)
3. Pwython will be copied from appdata to program files and the scripts are copied to C:\Scripts
4. A scheduled task will also be created to run on startup
5. On the next startup, the frida server and python script will start automatically
