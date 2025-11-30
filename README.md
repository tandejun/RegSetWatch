# RegSetWatch
Windows Agent for Automated Detection of Registry Timestomping

## How to run for one time use? (Recommended to try it out first)
1. Install the required dependencies using requirements.txt (pip install -r requirements.txt)
2. Open CMD as admin, execute frida-server.exe
3. Open another CMD as admin, run frida-local.py
4. Attempt to registry timestomping, an alert will be generated in frida-local.py. You may use an existing POC built by Joakim Schicht [https://github.com/jschicht/SetRegTime]
5. Optional: You may setup for logging by modifying parameters in frida-local.py. The program supports logging via Syslog, and if you do not have a Syslog server setup, you may refer to the guide below.

## How to setup for constant monitoring?
1. Clone this repository
2. Execute the bat file (Run as Adminstrator)
3. Pwython will be copied from appdata to program files and the scripts are copied to C:\Scripts
4. A scheduled task will also be created to run on startup
5. On the next startup, the frida server and python script will start automatically


## Kiwi Syslog Server NG – TLS Setup & Python Forwarder

This guide explains how to configure **Kiwi Syslog Server NG** to receive **TLS-secured syslog messages**, export the TLS certificate, and forward logs using a Python script.

### Install Kiwi Syslog Server NG
1. Download **Kiwi Syslog Server NG (Trial Version)** from SolarWinds.
2. After installation, open the **Web Console** on localhost port 5000.


### Configure Secure TCP (TLS) Input

1. Open the web console of Kiwi Syslog Server NG and go to:  
   **Setup → Settings → Inputs**
2. Under **Secure TCP**, enable:  
   **Listen for secure (TLS) TCP Syslog messages**
3. Select your desired **TCP port**.
4. Under **Windows Certificate**, choose:  
   **Kiwi Syslog Server NG**
5. Click **Apply**.
6. Restart the Kiwi service:
   - Open **services.msc**
   - Find **Kiwi Syslog Server NG**
   - Click **Restart**

### Export the TLS Certificate

1. Open **certlm.msc**
2. Navigate to:  
   **Personal → Certificates**
3. Right-click **Kiwi Syslog Server NG** → **All Tasks → Export**
4. Select:  
   **No, do not export the private key**
5. Choose the format:  
   **Base-64 encoded X.509 (.CER)**
6. Choose output folder & file name.
7. Click **Finish** to export the certificate.

---

## Forwarding Logs to the Server (Python)

1. Copy the exported certificate into the same folder as your Python script.
2. Modify the ip address and port number on frida_local.py
