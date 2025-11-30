# RegSetWatch
we stopping timestomping with this one
<br>
<br>
<br>
## Kiwi Syslog Server NG – TLS Setup & Python Forwarder

This guide explains how to configure **Kiwi Syslog Server NG** to receive **TLS-secured syslog messages**, export the TLS certificate, and forward logs using a Python script.

---

## Setup Instructions

### 1. Install Kiwi Syslog Server NG
1. Download **Kiwi Syslog Server NG (Trial Version)** from SolarWinds.
2. After installation, open the **Web Console** on localhost port 5000.

---

## Configure Secure TCP (TLS) Input

1. Open the web console and go to:  
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

---

## Export the TLS Certificate

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

