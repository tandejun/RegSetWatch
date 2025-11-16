# RegSetWatch
we stopping timestomping with this one

Syslog setup: 
🔧 Setup Instructions
### 1. Install Kiwi Syslog Server NG

Download Kiwi Syslog Server NG (Trial Version) from SolarWinds.

After installation, open the Web Console.

⚙️ Configure Secure TCP (TLS) Input

Open the web console and go to:
Setup → Settings → Inputs

Under Secure TCP, enable:
✔ Listen for secure (TLS) TCP Syslog messages

Select your desired TCP port.

Under Windows Certificate, choose:
Kiwi Syslog Server NG

Click Apply.

Restart the Kiwi service:

Open services.msc

Find Kiwi Syslog Server NG

Click Restart

🔐 Export the TLS Certificate

Open certlm.msc

Navigate to:
Personal → Certificates

Right-click Kiwi Syslog Server NG → All Tasks → Export

Select:
No, do not export the private key

Choose the format:
Base-64 encoded X.509 (.CER)

Choose output folder & file name.

Click Finish to export the certificate.

📤 Forwarding Logs to the Server (Python)

Copy the exported certificate (from the setup section) into the same folder as your Python script main.py.

Run main.py
