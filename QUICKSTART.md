# RegSetWatch Quick Start Guide

## 🚀 Get Started in 5 Minutes

This guide will help you quickly set up and test RegSetWatch.

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- Visual Studio 2019+ with Windows Driver Kit (WDK) for building
- Or pre-built binaries

## Step 1: Enable Test Signing (Development Only)

**⚠️ WARNING**: Test signing mode reduces system security. Only use in development/testing environments.

```cmd
# Open Command Prompt as Administrator
bcdedit /set testsigning on

# Reboot your system
shutdown /r /t 0
```

## Step 2: Build (Optional)

If you have the source code and want to build:

### Build User-Mode Applications

```cmd
# Using Visual Studio Developer Command Prompt
cd RegSetWatch
nmake /f Makefile
```

This creates:
- `RegSetWatchCtl.exe` - Control application
- `SetRegTime.exe` - Testing tool

### Build Driver

```cmd
# Using WDK environment
build_driver.bat
```

This creates:
- `RegSetWatch.sys` - Kernel driver

## Step 3: Install the Driver

```cmd
# Run as Administrator
install.bat
```

Expected output:
```
====================================
Installing RegSetWatch Driver
====================================

[*] Stopping existing service (if running)...
[*] Deleting existing service (if exists)...
[*] Creating service...
[*] Starting service...

[+] RegSetWatch driver installed and started successfully!
```

## Step 4: Start Monitoring

```cmd
RegSetWatchCtl.exe start
```

Expected output:
```
[*] Opening device...
[*] Starting monitoring...
[+] Monitoring started successfully
```

## Step 5: Test Detection

### Run Test Scenarios

```cmd
test_scenarios.bat
```

This will:
1. Create a benign test (current timestamp) - Should NOT be flagged as suspicious
2. Create malicious tests (backdated timestamps) - SHOULD be flagged as suspicious
3. Automatically retrieve and display alerts

### Manual Testing

**Test 1: Benign Operation**
```cmd
SetRegTime.exe HKCU\Software\TestKey benign
```

**Test 2: Malicious Operation**
```cmd
SetRegTime.exe HKCU\Software\TestKey
```

## Step 6: View Alerts

```cmd
RegSetWatchCtl.exe alerts
```

Example output:
```
[*] Opening device...
[*] Retrieving alerts...

===== Alert #1 =====
Detection Time: 2025-11-04 10:30:45
Process ID: 1234
Process Name: SetRegTime.exe
Registry Path: \REGISTRY\USER\S-1-5-21-xxx\Software\TestKey
New Timestamp: 2010-01-01 00:00:00
Suspicious: Yes

[+] Retrieved 1 alert(s)
```

## Step 7: Configure SIEM (Optional)

If you want to forward alerts to a SIEM system:

```cmd
RegSetWatchCtl.exe syslog 192.168.1.100 514
```

## Step 8: Stop Monitoring (Optional)

```cmd
RegSetWatchCtl.exe stop
```

## Step 9: Uninstall (When Done)

```cmd
uninstall.bat
```

## Troubleshooting

### Driver Won't Load

**Problem**: Service fails to start

**Solutions**:
1. Check if test signing is enabled:
   ```cmd
   bcdedit /enum | findstr testsigning
   ```
   Should show: `testsigning Yes`

2. Verify driver file exists:
   ```cmd
   dir %SystemRoot%\System32\drivers\RegSetWatch.sys
   ```

3. Check Event Viewer for errors:
   - Open Event Viewer
   - Navigate to: Windows Logs → System
   - Look for errors related to RegSetWatch

### No Device Found

**Problem**: `Failed to open device`

**Solutions**:
1. Check if service is running:
   ```cmd
   sc query RegSetWatch
   ```
   Should show: `STATE: RUNNING`

2. If not running, start it:
   ```cmd
   sc start RegSetWatch
   ```

### No Alerts Generated

**Problem**: Test runs but no alerts appear

**Solutions**:
1. Verify monitoring is started:
   ```cmd
   RegSetWatchCtl.exe start
   ```

2. Check driver logs:
   ```cmd
   # Use DebugView from Sysinternals
   # Filter for: RegSetWatch
   ```

3. Verify test ran successfully:
   - SetRegTime.exe should return 0 (success)
   - Check if registry key was created

## Common Commands Reference

| Command | Description |
|---------|-------------|
| `RegSetWatchCtl.exe start` | Start monitoring |
| `RegSetWatchCtl.exe stop` | Stop monitoring |
| `RegSetWatchCtl.exe alerts` | Get alerts |
| `RegSetWatchCtl.exe scan` | Scan registry hives |
| `RegSetWatchCtl.exe syslog <ip> <port>` | Configure SIEM |
| `SetRegTime.exe <path>` | Test with backdated timestamp |
| `SetRegTime.exe <path> benign` | Test with current timestamp |
| `sc query RegSetWatch` | Check driver status |
| `sc start RegSetWatch` | Start driver |
| `sc stop RegSetWatch` | Stop driver |

## Testing Checklist

- [ ] Test signing enabled
- [ ] Driver installed successfully
- [ ] Driver service is running
- [ ] Monitoring started
- [ ] Benign test generates alert (Suspicious: No)
- [ ] Malicious test generates alert (Suspicious: Yes)
- [ ] Alerts can be retrieved
- [ ] SIEM forwarding configured (if needed)

## Security Notes

### For Testing
- ✅ Use test signing mode
- ✅ Test in isolated environment
- ✅ Use virtual machines
- ✅ Document all tests

### For Production
- ❌ DO NOT use test signing
- ✅ Use properly signed drivers
- ✅ Enable secure boot
- ✅ Monitor driver integrity
- ✅ Integrate with SIEM

## Next Steps

1. **Read Full Documentation**
   - [USAGE.md](USAGE.md) - Detailed usage guide
   - [ARCHITECTURE.md](ARCHITECTURE.md) - System architecture
   - [DETECTION.md](DETECTION.md) - Detection methodology

2. **Customize Configuration**
   - Edit [config.ini](config.ini)
   - Set up monitoring rules
   - Configure alert thresholds

3. **Integrate with SIEM**
   - Configure syslog forwarding
   - Set up correlation rules
   - Create alert dashboards

4. **Test Thoroughly**
   - Run all test scenarios
   - Verify detection accuracy
   - Tune for false positives

## Example Workflow

```cmd
# 1. Install
install.bat

# 2. Start monitoring
RegSetWatchCtl.exe start

# 3. Configure SIEM (optional)
RegSetWatchCtl.exe syslog 192.168.1.100 514

# 4. Run tests
test_scenarios.bat

# 5. Check alerts
RegSetWatchCtl.exe alerts

# 6. Clean up test keys
reg delete HKCU\Software\RegSetWatchTest /f

# 7. When done
RegSetWatchCtl.exe stop
```

## Getting Help

- Check documentation files in the repository
- Review debug output with DebugView
- Check Windows Event Viewer
- Examine driver logs

## Cleanup

To completely remove RegSetWatch:

```cmd
# 1. Stop monitoring
RegSetWatchCtl.exe stop

# 2. Uninstall driver
uninstall.bat

# 3. Remove test keys
reg delete HKCU\Software\RegSetWatchTest /f
reg delete HKLM\Software\RegSetWatchTest /f

# 4. Disable test signing (optional)
bcdedit /set testsigning off

# 5. Reboot
shutdown /r /t 0
```

---

**Ready to detect timestomping? Let's go! 🛡️**
