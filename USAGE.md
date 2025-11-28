# RegSetWatch Usage Guide

## Overview

RegSetWatch is a Windows kernel driver and user-mode application suite designed to detect registry timestomping attacks. It monitors `NtSetInformationKey` API calls for `KeyWriteTimeInformation` usage, resolves registry paths for alerts, and can optionally scan registry hives for subkey-parent timestamp mismatches.

## Components

1. **RegSetWatch.sys** - Kernel driver that monitors registry operations
2. **RegSetWatchCtl.exe** - User-mode control application
3. **SetRegTime.exe** - Proof-of-concept timestomping tool for testing

## Installation

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- Driver signing disabled for test mode (for unsigned drivers)

### Installing the Driver

1. Build or obtain the driver binary (`RegSetWatch.sys`)
2. Run `install.bat` as Administrator:
   ```
   install.bat
   ```

### Enabling Test Mode (for unsigned drivers)

```cmd
bcdedit /set testsigning on
```

Then reboot the system.

## Basic Usage

### Starting Monitoring

To start monitoring for registry timestomping:

```cmd
RegSetWatchCtl.exe start
```

### Stopping Monitoring

To stop monitoring:

```cmd
RegSetWatchCtl.exe stop
```

### Retrieving Alerts

To retrieve and display all detected alerts:

```cmd
RegSetWatchCtl.exe alerts
```

Sample output:
```
===== Alert #1 =====
Detection Time: 2025-11-04 10:30:45
Process ID: 1234
Process Name: SetRegTime.exe
Registry Path: \REGISTRY\MACHINE\Software\TestKey
New Timestamp: 2010-01-01 00:00:00
Suspicious: Yes
```

### Scanning Registry Hives

To scan registry hives for timestamp mismatches:

```cmd
RegSetWatchCtl.exe scan
```

This feature scans for subkeys that have timestamps newer than their parent keys, which could indicate timestomping.

### Configuring Syslog Forwarding

To forward alerts to a SIEM system via syslog:

```cmd
RegSetWatchCtl.exe syslog <server_ip> <port>
```

Example:
```cmd
RegSetWatchCtl.exe syslog 192.168.1.100 514
```

## Testing

### Benign Test

Create a registry key with current timestamp (should not trigger alert):

```cmd
SetRegTime.exe HKCU\Software\TestKey benign
```

### Malicious Test

Create a registry key with backdated timestamp (should trigger alert):

```cmd
SetRegTime.exe HKCU\Software\TestKey
```

This sets the timestamp to 2010-01-01, which is suspicious and will be detected by RegSetWatch.

### Custom Timestamp Test

Set a specific timestamp using FILETIME format:

```cmd
SetRegTime.exe HKCU\Software\TestKey 130000000000000000
```

## Alert Details

Each alert contains:

- **Detection Time**: When the timestomping attempt was detected
- **Process ID**: ID of the process that performed the operation
- **Process Name**: Name of the executable that performed the operation
- **Registry Path**: Full path to the affected registry key
- **New Timestamp**: The timestamp that was set
- **Suspicious**: Boolean flag indicating if the operation is suspicious

## SIEM Integration

RegSetWatch can forward alerts to SIEM systems via syslog protocol (UDP port 514 by default). Configure the syslog server address and port using the control application.

The syslog messages are formatted as:

```
<Priority>Timestamp Hostname RegSetWatch[PID]: Alert details
```

## Common Registry Paths

- `HKLM\Software\*` - Local machine software settings
- `HKCU\Software\*` - Current user software settings
- `HKLM\System\*` - System configuration
- `HKLM\Security\*` - Security settings

## Best Practices

1. **Enable monitoring at boot** - Start RegSetWatch automatically on system startup
2. **Configure SIEM forwarding** - Integrate with your security monitoring infrastructure
3. **Regular scans** - Run periodic registry hive scans to detect existing timestomping
4. **Monitor alerts** - Regularly check alerts for suspicious activity
5. **Test thoroughly** - Use SetRegTime.exe to verify detection capabilities

## Troubleshooting

### Driver Won't Load

- Ensure you're running as Administrator
- Check if test signing is enabled (`bcdedit /enum`)
- Verify driver file is present in System32\drivers
- Check Windows Event Log for error messages

### No Alerts Generated

- Verify monitoring is started (`RegSetWatchCtl.exe start`)
- Check if driver is running (`sc query RegSetWatch`)
- Test with SetRegTime.exe to confirm detection

### Permission Denied

- Ensure you're running with Administrator privileges
- Check if the device is accessible (`\\.\RegSetWatch`)

## Uninstallation

To uninstall RegSetWatch:

```cmd
uninstall.bat
```

Or manually:
```cmd
sc stop RegSetWatch
sc delete RegSetWatch
```

## Security Considerations

- RegSetWatch requires kernel-level access
- Only use signed drivers in production environments
- Monitor the driver itself for tampering
- Regularly update to latest version

## Support

For issues, questions, or contributions, please visit the project repository.
