# RegSetWatch

**Windows Registry Timestomping Detection System**

RegSetWatch is a kernel-mode driver and user-mode application suite designed to detect and alert on registry timestomping attacks. It monitors `NtSetInformationKey` API calls for `KeyWriteTimeInformation` usage, resolves registry paths for alerts, and can optionally scan registry hives for subkey-parent timestamp mismatches. Events can be forwarded to SIEM systems via syslog.

## Features

- **Real-time Monitoring**: Detects registry timestomping attempts as they occur
- **API Hooking**: Monitors `NtSetInformationKey` with `KeyWriteTimeInformation` class
- **Path Resolution**: Resolves full registry paths for detected operations
- **Hive Scanning**: Scans registry hives for timestamp anomalies (subkey-parent mismatches)
- **SIEM Integration**: Forwards alerts to SIEM systems via syslog (UDP)
- **Detailed Alerts**: Captures process information, timestamps, and registry paths
- **Testing Tools**: Includes PoC tool (SetRegTime) for testing detection capabilities

## Architecture

### Components

1. **RegSetWatch.sys** - Kernel driver
   - Registers callback for registry operations
   - Detects `KeyWriteTimeInformation` usage
   - Resolves registry paths
   - Queues alerts for user-mode retrieval

2. **RegSetWatchCtl.exe** - Control application
   - Start/stop monitoring
   - Retrieve alerts
   - Configure syslog forwarding
   - Trigger registry hive scans

3. **SetRegTime.exe** - Testing tool
   - Demonstrates timestomping techniques
   - Supports benign and malicious scenarios
   - Used to validate detection capabilities

## Quick Start

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- Administrator privileges
- Visual Studio 2019+ with WDK (for building)
- Test signing enabled (for unsigned drivers)

### Installation

1. **Enable test signing** (for development):
   ```cmd
   bcdedit /set testsigning on
   ```
   Reboot the system.

2. **Install the driver**:
   ```cmd
   install.bat
   ```

3. **Start monitoring**:
   ```cmd
   RegSetWatchCtl.exe start
   ```

### Basic Usage

**Start monitoring for timestomping:**
```cmd
RegSetWatchCtl.exe start
```

**Retrieve alerts:**
```cmd
RegSetWatchCtl.exe alerts
```

**Stop monitoring:**
```cmd
RegSetWatchCtl.exe stop
```

**Configure SIEM forwarding:**
```cmd
RegSetWatchCtl.exe syslog 192.168.1.100 514
```

**Scan registry hives:**
```cmd
RegSetWatchCtl.exe scan
```

## Testing

RegSetWatch includes a comprehensive testing tool and scenarios:

### Run Test Scenarios

```cmd
test_scenarios.bat
```

This script runs:
- **Benign test**: Sets current timestamp (should not alert)
- **Malicious test**: Backdates timestamp to 2010 (should alert)
- **Multiple operations**: Tests alert queuing

### Manual Testing

**Benign operation (current time):**
```cmd
SetRegTime.exe HKCU\Software\TestKey benign
```

**Malicious operation (backdated):**
```cmd
SetRegTime.exe HKCU\Software\TestKey
```

**Custom timestamp:**
```cmd
SetRegTime.exe HKCU\Software\TestKey 130000000000000000
```

## How It Works

### Detection Mechanism

1. **Registry Callback Registration**
   - Driver registers with `CmRegisterCallbackEx`
   - Receives notifications for all registry operations

2. **KeyWriteTimeInformation Detection**
   - Filters for `RegNtPreSetInformationKey` notifications
   - Checks if `KeySetInformationClass == KeyWriteTimeInformation`
   - This is the API used for registry timestomping

3. **Path Resolution**
   - Uses `ObQueryNameString` to resolve registry object paths
   - Converts kernel object to user-readable path

4. **Alert Generation**
   - Captures process ID and name
   - Records old and new timestamps
   - Flags suspicious operations
   - Queues alert for user-mode retrieval

5. **SIEM Integration**
   - Forwards alerts via syslog UDP protocol
   - Supports standard syslog format
   - Configurable server and port

### Registry Hive Scanning

The optional scanning feature:
- Recursively traverses registry hives
- Compares subkey timestamps with parent keys
- Detects anomalies where subkeys are older than parents
- Identifies potential historical timestomping

## Alert Format

Each alert contains:

```
Detection Time: 2025-11-04 10:30:45
Process ID: 1234
Process Name: SetRegTime.exe
Registry Path: \REGISTRY\MACHINE\Software\TestKey
New Timestamp: 2010-01-01 00:00:00
Suspicious: Yes
```

## Building from Source

### Requirements

- Windows Driver Kit (WDK) 10
- Visual Studio 2019 or later
- Windows 10 SDK

### Build Steps

**Driver:**
```cmd
build_driver.bat
```

**User-mode applications:**
```cmd
nmake /f Makefile
```

Or use Visual Studio to open and build the project.

## Configuration

Edit `config.ini` to configure:

- Monitoring on startup
- Syslog server details
- Timestamp age thresholds
- Debug logging

## Use Cases

1. **Malware Detection**: Identify malware using timestomping to evade detection
2. **Forensics**: Detect timestamp manipulation during investigations
3. **Compliance**: Monitor for unauthorized system modifications
4. **Threat Hunting**: Proactive detection of advanced persistence techniques
5. **SIEM Integration**: Feed alerts into security monitoring infrastructure

## Technical Details

### Timestomping Background

Registry timestomping is a technique used by attackers to:
- Hide malicious registry modifications
- Evade timeline-based detection
- Make malicious keys appear legitimate
- Complicate forensic investigations

The technique uses the undocumented `NtSetInformationKey` API with `KeyWriteTimeInformation` class to modify the `LastWriteTime` of registry keys.

### Detection Strategy

RegSetWatch detects timestomping by:
1. **Monitoring API calls**: Intercepts `NtSetInformationKey` at kernel level
2. **Analyzing parameters**: Checks for `KeyWriteTimeInformation` class
3. **Context analysis**: Evaluates if timestamp change is suspicious
4. **Anomaly detection**: Scans for timestamp inconsistencies in hives

## Security Considerations

- **Kernel mode**: Driver runs with high privileges
- **Production use**: Sign drivers with valid certificate
- **Testing**: Use test signing mode only in development
- **Monitoring**: Monitor the driver itself for tampering
- **Updates**: Keep RegSetWatch updated for latest detection techniques

## Known Limitations

- Requires kernel-level access (driver)
- Test signing mode reduces system security
- Performance impact on high-registry-activity systems
- Syslog implementation is basic (UDP only, no TLS)
- Hive scanning can be resource-intensive

## Future Enhancements

- [ ] Machine learning-based anomaly detection
- [ ] TLS support for syslog forwarding
- [ ] Real-time hive monitoring
- [ ] Configuration via GUI
- [ ] Integration with Windows Event Log
- [ ] Support for custom alert rules

## Documentation

- [USAGE.md](USAGE.md) - Detailed usage guide
- [config.ini](config.ini) - Configuration reference
- [test_scenarios.bat](test_scenarios.bat) - Test scenarios

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is provided for educational and research purposes.

## Disclaimer

This tool is provided for security research and defensive purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before monitoring or testing systems.

## References

- [MITRE ATT&CK - Timestomp](https://attack.mitre.org/techniques/T1070/006/)
- [Windows Registry Internals](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/registry-callbacks)
- [NtSetInformationKey Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationkey)

---

**We stopping timestomping with this one** 🛡️
