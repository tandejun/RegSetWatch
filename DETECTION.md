# Registry Timestomping Detection

## What is Registry Timestomping?

Registry timestomping is a technique used by attackers to manipulate the "LastWriteTime" metadata of Windows registry keys. This technique is used to:

1. **Evade Detection**: Make malicious registry modifications appear older or newer than they actually are
2. **Hide Timeline**: Obscure the true timeline of system compromise
3. **Appear Legitimate**: Blend malicious keys with legitimate system keys
4. **Complicate Forensics**: Make forensic timeline analysis more difficult

### MITRE ATT&CK

- **Technique**: T1070.006 - Indicator Removal on Host: Timestomp
- **Tactic**: Defense Evasion
- **Platforms**: Windows

## How Timestomping Works

### The API

Registry timestomping uses the undocumented Windows Native API:

```c
NTSTATUS NtSetInformationKey(
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength
);
```

When `KeySetInformationClass` is set to `KeyWriteTimeInformation` (value 0), this API allows modification of the registry key's LastWriteTime timestamp.

### Information Structure

```c
typedef struct _KEY_WRITE_TIME_INFORMATION {
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION;
```

The `LARGE_INTEGER` represents the timestamp in Windows FILETIME format (100-nanosecond intervals since January 1, 1601).

### Example Attack Flow

```
1. Attacker creates malicious registry key
   HKLM\Software\Malware\Config
   (Timestamp: 2025-11-04 10:30:00)

2. Attacker calls NtSetInformationKey with KeyWriteTimeInformation
   Sets timestamp to: 2020-01-01 00:00:00

3. Registry key now appears to have been created in 2020
   Making it appear as a legitimate, long-standing key

4. Standard forensic tools show old timestamp
   Investigation timeline is confused
```

## Detection Methods

### 1. API Monitoring (RegSetWatch)

**How it works:**
- Register kernel-mode callback with Configuration Manager
- Monitor all `NtSetInformationKey` calls
- Filter for `KeyWriteTimeInformation` class
- Generate alert with full context

**Advantages:**
- Real-time detection
- Captures exact moment of tampering
- Gets process and path information
- Cannot be easily bypassed

**Code Location:**
```c
// In RegSetWatch.c
NTSTATUS RegSetWatchRegistryCallback(
    PVOID CallbackContext,
    PVOID Argument1,
    PVOID Argument2
)
{
    if (notifyClass == RegNtPreSetInformationKey) {
        if (setInfoKey->KeySetInformationClass == KeyWriteTimeInformation) {
            // DETECTED!
        }
    }
}
```

### 2. Registry Hive Scanning

**How it works:**
- Recursively traverse registry hives
- Compare subkey timestamps with parent keys
- Identify anomalies (subkey older than parent)
- Flag suspicious timestamp relationships

**Advantages:**
- Detects historical tampering
- No need for real-time monitoring
- Can scan entire registry

**Limitations:**
- Resource intensive
- Cannot catch real-time attacks
- May have false positives

### 3. Timestamp Anomaly Analysis

**Indicators of timestomping:**

1. **Age Mismatch**
   - Key timestamp significantly older than expected
   - Key timestamp in the past relative to system install
   - Key timestamp in the future

2. **Parent-Child Mismatch**
   - Subkey timestamp older than parent key
   - Multiple subkeys with identical old timestamps

3. **Value Mismatch**
   - Key timestamp older than value timestamps
   - Values recently modified but key shows old timestamp

4. **System Inconsistency**
   - Key timestamp predates Windows installation
   - Key timestamp during system downtime
   - Key timestamp conflicts with other evidence

## Detection Patterns

### Pattern 1: Backdated Timestamps

```
Normal:  HKLM\Software\NewApp\Config (2025-11-04 10:30:00)
Suspect: HKLM\Software\NewApp\Config (2010-01-01 00:00:00)
                                       ^^^^^^^^^^^^^^^^
                                       Suspiciously old!
```

**Detection Logic:**
- Compare timestamp with current date
- Flag if timestamp is > N years in the past
- Alert if key was just accessed/modified

### Pattern 2: Future Timestamps

```
Current Date: 2025-11-04
Key Timestamp: 2030-01-01
               ^^^^^^^^
               In the future!
```

**Detection Logic:**
- Compare timestamp with current system time
- Flag any timestamp in the future

### Pattern 3: Parent-Child Inversion

```
Parent: HKLM\Software\App (2025-11-04 10:30:00)
Child:  HKLM\Software\App\Config (2010-01-01 00:00:00)
                                   ^^^^^^^^^^^^^^^^
                                   Older than parent!
```

**Detection Logic:**
- Recursively scan hives
- Compare each subkey with parent
- Flag when subkey < parent

### Pattern 4: Round Number Timestamps

```
Timestamp: 2020-01-01 00:00:00
           ^^^^^^^^^^^^^^^^^^^
           Too clean!
```

**Detection Logic:**
- Check for timestamps at exact midnight
- Check for January 1st dates
- Flag round number timestamps (2000, 2010, 2020)

## RegSetWatch Detection Strategy

### Real-Time Monitoring

```
[Detection Flow]

Application calls NtSetInformationKey
              ↓
Registry Manager invokes callbacks
              ↓
RegSetWatch callback executes
              ↓
Check: KeySetInformationClass == KeyWriteTimeInformation?
              ↓
            YES → ALERT!
              ↓
Capture:
- Process ID and Name
- Registry Path
- Old Timestamp (if available)
- New Timestamp
- Detection Time
              ↓
Add to Alert Queue
              ↓
(Optional) Forward to SIEM
```

### Alert Context

Each alert includes:

```
{
    "detection_time": "2025-11-04 10:30:45",
    "process_id": 1234,
    "process_name": "malware.exe",
    "registry_path": "\\REGISTRY\\MACHINE\\Software\\Malware",
    "old_timestamp": "2025-11-04 10:30:44",
    "new_timestamp": "2010-01-01 00:00:00",
    "suspicious": true
}
```

### Suspicion Scoring

Factors that increase suspicion score:

1. **Timestamp Age**: Older than system installation
2. **Process Reputation**: Unknown or untrusted process
3. **Registry Location**: Critical system keys
4. **Timestamp Type**: Round numbers, future dates
5. **Frequency**: Multiple timestomping operations
6. **Context**: No legitimate reason for operation

## Evasion Techniques and Counter-Measures

### Evasion 1: Disable Driver

**Attempt:** Stop or unload RegSetWatch driver

**Counter-Measure:**
- Protected driver service
- Monitor driver status
- Alert on driver stop attempts
- Use signed drivers with anti-tampering

### Evasion 2: Direct Kernel Manipulation

**Attempt:** Modify registry data structures directly in kernel memory

**Counter-Measure:**
- Memory integrity checks
- Kernel patch protection
- Secure boot
- This bypasses API monitoring (limitation)

### Evasion 3: Time-Based Evasion

**Attempt:** Set timestamps to recent but plausible values

**Counter-Measure:**
- Behavioral analysis
- Timestamp consistency checks
- Multiple detection methods
- Machine learning for anomaly detection

### Evasion 4: Process Hollowing

**Attempt:** Execute timestomping from legitimate process

**Counter-Measure:**
- Process behavior analysis
- Call stack analysis
- Code signing verification

## Integration with SIEM

### Syslog Message Format

```
<Priority>Timestamp Hostname RegSetWatch[PID]: Registry timestomping detected - Process: malware.exe (1234), Path: \\REGISTRY\\MACHINE\\Software\\Malware, NewTimestamp: 2010-01-01 00:00:00
```

### SIEM Correlation Rules

**Rule 1: Multiple Timestomping**
```
IF count(timestomp_alerts) > 5 IN 1 minute
THEN raise_critical_alert("Aggressive timestomping detected")
```

**Rule 2: Critical Path Timestomping**
```
IF timestomp_alert.path CONTAINS "\\CurrentVersion\\Run"
THEN raise_high_alert("Persistence mechanism timestomped")
```

**Rule 3: Known Malware Process**
```
IF timestomp_alert.process IN malware_process_list
THEN raise_critical_alert("Known malware timestomping")
```

## False Positives

### Legitimate Use Cases

Some legitimate scenarios may trigger alerts:

1. **System Restore**: Restoring backed-up registry keys
2. **Software Installation**: Some installers modify timestamps
3. **Synchronization**: Syncing registry between systems
4. **Testing Tools**: Legitimate security testing

### Reducing False Positives

1. **Whitelist trusted processes**
   - System processes
   - Trusted applications
   - Known backup tools

2. **Context analysis**
   - Check if timestamp is reasonable
   - Verify process legitimacy
   - Correlate with other events

3. **Threshold tuning**
   - Adjust age thresholds
   - Consider system installation date
   - Account for timezone differences

## Best Practices

### For Detection

1. **Enable Real-Time Monitoring**: Start RegSetWatch on boot
2. **Integrate with SIEM**: Forward all alerts for correlation
3. **Regular Scans**: Periodically scan hives for historical tampering
4. **Baseline Normal Behavior**: Understand legitimate timestamp patterns
5. **Investigate All Alerts**: Every alert warrants investigation

### For Response

1. **Immediate Actions**:
   - Isolate affected system
   - Capture memory dump
   - Export registry for analysis
   - Identify attacker process

2. **Investigation**:
   - Analyze alert context
   - Check process legitimacy
   - Review other indicators
   - Correlate with other events

3. **Remediation**:
   - Remove malicious keys
   - Clean infected files
   - Restore correct timestamps
   - Update security controls

## Testing and Validation

### Test Scenarios

Use `SetRegTime.exe` for testing:

**Benign Test:**
```cmd
SetRegTime.exe HKCU\Software\TestKey benign
```
Expected: Alert generated, suspicious=false

**Malicious Test:**
```cmd
SetRegTime.exe HKCU\Software\TestKey
```
Expected: Alert generated, suspicious=true

### Validation Checklist

- [ ] Alert is generated for timestomping attempt
- [ ] Process information is captured correctly
- [ ] Registry path is resolved accurately
- [ ] Timestamps are recorded properly
- [ ] Syslog forwarding works (if enabled)
- [ ] No false negatives for malicious operations
- [ ] Acceptable false positive rate

## References

- [MITRE ATT&CK - T1070.006](https://attack.mitre.org/techniques/T1070/006/)
- [Windows Registry Internals](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/registry-key-object-routines)
- [NtSetInformationKey Documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationkey)
- [Registry Forensics](https://www.forensicfocus.com/articles/windows-registry-forensics/)

## Conclusion

Registry timestomping is a sophisticated evasion technique, but with proper monitoring and analysis, it can be reliably detected. RegSetWatch provides real-time detection at the kernel level, making it extremely difficult for attackers to bypass. Combined with hive scanning and SIEM integration, it provides comprehensive protection against this threat.
