# RegSetWatch Architecture

## Overview

RegSetWatch is a Windows security tool designed to detect registry timestomping attacks. It consists of a kernel-mode driver that monitors registry operations and user-mode applications for control and testing.

## Components

### 1. Kernel Driver (RegSetWatch.sys)

The core component that operates in kernel mode with the following responsibilities:

#### Registry Callback System
- Registers with the Configuration Manager using `CmRegisterCallbackEx`
- Receives pre and post notifications for all registry operations
- Filters specifically for `RegNtPreSetInformationKey` operations
- Operates at altitude "385200" for proper callback ordering

#### Detection Logic
```
Registry Operation → Callback → Check KeySetInformationClass
                                       ↓
                        KeyWriteTimeInformation?
                                       ↓
                                    Yes → Generate Alert
                                       ↓
                              Resolve Registry Path
                                       ↓
                           Capture Process Information
                                       ↓
                              Add to Alert Queue
                                       ↓
                      (Optional) Send to Syslog
```

#### Alert Queue Management
- Lock-protected queue using KSPIN_LOCK
- Dynamically allocated alert entries
- FIFO ordering for reliable alert retrieval
- Memory management using pool allocations with custom tag

#### Path Resolution
- Uses `ObQueryNameString` to resolve registry object handles
- Converts kernel registry paths to user-readable format
- Handles dynamic memory allocation for path buffers
- Error handling for unresolvable paths

### 2. Control Application (RegSetWatchCtl.exe)

User-mode application providing interface to the driver:

#### Command Interface
```
RegSetWatchCtl.exe → Open Device (\\.\RegSetWatch)
                            ↓
                    Send IOCTL Commands
                            ↓
                ┌───────────┴───────────┐
                ↓                       ↓
        Control Operations        Data Operations
        - Start monitoring        - Get alerts
        - Stop monitoring         - Configure syslog
        - Scan hives
```

#### IOCTL Communication
- Uses `DeviceIoControl` for driver communication
- Synchronous operations for control commands
- Buffer-based data transfer for alerts
- Error handling and status reporting

### 3. Testing Tool (SetRegTime.exe)

Proof-of-concept application demonstrating timestomping:

#### Timestomping Technique
```
User Request → Parse Registry Path
                      ↓
            Open/Create Registry Key
                      ↓
        Load NtSetInformationKey from ntdll
                      ↓
        Call with KeyWriteTimeInformation
                      ↓
            (RegSetWatch Detects)
                      ↓
              Timestamp Modified
```

## Data Structures

### REGSETWATCH_ALERT
```c
typedef struct _REGSETWATCH_ALERT {
    LARGE_INTEGER Timestamp;      // Detection time
    ULONG ProcessId;               // Process that performed operation
    WCHAR ProcessName[256];        // Process executable name
    WCHAR RegistryPath[512];       // Full registry path
    LARGE_INTEGER OldTimestamp;    // Original timestamp (if available)
    LARGE_INTEGER NewTimestamp;    // New timestamp being set
    BOOLEAN IsSuspicious;          // Suspicion flag
} REGSETWATCH_ALERT;
```

### REGSETWATCH_CONFIG
```c
typedef struct _REGSETWATCH_CONFIG {
    BOOLEAN MonitoringEnabled;     // Monitoring state
    BOOLEAN ScanningEnabled;       // Hive scanning state
    BOOLEAN SyslogEnabled;         // Syslog forwarding state
    CHAR SyslogServer[256];        // Syslog server address
    USHORT SyslogPort;             // Syslog server port
    FAST_MUTEX ConfigLock;         // Configuration protection
} REGSETWATCH_CONFIG;
```

### ALERT_QUEUE_ENTRY
```c
typedef struct _ALERT_QUEUE_ENTRY {
    LIST_ENTRY ListEntry;          // Doubly-linked list entry
    REGSETWATCH_ALERT Alert;       // Alert data
} ALERT_QUEUE_ENTRY;
```

## Communication Flow

### Starting Monitoring

```
User: RegSetWatchCtl.exe start
         ↓
    Open Device Handle
         ↓
    Send IOCTL_REGSETWATCH_START_MONITOR
         ↓
    Driver: Register Registry Callback
         ↓
    Driver: Set MonitoringEnabled = TRUE
         ↓
    Return Success
         ↓
    User: Display "Monitoring started"
```

### Alert Generation and Retrieval

```
Application: NtSetInformationKey(KeyWriteTimeInformation)
         ↓
    Registry Manager: Notify Callbacks
         ↓
    RegSetWatch Callback: Detect KeyWriteTimeInformation
         ↓
    Generate Alert Structure
         ↓
    Resolve Registry Path
         ↓
    Capture Process Info
         ↓
    Add to Alert Queue (with SpinLock)
         ↓
    (Optional) Send to Syslog
         
         ... (later) ...
         
User: RegSetWatchCtl.exe alerts
         ↓
    Send IOCTL_REGSETWATCH_GET_ALERTS
         ↓
    Driver: Acquire SpinLock
         ↓
    Remove Alert from Queue
         ↓
    Copy to User Buffer
         ↓
    Release SpinLock
         ↓
    Return Alert
         ↓
    User: Display Alert Information
```

## Threading Model

### Driver Threading
- Callbacks execute in arbitrary thread context
- SpinLocks protect alert queue (IRQL <= DISPATCH_LEVEL)
- Fast Mutex protects configuration (IRQL == PASSIVE_LEVEL)
- No dedicated driver threads

### Synchronization Mechanisms
1. **KSPIN_LOCK** for alert queue
   - High-performance locking
   - Protects concurrent queue access
   - Used in callback context

2. **FAST_MUTEX** for configuration
   - Allows blocking operations
   - Protects configuration changes
   - Used in IOCTL handlers

## Memory Management

### Allocation Strategy
- Pool allocations with custom tag 'wSgR' (RegSetWatch)
- NonPagedPool for alert queue entries (accessible at DISPATCH_LEVEL)
- Dynamic allocation for path resolution
- Proper cleanup on driver unload

### Memory Lifecycle
```
Driver Load:
  - Allocate global structures
  - Initialize lists and locks
  
Alert Generation:
  - Allocate ALERT_QUEUE_ENTRY
  - Add to queue
  
Alert Retrieval:
  - Remove from queue
  - Copy to user buffer
  - Free ALERT_QUEUE_ENTRY
  
Driver Unload:
  - Drain alert queue
  - Free all allocations
  - Release synchronization objects
```

## Security Considerations

### Driver Security
- Device secured with FILE_DEVICE_SECURE_OPEN
- Requires administrative privileges to access
- Validates all user-mode input buffers
- Prevents buffer overflows with size checks

### Attack Surface
- Device object is accessible to administrators only
- IOCTL interface requires valid handles
- No user-mode callbacks (unidirectional communication)
- Registry callback cannot be unregistered externally

## Performance Characteristics

### Overhead
- Minimal overhead for non-timestomping operations
- Callback executes only for SetInformationKey
- Fast path for non-KeyWriteTimeInformation operations
- Alert queue bounded by available memory

### Scalability
- Can handle multiple simultaneous operations
- Lock contention minimal with spinlocks
- No global registry serialization
- Queue grows as needed

## Error Handling

### Driver Error Handling
```c
// Pattern used throughout driver
status = Operation();
if (!NT_SUCCESS(status)) {
    DbgPrint("[RegSetWatch] Operation failed: 0x%X\n", status);
    // Cleanup and return error
    return status;
}
```

### User-Mode Error Handling
- GetLastError() for all API failures
- Descriptive error messages
- Graceful degradation on driver unavailability
- Return codes indicate success/failure

## Extension Points

### Future Enhancements
1. **Machine Learning Integration**
   - Behavioral analysis of timestamp patterns
   - Anomaly scoring system
   - Training data collection

2. **Advanced Scanning**
   - Real-time hive monitoring
   - Recursive subkey analysis
   - Timestamp consistency checks

3. **Enhanced Reporting**
   - Windows Event Log integration
   - JSON alert format
   - REST API for alert retrieval

4. **Configuration**
   - Dynamic configuration reloading
   - Per-process whitelisting
   - Custom alert rules

## Testing Strategy

### Unit Testing
- Individual function validation
- Edge case testing
- Error condition handling

### Integration Testing
- Driver-to-usermode communication
- Alert generation and retrieval
- Configuration changes

### System Testing
- End-to-end scenarios
- Performance testing
- Stability testing

### Security Testing
- Privilege escalation attempts
- Buffer overflow testing
- Race condition testing

## Deployment Architecture

```
┌─────────────────────────────────────┐
│         Windows System              │
│                                     │
│  ┌──────────────────────────────┐  │
│  │   User Mode                  │  │
│  │                              │  │
│  │  ┌─────────────────────┐    │  │
│  │  │ RegSetWatchCtl.exe  │    │  │
│  │  └──────────┬──────────┘    │  │
│  │             │ IOCTL          │  │
│  └─────────────┼────────────────┘  │
│                │                    │
│  ┌─────────────┼────────────────┐  │
│  │   Kernel Mode│               │  │
│  │              ↓               │  │
│  │  ┌─────────────────────┐    │  │
│  │  │  RegSetWatch.sys    │    │  │
│  │  │  (Driver)           │    │  │
│  │  └──────────┬──────────┘    │  │
│  │             │ Callback       │  │
│  │             ↓                │  │
│  │  ┌─────────────────────┐    │  │
│  │  │ Configuration Mgr   │    │  │
│  │  │ (Registry System)   │    │  │
│  │  └─────────────────────┘    │  │
│  └──────────────────────────────┘  │
└─────────────────────────────────────┘
```

## References

- Windows Driver Model (WDM) documentation
- Configuration Manager callback architecture
- Registry internals and data structures
- Native API reference
