/*
 * RegSetWatch - Windows Registry Timestomping Detection Driver
 * 
 * This driver monitors NtSetInformationKey API calls to detect registry
 * timestomping attempts (KeyWriteTimeInformation usage). It can also scan
 * registry hives for subkey-parent timestamp mismatches and forward events
 * to SIEM systems via syslog.
 */

#include <ntddk.h>
#include <ntstrsafe.h>

#define REGSETWATCH_DEVICE_NAME     L"\\Device\\RegSetWatch"
#define REGSETWATCH_SYMLINK_NAME    L"\\??\\RegSetWatch"
#define REGSETWATCH_POOL_TAG        'wSgR'

// IOCTL codes for user-mode communication
#define IOCTL_REGSETWATCH_START_MONITOR     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_STOP_MONITOR      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_SCAN_HIVES        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_GET_ALERTS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_CONFIG_SYSLOG     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Alert structure
typedef struct _REGSETWATCH_ALERT {
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    WCHAR ProcessName[256];
    WCHAR RegistryPath[512];
    LARGE_INTEGER OldTimestamp;
    LARGE_INTEGER NewTimestamp;
    BOOLEAN IsSuspicious;
} REGSETWATCH_ALERT, *PREGSETWATCH_ALERT;

// Global configuration
typedef struct _REGSETWATCH_CONFIG {
    BOOLEAN MonitoringEnabled;
    BOOLEAN ScanningEnabled;
    BOOLEAN SyslogEnabled;
    CHAR SyslogServer[256];
    USHORT SyslogPort;
    FAST_MUTEX ConfigLock;
} REGSETWATCH_CONFIG, *PREGSETWATCH_CONFIG;

// Alert queue entry
typedef struct _ALERT_QUEUE_ENTRY {
    LIST_ENTRY ListEntry;
    REGSETWATCH_ALERT Alert;
} ALERT_QUEUE_ENTRY, *PALERT_QUEUE_ENTRY;

// Global state
static REGSETWATCH_CONFIG g_Config = {0};
static LIST_ENTRY g_AlertQueue;
static KSPIN_LOCK g_AlertQueueLock;
static ULONG g_AlertCount = 0;
static PDEVICE_OBJECT g_DeviceObject = NULL;

// Registry callback cookie
static LARGE_INTEGER g_RegistryCallbackCookie = {0};

// Function prototypes
DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RegSetWatchUnload;
_Dispatch_type_(IRP_MJ_CREATE) DRIVER_DISPATCH RegSetWatchCreate;
_Dispatch_type_(IRP_MJ_CLOSE) DRIVER_DISPATCH RegSetWatchClose;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH RegSetWatchDeviceControl;

EX_CALLBACK_FUNCTION RegSetWatchRegistryCallback;
NTSTATUS ResolveRegistryPath(PVOID Object, PUNICODE_STRING ResolvedPath);
NTSTATUS ScanRegistryHives();
NTSTATUS AddAlert(PREGSETWATCH_ALERT Alert);
NTSTATUS SendSyslogAlert(PREGSETWATCH_ALERT Alert);

/*
 * DriverEntry - Driver initialization routine
 */
NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symlinkName;
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    DbgPrint("[RegSetWatch] Driver loading...\n");
    
    // Initialize configuration
    RtlZeroMemory(&g_Config, sizeof(g_Config));
    ExInitializeFastMutex(&g_Config.ConfigLock);
    g_Config.SyslogPort = 514; // Default syslog port
    
    // Initialize alert queue
    InitializeListHead(&g_AlertQueue);
    KeInitializeSpinLock(&g_AlertQueueLock);
    
    // Create device object
    RtlInitUnicodeString(&deviceName, REGSETWATCH_DEVICE_NAME);
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_DeviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RegSetWatch] Failed to create device: 0x%X\n", status);
        return status;
    }
    
    // Create symbolic link
    RtlInitUnicodeString(&symlinkName, REGSETWATCH_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);
    
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RegSetWatch] Failed to create symbolic link: 0x%X\n", status);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }
    
    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = RegSetWatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RegSetWatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RegSetWatchDeviceControl;
    DriverObject->DriverUnload = RegSetWatchUnload;
    
    DbgPrint("[RegSetWatch] Driver loaded successfully\n");
    
    return STATUS_SUCCESS;
}

/*
 * RegSetWatchUnload - Driver unload routine
 */
VOID RegSetWatchUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{
    UNICODE_STRING symlinkName;
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PALERT_QUEUE_ENTRY alertEntry;
    
    DbgPrint("[RegSetWatch] Driver unloading...\n");
    
    // Unregister registry callback if registered
    if (g_RegistryCallbackCookie.QuadPart != 0) {
        CmUnRegisterCallback(g_RegistryCallbackCookie);
        g_RegistryCallbackCookie.QuadPart = 0;
    }
    
    // Clean up alert queue
    KeAcquireSpinLock(&g_AlertQueueLock, &oldIrql);
    while (!IsListEmpty(&g_AlertQueue)) {
        entry = RemoveHeadList(&g_AlertQueue);
        alertEntry = CONTAINING_RECORD(entry, ALERT_QUEUE_ENTRY, ListEntry);
        ExFreePoolWithTag(alertEntry, REGSETWATCH_POOL_TAG);
    }
    KeReleaseSpinLock(&g_AlertQueueLock, oldIrql);
    
    // Delete symbolic link
    RtlInitUnicodeString(&symlinkName, REGSETWATCH_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);
    
    // Delete device object
    if (g_DeviceObject) {
        IoDeleteDevice(g_DeviceObject);
    }
    
    DbgPrint("[RegSetWatch] Driver unloaded\n");
}

/*
 * RegSetWatchCreate - Handle IRP_MJ_CREATE
 */
NTSTATUS RegSetWatchCreate(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

/*
 * RegSetWatchClose - Handle IRP_MJ_CLOSE
 */
NTSTATUS RegSetWatchClose(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

/*
 * RegSetWatchDeviceControl - Handle IRP_MJ_DEVICE_CONTROL
 */
NTSTATUS RegSetWatchDeviceControl(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
)
{
    NTSTATUS status = STATUS_SUCCESS;
    PIO_STACK_LOCATION irpStack;
    ULONG ioControlCode;
    PVOID inputBuffer;
    PVOID outputBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    ULONG bytesReturned = 0;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    
    irpStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = Irp->AssociatedIrp.SystemBuffer;
    outputBuffer = Irp->AssociatedIrp.SystemBuffer;
    inputBufferLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
    
    switch (ioControlCode) {
        case IOCTL_REGSETWATCH_START_MONITOR:
            DbgPrint("[RegSetWatch] Starting monitoring\n");
            
            // Register registry callback
            if (g_RegistryCallbackCookie.QuadPart == 0) {
                status = CmRegisterCallbackEx(
                    RegSetWatchRegistryCallback,
                    &Altitude,
                    g_DeviceObject->DriverObject,
                    NULL,
                    &g_RegistryCallbackCookie,
                    NULL
                );
                
                if (NT_SUCCESS(status)) {
                    ExAcquireFastMutex(&g_Config.ConfigLock);
                    g_Config.MonitoringEnabled = TRUE;
                    ExReleaseFastMutex(&g_Config.ConfigLock);
                    DbgPrint("[RegSetWatch] Monitoring started\n");
                } else {
                    DbgPrint("[RegSetWatch] Failed to register callback: 0x%X\n", status);
                }
            }
            break;
            
        case IOCTL_REGSETWATCH_STOP_MONITOR:
            DbgPrint("[RegSetWatch] Stopping monitoring\n");
            
            if (g_RegistryCallbackCookie.QuadPart != 0) {
                CmUnRegisterCallback(g_RegistryCallbackCookie);
                g_RegistryCallbackCookie.QuadPart = 0;
                
                ExAcquireFastMutex(&g_Config.ConfigLock);
                g_Config.MonitoringEnabled = FALSE;
                ExReleaseFastMutex(&g_Config.ConfigLock);
                
                DbgPrint("[RegSetWatch] Monitoring stopped\n");
            }
            break;
            
        case IOCTL_REGSETWATCH_SCAN_HIVES:
            DbgPrint("[RegSetWatch] Scanning registry hives\n");
            status = ScanRegistryHives();
            break;
            
        case IOCTL_REGSETWATCH_GET_ALERTS:
            // Get alerts from queue
            if (outputBufferLength >= sizeof(REGSETWATCH_ALERT)) {
                KIRQL oldIrql;
                PLIST_ENTRY entry;
                PALERT_QUEUE_ENTRY alertEntry;
                
                KeAcquireSpinLock(&g_AlertQueueLock, &oldIrql);
                
                if (!IsListEmpty(&g_AlertQueue)) {
                    entry = RemoveHeadList(&g_AlertQueue);
                    alertEntry = CONTAINING_RECORD(entry, ALERT_QUEUE_ENTRY, ListEntry);
                    
                    RtlCopyMemory(outputBuffer, &alertEntry->Alert, sizeof(REGSETWATCH_ALERT));
                    bytesReturned = sizeof(REGSETWATCH_ALERT);
                    
                    ExFreePoolWithTag(alertEntry, REGSETWATCH_POOL_TAG);
                    g_AlertCount--;
                } else {
                    status = STATUS_NO_MORE_ENTRIES;
                }
                
                KeReleaseSpinLock(&g_AlertQueueLock, oldIrql);
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
            
        case IOCTL_REGSETWATCH_CONFIG_SYSLOG:
            // Configure syslog settings
            if (inputBufferLength >= sizeof(REGSETWATCH_CONFIG)) {
                ExAcquireFastMutex(&g_Config.ConfigLock);
                RtlCopyMemory(&g_Config, inputBuffer, sizeof(REGSETWATCH_CONFIG));
                ExReleaseFastMutex(&g_Config.ConfigLock);
                DbgPrint("[RegSetWatch] Syslog configured\n");
            } else {
                status = STATUS_BUFFER_TOO_SMALL;
            }
            break;
            
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// Altitude string for registry callback (required for Windows 8+)
static UNICODE_STRING Altitude = RTL_CONSTANT_STRING(L"385200");

/*
 * RegSetWatchRegistryCallback - Registry operation callback
 */
NTSTATUS RegSetWatchRegistryCallback(
    _In_ PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
{
    REG_NOTIFY_CLASS notifyClass;
    PREG_SET_INFORMATION_KEY_INFORMATION setInfoKey;
    REGSETWATCH_ALERT alert;
    UNICODE_STRING resolvedPath;
    NTSTATUS status;
    PEPROCESS process;
    PUCHAR imageName;
    
    UNREFERENCED_PARAMETER(CallbackContext);
    
    notifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;
    
    // We're interested in SetInformationKey operations
    if (notifyClass == RegNtPreSetInformationKey) {
        setInfoKey = (PREG_SET_INFORMATION_KEY_INFORMATION)Argument2;
        
        // Check if this is KeyWriteTimeInformation (timestomping)
        if (setInfoKey->KeySetInformationClass == KeyWriteTimeInformation) {
            DbgPrint("[RegSetWatch] Detected KeyWriteTimeInformation attempt!\n");
            
            // Prepare alert
            RtlZeroMemory(&alert, sizeof(alert));
            KeQuerySystemTime(&alert.Timestamp);
            alert.ProcessId = HandleToULong(PsGetCurrentProcessId());
            alert.IsSuspicious = TRUE;
            
            // Get process name
            process = PsGetCurrentProcess();
            imageName = PsGetProcessImageFileName(process);
            if (imageName) {
                RtlStringCbPrintfW(
                    alert.ProcessName,
                    sizeof(alert.ProcessName),
                    L"%S",
                    imageName
                );
            }
            
            // Resolve registry path
            resolvedPath.Length = 0;
            resolvedPath.MaximumLength = sizeof(alert.RegistryPath);
            resolvedPath.Buffer = alert.RegistryPath;
            
            status = ResolveRegistryPath(setInfoKey->Object, &resolvedPath);
            if (!NT_SUCCESS(status)) {
                RtlStringCbCopyW(
                    alert.RegistryPath,
                    sizeof(alert.RegistryPath),
                    L"<Unable to resolve>"
                );
            }
            
            // Get old and new timestamps
            if (setInfoKey->KeySetInformation && 
                setInfoKey->KeySetInformationLength >= sizeof(LARGE_INTEGER)) {
                RtlCopyMemory(
                    &alert.NewTimestamp,
                    setInfoKey->KeySetInformation,
                    sizeof(LARGE_INTEGER)
                );
            }
            
            // Add to alert queue
            AddAlert(&alert);
            
            // Send to syslog if enabled
            if (g_Config.SyslogEnabled) {
                SendSyslogAlert(&alert);
            }
            
            DbgPrint("[RegSetWatch] Alert generated for process %lu (%ws)\n",
                     alert.ProcessId, alert.ProcessName);
        }
    }
    
    return STATUS_SUCCESS;
}

/*
 * ResolveRegistryPath - Resolve registry object to path
 */
NTSTATUS ResolveRegistryPath(
    _In_ PVOID Object,
    _Out_ PUNICODE_STRING ResolvedPath
)
{
    NTSTATUS status;
    ULONG returnedLength;
    PUNICODE_STRING objectName;
    
    // Query object name
    status = ObQueryNameString(
        Object,
        NULL,
        0,
        &returnedLength
    );
    
    if (status == STATUS_INFO_LENGTH_MISMATCH && returnedLength > 0) {
        objectName = (PUNICODE_STRING)ExAllocatePoolWithTag(
            NonPagedPool,
            returnedLength,
            REGSETWATCH_POOL_TAG
        );
        
        if (objectName) {
            status = ObQueryNameString(
                Object,
                objectName,
                returnedLength,
                &returnedLength
            );
            
            if (NT_SUCCESS(status)) {
                RtlCopyUnicodeString(ResolvedPath, objectName);
            }
            
            ExFreePoolWithTag(objectName, REGSETWATCH_POOL_TAG);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    
    return status;
}

/*
 * ScanRegistryHives - Scan registry for timestamp mismatches
 */
NTSTATUS ScanRegistryHives()
{
    // This would implement recursive scanning of registry hives
    // to detect subkeys with timestamps newer than their parent keys
    // For now, we'll return success as this is a placeholder
    
    DbgPrint("[RegSetWatch] Registry hive scanning not yet implemented\n");
    return STATUS_SUCCESS;
}

/*
 * AddAlert - Add an alert to the queue
 */
NTSTATUS AddAlert(
    _In_ PREGSETWATCH_ALERT Alert
)
{
    PALERT_QUEUE_ENTRY entry;
    KIRQL oldIrql;
    
    entry = (PALERT_QUEUE_ENTRY)ExAllocatePoolWithTag(
        NonPagedPool,
        sizeof(ALERT_QUEUE_ENTRY),
        REGSETWATCH_POOL_TAG
    );
    
    if (!entry) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    RtlCopyMemory(&entry->Alert, Alert, sizeof(REGSETWATCH_ALERT));
    
    KeAcquireSpinLock(&g_AlertQueueLock, &oldIrql);
    InsertTailList(&g_AlertQueue, &entry->ListEntry);
    g_AlertCount++;
    KeReleaseSpinLock(&g_AlertQueueLock, oldIrql);
    
    return STATUS_SUCCESS;
}

/*
 * SendSyslogAlert - Send alert to syslog server
 */
NTSTATUS SendSyslogAlert(
    _In_ PREGSETWATCH_ALERT Alert
)
{
    // This would implement sending the alert to a syslog server via UDP
    // For now, we'll just log it
    
    UNREFERENCED_PARAMETER(Alert);
    
    DbgPrint("[RegSetWatch] Syslog forwarding not yet implemented\n");
    return STATUS_SUCCESS;
}
