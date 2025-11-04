/*
 * RegSetWatchCtl - User-mode control application for RegSetWatch driver
 * 
 * This application allows users to control the RegSetWatch driver,
 * start/stop monitoring, retrieve alerts, and configure settings.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define DEVICE_PATH "\\\\.\\RegSetWatch"

// IOCTL codes (must match driver)
#define IOCTL_REGSETWATCH_START_MONITOR     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_STOP_MONITOR      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_SCAN_HIVES        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_GET_ALERTS        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_REGSETWATCH_CONFIG_SYSLOG     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Alert structure (must match driver)
typedef struct _REGSETWATCH_ALERT {
    LARGE_INTEGER Timestamp;
    ULONG ProcessId;
    WCHAR ProcessName[256];
    WCHAR RegistryPath[512];
    LARGE_INTEGER OldTimestamp;
    LARGE_INTEGER NewTimestamp;
    BOOLEAN IsSuspicious;
} REGSETWATCH_ALERT, *PREGSETWATCH_ALERT;

// Configuration structure (must match driver)
typedef struct _REGSETWATCH_CONFIG {
    BOOLEAN MonitoringEnabled;
    BOOLEAN ScanningEnabled;
    BOOLEAN SyslogEnabled;
    CHAR SyslogServer[256];
    USHORT SyslogPort;
    BYTE Reserved[6]; // Padding for alignment
} REGSETWATCH_CONFIG, *PREGSETWATCH_CONFIG;

void PrintUsage(const char* programName) {
    printf("RegSetWatch Control Application\n");
    printf("Usage: %s [command] [options]\n\n", programName);
    printf("Commands:\n");
    printf("  start              Start monitoring registry timestomping\n");
    printf("  stop               Stop monitoring\n");
    printf("  scan               Scan registry hives for timestamp mismatches\n");
    printf("  alerts             Retrieve and display alerts\n");
    printf("  syslog <server> <port>  Configure syslog forwarding\n");
    printf("  help               Show this help message\n");
}

void FormatTimestamp(LARGE_INTEGER timestamp, char* buffer, size_t bufferSize) {
    FILETIME fileTime;
    SYSTEMTIME systemTime;
    
    fileTime.dwLowDateTime = timestamp.LowPart;
    fileTime.dwHighDateTime = timestamp.HighPart;
    
    if (FileTimeToSystemTime(&fileTime, &systemTime)) {
        snprintf(buffer, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d",
                 systemTime.wYear, systemTime.wMonth, systemTime.wDay,
                 systemTime.wHour, systemTime.wMinute, systemTime.wSecond);
    } else {
        snprintf(buffer, bufferSize, "<invalid>");
    }
}

int StartMonitoring() {
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    
    printf("[*] Opening device...\n");
    hDevice = CreateFileA(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open device: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[*] Starting monitoring...\n");
    result = DeviceIoControl(
        hDevice,
        IOCTL_REGSETWATCH_START_MONITOR,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    
    if (result) {
        printf("[+] Monitoring started successfully\n");
    } else {
        printf("[!] Failed to start monitoring: %lu\n", GetLastError());
    }
    
    CloseHandle(hDevice);
    return result ? 0 : 1;
}

int StopMonitoring() {
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    
    printf("[*] Opening device...\n");
    hDevice = CreateFileA(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open device: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[*] Stopping monitoring...\n");
    result = DeviceIoControl(
        hDevice,
        IOCTL_REGSETWATCH_STOP_MONITOR,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    
    if (result) {
        printf("[+] Monitoring stopped successfully\n");
    } else {
        printf("[!] Failed to stop monitoring: %lu\n", GetLastError());
    }
    
    CloseHandle(hDevice);
    return result ? 0 : 1;
}

int ScanHives() {
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    
    printf("[*] Opening device...\n");
    hDevice = CreateFileA(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open device: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[*] Scanning registry hives...\n");
    result = DeviceIoControl(
        hDevice,
        IOCTL_REGSETWATCH_SCAN_HIVES,
        NULL,
        0,
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    
    if (result) {
        printf("[+] Scan completed successfully\n");
    } else {
        printf("[!] Failed to scan: %lu\n", GetLastError());
    }
    
    CloseHandle(hDevice);
    return result ? 0 : 1;
}

int GetAlerts() {
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    REGSETWATCH_ALERT alert;
    char timestampBuf[64];
    int alertCount = 0;
    
    printf("[*] Opening device...\n");
    hDevice = CreateFileA(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open device: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[*] Retrieving alerts...\n\n");
    
    // Retrieve all alerts from queue
    while (1) {
        result = DeviceIoControl(
            hDevice,
            IOCTL_REGSETWATCH_GET_ALERTS,
            NULL,
            0,
            &alert,
            sizeof(alert),
            &bytesReturned,
            NULL
        );
        
        if (!result) {
            DWORD error = GetLastError();
            if (error == ERROR_NO_MORE_ITEMS) {
                break;
            }
            printf("[!] Failed to retrieve alert: %lu\n", error);
            break;
        }
        
        alertCount++;
        
        // Display alert
        printf("===== Alert #%d =====\n", alertCount);
        
        FormatTimestamp(alert.Timestamp, timestampBuf, sizeof(timestampBuf));
        printf("Detection Time: %s\n", timestampBuf);
        
        printf("Process ID: %lu\n", alert.ProcessId);
        wprintf(L"Process Name: %s\n", alert.ProcessName);
        wprintf(L"Registry Path: %s\n", alert.RegistryPath);
        
        FormatTimestamp(alert.NewTimestamp, timestampBuf, sizeof(timestampBuf));
        printf("New Timestamp: %s\n", timestampBuf);
        
        printf("Suspicious: %s\n", alert.IsSuspicious ? "Yes" : "No");
        printf("\n");
    }
    
    if (alertCount == 0) {
        printf("[*] No alerts found\n");
    } else {
        printf("[+] Retrieved %d alert(s)\n", alertCount);
    }
    
    CloseHandle(hDevice);
    return 0;
}

int ConfigureSyslog(const char* server, int port) {
    HANDLE hDevice;
    DWORD bytesReturned;
    BOOL result;
    REGSETWATCH_CONFIG config;
    
    if (port < 1 || port > 65535) {
        printf("[!] Invalid port number\n");
        return 1;
    }
    
    printf("[*] Opening device...\n");
    hDevice = CreateFileA(
        DEVICE_PATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    
    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open device: %lu\n", GetLastError());
        return 1;
    }
    
    // Prepare configuration
    memset(&config, 0, sizeof(config));
    config.SyslogEnabled = TRUE;
    strncpy(config.SyslogServer, server, sizeof(config.SyslogServer) - 1);
    config.SyslogPort = (USHORT)port;
    
    printf("[*] Configuring syslog: %s:%d\n", server, port);
    result = DeviceIoControl(
        hDevice,
        IOCTL_REGSETWATCH_CONFIG_SYSLOG,
        &config,
        sizeof(config),
        NULL,
        0,
        &bytesReturned,
        NULL
    );
    
    if (result) {
        printf("[+] Syslog configured successfully\n");
    } else {
        printf("[!] Failed to configure syslog: %lu\n", GetLastError());
    }
    
    CloseHandle(hDevice);
    return result ? 0 : 1;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "start") == 0) {
        return StartMonitoring();
    }
    else if (strcmp(argv[1], "stop") == 0) {
        return StopMonitoring();
    }
    else if (strcmp(argv[1], "scan") == 0) {
        return ScanHives();
    }
    else if (strcmp(argv[1], "alerts") == 0) {
        return GetAlerts();
    }
    else if (strcmp(argv[1], "syslog") == 0) {
        if (argc < 4) {
            printf("[!] Usage: %s syslog <server> <port>\n", argv[0]);
            return 1;
        }
        return ConfigureSyslog(argv[2], atoi(argv[3]));
    }
    else if (strcmp(argv[1], "help") == 0) {
        PrintUsage(argv[0]);
        return 0;
    }
    else {
        printf("[!] Unknown command: %s\n", argv[1]);
        PrintUsage(argv[0]);
        return 1;
    }
}
