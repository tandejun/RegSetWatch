/*
 * SetRegTime - Proof of Concept tool for registry timestomping
 * 
 * This tool demonstrates how to modify registry key timestamps using
 * the NtSetInformationKey API with KeyWriteTimeInformation.
 * Used for testing RegSetWatch detection capabilities.
 */

#include <windows.h>
#include <stdio.h>
#include <time.h>

// Native API definitions
typedef LONG NTSTATUS;

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef enum _KEY_INFORMATION_CLASS {
    KeyBasicInformation = 0,
    KeyNodeInformation = 1,
    KeyFullInformation = 2,
    KeyNameInformation = 3,
    KeyCachedInformation = 4,
    KeyFlagsInformation = 5,
    KeyVirtualizationInformation = 6,
    KeyHandleTagsInformation = 7,
    KeyTrustInformation = 8,
    KeyLayerInformation = 9,
    MaxKeyInfoClass = 10
} KEY_INFORMATION_CLASS;

typedef enum _KEY_SET_INFORMATION_CLASS {
    KeyWriteTimeInformation = 0,
    KeyWow64FlagsInformation = 1,
    KeyControlFlagsInformation = 2,
    KeySetVirtualizationInformation = 3,
    KeySetDebugInformation = 4,
    KeySetHandleTagsInformation = 5,
    KeySetLayerInformation = 6,
    MaxKeySetInfoClass = 7
} KEY_SET_INFORMATION_CLASS;

typedef struct _KEY_WRITE_TIME_INFORMATION {
    LARGE_INTEGER LastWriteTime;
} KEY_WRITE_TIME_INFORMATION, *PKEY_WRITE_TIME_INFORMATION;

typedef NTSTATUS (NTAPI *PNtSetInformationKey)(
    HANDLE KeyHandle,
    KEY_SET_INFORMATION_CLASS KeySetInformationClass,
    PVOID KeySetInformation,
    ULONG KeySetInformationLength
);

typedef NTSTATUS (NTAPI *PNtQueryInformationKey)(
    HANDLE KeyHandle,
    KEY_INFORMATION_CLASS KeyInformationClass,
    PVOID KeyInformation,
    ULONG Length,
    PULONG ResultLength
);

void PrintUsage(const char* programName) {
    printf("SetRegTime - Registry Timestomping PoC Tool\n");
    printf("Usage: %s <registry_path> [timestamp]\n\n", programName);
    printf("Arguments:\n");
    printf("  registry_path    Full registry path (e.g., HKLM\\Software\\Test)\n");
    printf("  timestamp        Optional: FILETIME value or 'benign' for current time\n");
    printf("                   Default: Sets timestamp to 2010-01-01\n\n");
    printf("Examples:\n");
    printf("  %s HKLM\\Software\\TestKey               (malicious - old timestamp)\n", programName);
    printf("  %s HKLM\\Software\\TestKey benign        (benign - current time)\n", programName);
    printf("  %s HKLM\\Software\\TestKey 130000000000000000\n", programName);
}

BOOL ParseRegistryPath(const char* path, HKEY* rootKey, char* subKey, size_t subKeySize) {
    if (strncmp(path, "HKLM\\", 5) == 0 || strncmp(path, "HKEY_LOCAL_MACHINE\\", 19) == 0) {
        *rootKey = HKEY_LOCAL_MACHINE;
        if (strncmp(path, "HKLM\\", 5) == 0) {
            strncpy(subKey, path + 5, subKeySize - 1);
        } else {
            strncpy(subKey, path + 19, subKeySize - 1);
        }
    }
    else if (strncmp(path, "HKCU\\", 5) == 0 || strncmp(path, "HKEY_CURRENT_USER\\", 18) == 0) {
        *rootKey = HKEY_CURRENT_USER;
        if (strncmp(path, "HKCU\\", 5) == 0) {
            strncpy(subKey, path + 5, subKeySize - 1);
        } else {
            strncpy(subKey, path + 18, subKeySize - 1);
        }
    }
    else if (strncmp(path, "HKCR\\", 5) == 0 || strncmp(path, "HKEY_CLASSES_ROOT\\", 18) == 0) {
        *rootKey = HKEY_CLASSES_ROOT;
        if (strncmp(path, "HKCR\\", 5) == 0) {
            strncpy(subKey, path + 5, subKeySize - 1);
        } else {
            strncpy(subKey, path + 18, subKeySize - 1);
        }
    }
    else {
        return FALSE;
    }
    
    subKey[subKeySize - 1] = '\0';
    return TRUE;
}

void GetCurrentFileTime(LARGE_INTEGER* fileTime) {
    SYSTEMTIME systemTime;
    FILETIME ft;
    
    GetSystemTime(&systemTime);
    SystemTimeToFileTime(&systemTime, &ft);
    
    fileTime->LowPart = ft.dwLowDateTime;
    fileTime->HighPart = ft.dwHighDateTime;
}

void GetOldFileTime(LARGE_INTEGER* fileTime) {
    SYSTEMTIME systemTime = {0};
    FILETIME ft;
    
    // Set to January 1, 2010
    systemTime.wYear = 2010;
    systemTime.wMonth = 1;
    systemTime.wDay = 1;
    systemTime.wHour = 0;
    systemTime.wMinute = 0;
    systemTime.wSecond = 0;
    
    SystemTimeToFileTime(&systemTime, &ft);
    
    fileTime->LowPart = ft.dwLowDateTime;
    fileTime->HighPart = ft.dwHighDateTime;
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

int main(int argc, char* argv[]) {
    HMODULE hNtdll;
    PNtSetInformationKey NtSetInformationKey;
    HKEY rootKey;
    HKEY hKey;
    char subKey[512];
    KEY_WRITE_TIME_INFORMATION writeTime;
    NTSTATUS status;
    LONG result;
    char timestampBuf[64];
    BOOL isBenign = FALSE;
    
    if (argc < 2) {
        PrintUsage(argv[0]);
        return 1;
    }
    
    // Parse registry path
    if (!ParseRegistryPath(argv[1], &rootKey, subKey, sizeof(subKey))) {
        printf("[!] Invalid registry path format\n");
        return 1;
    }
    
    printf("[*] Registry Path: %s\n", argv[1]);
    printf("[*] Parsed SubKey: %s\n", subKey);
    
    // Determine timestamp to use
    if (argc > 2) {
        if (strcmp(argv[2], "benign") == 0) {
            GetCurrentFileTime(&writeTime.LastWriteTime);
            isBenign = TRUE;
            printf("[*] Mode: Benign (current timestamp)\n");
        } else {
            // Parse as FILETIME value
            writeTime.LastWriteTime.QuadPart = _strtoui64(argv[2], NULL, 10);
            printf("[*] Mode: Custom timestamp\n");
        }
    } else {
        GetOldFileTime(&writeTime.LastWriteTime);
        printf("[*] Mode: Malicious (backdated timestamp)\n");
    }
    
    FormatTimestamp(writeTime.LastWriteTime, timestampBuf, sizeof(timestampBuf));
    printf("[*] Target Timestamp: %s\n", timestampBuf);
    
    // Load NtSetInformationKey from ntdll.dll
    hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        printf("[!] Failed to get ntdll.dll handle\n");
        return 1;
    }
    
    NtSetInformationKey = (PNtSetInformationKey)GetProcAddress(
        hNtdll,
        "NtSetInformationKey"
    );
    
    if (!NtSetInformationKey) {
        printf("[!] Failed to get NtSetInformationKey address\n");
        return 1;
    }
    
    // Open or create the registry key
    result = RegCreateKeyExA(
        rootKey,
        subKey,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_SET_VALUE | KEY_WRITE,
        NULL,
        &hKey,
        NULL
    );
    
    if (result != ERROR_SUCCESS) {
        printf("[!] Failed to open/create registry key: %ld\n", result);
        return 1;
    }
    
    printf("[*] Registry key opened successfully\n");
    
    // Set the timestamp using NtSetInformationKey
    printf("[*] Attempting to set timestamp...\n");
    status = NtSetInformationKey(
        hKey,
        KeyWriteTimeInformation,
        &writeTime,
        sizeof(writeTime)
    );
    
    if (NT_SUCCESS(status)) {
        printf("[+] Timestamp modified successfully!\n");
        if (isBenign) {
            printf("[*] This was a benign operation (current time)\n");
        } else {
            printf("[!] This was a timestomping operation (suspicious)\n");
        }
    } else {
        printf("[!] Failed to set timestamp: 0x%08X\n", status);
    }
    
    RegCloseKey(hKey);
    
    return NT_SUCCESS(status) ? 0 : 1;
}
