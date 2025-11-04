# Makefile for RegSetWatch
# Note: Driver compilation requires Windows Driver Kit (WDK)
# User-mode applications can be built with Visual Studio or MinGW

# Compiler settings for user-mode applications
CC = cl.exe
CFLAGS = /W4 /O2 /D_CRT_SECURE_NO_WARNINGS

# Targets
all: RegSetWatchCtl.exe SetRegTime.exe

# User-mode control application
RegSetWatchCtl.exe: RegSetWatchCtl.c
	$(CC) $(CFLAGS) RegSetWatchCtl.c /Fe:RegSetWatchCtl.exe

# Testing tool
SetRegTime.exe: SetRegTime.c
	$(CC) $(CFLAGS) SetRegTime.c /Fe:SetRegTime.exe

# Driver (requires WDK)
driver:
	@echo "Building driver requires Windows Driver Kit (WDK)"
	@echo "Use build_driver.bat or Visual Studio driver project"

clean:
	del /Q *.exe *.obj *.pdb 2>nul

.PHONY: all driver clean
