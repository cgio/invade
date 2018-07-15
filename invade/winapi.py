"""invade winapi module.

Contains Windows API constants, structs, and functions. Windows API functions
in this module should not stray far from their original purposes. The main
module is a better place for heavily modified or repurposed Windows API
functions.
"""


from ctypes import *
from ctypes.wintypes import *


# Windows API modules

kernel32 = windll.kernel32
user32 = windll.user32
advapi32 = windll.advapi32
shell32 = windll.shell32
psapi = windll.psapi
ntdll = windll.ntdll


# Windows API constants

MAX_PATH = 260
STILL_ACTIVE = 259
CREATE_SUSPENDED = 0x00000004
SE_PRIVILEGE_ENABLED = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000
PROCESS_QUERY_INFORMATION = 0x00000400
PROCESS_ALL_ACCESS = 0x001F0FFF
PROCESS_VM_READ = 0x00000010
TOKEN_ALL_ACCESS = 0x000F01FF
LIST_MODULES_ALL = 0x00000003
INVALID_HANDLE_VALUE = c_void_p(-1).value


# Memory constants (most are unused, but are declared for posterity)

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_RESET = 0x00080000
MEM_RESET_UNDO = 0x1000000
MEM_LARGE_PAGES = 0x20000000
MEM_PHYSICAL = 0x00400000
MEM_TOP_DOWN = 0x00100000
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_TARGETS_INVALID = 0x40000000
PAGE_TARGETS_NO_UPDATE = 0x40000000
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400


# Windows API structures

class LUID(Structure):
    _fields_ = [
        ("LowPart", DWORD),
        ("HighPart", LONG),
    ]


class LUID_AND_ATTRIBUTES(Structure):
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", DWORD),
    ]


class TOKEN_PRIVILEGES(Structure):
    _fields_ = [
        ("PrivilegeCount", DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES),
    ]


class MODULEINFO(Structure):
    _fields_ = [
        ("lpBaseOfDll", LPVOID),
        ("SizeOfImage", DWORD),
        ("EntryPoint", LPVOID)
    ]


# Windows API functions

GetLastError = ctypes.GetLastError()
OpenProcess = kernel32.OpenProcess
CloseHandle = kernel32.CloseHandle
GetAsyncKeyState = user32.GetAsyncKeyState


def GetProcAddress(hModule, lpProcName):
    _GetProcAddress = kernel32.GetProcAddress
    return _GetProcAddress(hModule, lpProcName.encode(encoding='ascii'))


def VirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect):
    _VirtualAllocEx = kernel32.VirtualAllocEx
    _VirtualAllocEx.restype = LPVOID
    new_memory_region = _VirtualAllocEx(hProcess, lpAddress, dwSize,
                                        flAllocationType, flProtect)
    if new_memory_region:
        return new_memory_region


def VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect,
                     lpflOldProtect):
    """Unlike the original VirtualProtectEx, this function returns
    the memory region's old protection on success.
    """
    _VirtualProtectEx = kernel32.VirtualProtectEx
    if _VirtualProtectEx(hProcess, lpAddress, dwSize, flNewProtect,
                         lpflOldProtect):
        return lpflOldProtect


def WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize,
                       lpNumberOfBytesWritten):
    _WriteProcessMemory = kernel32.WriteProcessMemory
    if _WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize,
                           lpNumberOfBytesWritten):
        return lpNumberOfBytesWritten


def ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize,
                      lpNumberOfBytesRead):
    _ReadProcessMemory = kernel32.ReadProcessMemory
    if _ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize,
                          lpNumberOfBytesRead):
        return lpBuffer.raw
