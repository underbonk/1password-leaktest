"""Load Winsock Hook.dll into the 1Password process that has index.node loaded.

Classic LoadLibrary injection via ctypes; no third-party injector is required.

    python gui/inject.py
    python gui/inject.py --dll path\\to\\Winsock Hook.dll --pid 1234
"""
import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path
import sys

PROCESS_ALL_ACCESS = 0x1F0FFF
TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DLL = ROOT / 'gui' / 'Winsock-Hook' / 'Winsock Hook' / 'x64' / 'Release' / 'Winsock Hook.dll'


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('cntUsage', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('th32DefaultHeapID', ctypes.c_size_t),
        ('th32ModuleID', wintypes.DWORD),
        ('cntThreads', wintypes.DWORD),
        ('th32ParentProcessID', wintypes.DWORD),
        ('pcPriClassBase', ctypes.c_long),
        ('dwFlags', wintypes.DWORD),
        ('szExeFile', wintypes.WCHAR * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ('dwSize', wintypes.DWORD),
        ('th32ModuleID', wintypes.DWORD),
        ('th32ProcessID', wintypes.DWORD),
        ('GlblcntUsage', wintypes.DWORD),
        ('ProccntUsage', wintypes.DWORD),
        ('modBaseAddr', ctypes.c_void_p),
        ('modBaseSize', wintypes.DWORD),
        ('hModule', wintypes.HMODULE),
        ('szModule', wintypes.WCHAR * 256),
        ('szExePath', wintypes.WCHAR * 260),
    ]


def processes_named(exe):
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    found = []
    try:
        ok = k32.Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == exe.lower():
                found.append(entry.th32ProcessID)
            ok = k32.Process32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return found


def has_module(pid, module_name):
    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid)
    if snap == INVALID_HANDLE_VALUE:
        return False
    entry = MODULEENTRY32W()
    entry.dwSize = ctypes.sizeof(entry)
    try:
        ok = k32.Module32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szModule.lower() == module_name.lower():
                return True
            ok = k32.Module32NextW(snap, ctypes.byref(entry))
    finally:
        k32.CloseHandle(snap)
    return False


def main_pid():
    matches = [pid for pid in processes_named('1Password.exe') if has_module(pid, 'index.node')]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        print('No 1Password.exe process has index.node loaded.')
    else:
        print('More than one 1Password process has index.node loaded: ' + ', '.join(map(str, matches)))
    return None


def inject(pid, dll):
    k32 = ctypes.windll.kernel32
    k32.OpenProcess.restype = ctypes.c_void_p
    k32.VirtualAllocEx.restype = ctypes.c_void_p
    k32.VirtualAllocEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.c_ulong, ctypes.c_ulong]
    k32.WriteProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_char_p,
                                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.GetModuleHandleW.restype = ctypes.c_void_p
    k32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    k32.CreateRemoteThread.restype = ctypes.c_void_p
    k32.CreateRemoteThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                       ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong,
                                       ctypes.POINTER(ctypes.c_ulong)]
    k32.VirtualFreeEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_ulong]
    path = str(dll).encode('mbcs')
    h = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        print(f'OpenProcess failed gle={ctypes.GetLastError()}')
        return 1
    try:
        remote = k32.VirtualAllocEx(h, None, len(path) + 1, 0x3000, 0x04)
        if not remote:
            print(f'VirtualAllocEx failed gle={ctypes.GetLastError()}')
            return 1
        written = ctypes.c_size_t(0)
        if not k32.WriteProcessMemory(h, remote, path, len(path) + 1, ctypes.byref(written)):
            print(f'WriteProcessMemory failed gle={ctypes.GetLastError()}')
            return 1
        loadlib = k32.GetProcAddress(k32.GetModuleHandleW('kernel32.dll'), b'LoadLibraryA')
        tid = ctypes.c_ulong(0)
        th = k32.CreateRemoteThread(h, None, 0, loadlib, remote, 0, ctypes.byref(tid))
        if not th:
            print(f'CreateRemoteThread failed gle={ctypes.GetLastError()}')
            return 1
        k32.WaitForSingleObject(th, 15000)
        exit_code = ctypes.c_ulong(0)
        k32.GetExitCodeThread(th, ctypes.byref(exit_code))
        k32.CloseHandle(th)
        k32.VirtualFreeEx(h, remote, 0, 0x8000)
        if exit_code.value == 0:
            print('LoadLibraryA returned NULL - DLL failed to load')
            return 1
        print(f'injected OK into PID {pid}, dll base 0x{exit_code.value:x}')
        return 0
    finally:
        k32.CloseHandle(h)


def main():
    ap = argparse.ArgumentParser(description='Inject the hex viewer into the 1Password process that loaded index.node.')
    ap.add_argument('--pid', type=int, help='Override the auto-detected main process')
    ap.add_argument('--dll', type=Path, default=DEFAULT_DLL)
    args = ap.parse_args()
    if not args.dll.is_file():
        print(f'DLL not found: {args.dll}')
        print('Build gui/Winsock-Hook as Release|x64 first.')
        return 1
    pid = args.pid or main_pid()
    if pid is None:
        return 1
    return inject(pid, args.dll)


if __name__ == '__main__':
    sys.exit(main())
