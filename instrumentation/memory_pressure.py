r"""Force a target process's private pages toward pagefile.sys, for research.

Two phases, matching how Windows actually pages:
  trim      SetProcessWorkingSetSize(pid, -1, -1) -- evicts the target's pages
            from its working set onto the Modified Page List (still RAM).
  pressure  Allocate+touch memory until a free-RAM floor, forcing the Modified
            Page Writer to flush modified pages to pagefile.sys. Sustained
            pressure defeats memory compression.

Verification caveats: ReadProcessMemory on a paged-out range faults it back
into RAM, so a RAM rescan cannot prove page-out. Watch instead:
  Get-Counter '\Memory\Modified Page List Bytes', '\Paging File(_Total)\% Usage',
  '\Process(1Password*)\Working Set'
Definitive content proof requires reading pagefile.sys offline (it persists
across reboots) or a raw-disk carve from an elevated live session.
"""
import argparse
import ctypes
from ctypes import wintypes
import time

PROCESS_SET_QUOTA = 0x0100
PROCESS_QUERY_INFORMATION = 0x0400


class MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [('dwLength', wintypes.DWORD), ('dwMemoryLoad', wintypes.DWORD),
                ('ullTotalPhys', ctypes.c_ulonglong), ('ullAvailPhys', ctypes.c_ulonglong),
                ('ullTotalPageFile', ctypes.c_ulonglong), ('ullAvailPageFile', ctypes.c_ulonglong),
                ('ullTotalVirtual', ctypes.c_ulonglong), ('ullAvailVirtual', ctypes.c_ulonglong),
                ('ullAvailExtendedVirtual', ctypes.c_ulonglong)]


def memstatus():
    s = MEMORYSTATUSEX()
    s.dwLength = ctypes.sizeof(s)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(s))
    return s


def free_mb():
    return memstatus().ullAvailPhys / 2**20


def trim(pid):
    k32 = ctypes.windll.kernel32
    h = k32.OpenProcess(PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, False, pid)
    if not h:
        return f'PID {pid}: OpenProcess failed gle={ctypes.GetLastError()}'
    try:
        ok = k32.SetProcessWorkingSetSize(h, ctypes.c_size_t(-1), ctypes.c_size_t(-1))
        return f'PID {pid}: working set emptied' if ok else f'PID {pid}: trim failed gle={ctypes.GetLastError()}'
    finally:
        k32.CloseHandle(h)


def pressure(target_mb, floor_mb, hold_seconds, chunk_mb=256):
    blocks = []
    held = 0
    try:
        while target_mb is None or held < target_mb:
            if free_mb() < floor_mb:
                print(f'free-RAM floor reached at {free_mb():.0f} MiB; stopping allocation', flush=True)
                break
            b = bytearray(chunk_mb * 2**20)
            for i in range(0, len(b), 4096):
                b[i] = 1  # fault every page in, so it cannot be discarded
            blocks.append(b)
            held += chunk_mb
            print(f'committed+held {held} MiB; free RAM {free_mb():.0f} MiB; '
                  f'availCommit {memstatus().ullAvailPageFile / 2**30:.1f} GiB', flush=True)
            time.sleep(0.25)
        print(f'holding {held} MiB for {hold_seconds}s; watch pagefile counters now', flush=True)
        t0 = time.monotonic()
        while time.monotonic() - t0 < hold_seconds:
            time.sleep(5)
            print(f'  hold: free RAM {free_mb():.0f} MiB', flush=True)
    finally:
        blocks.clear()
        print(f'released; free RAM {free_mb():.0f} MiB', flush=True)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest='cmd', required=True)
    t = sub.add_parser('trim')
    t.add_argument('--pid', type=int, action='append', required=True)
    p = sub.add_parser('pressure')
    p.add_argument('--target-mb', type=int, default=None, help='stop after this much is held (default: until floor)')
    p.add_argument('--floor-mb', type=int, default=2048, help='leave this much free RAM')
    p.add_argument('--hold', type=int, default=120, help='seconds to hold pressure')
    args = ap.parse_args()
    if args.cmd == 'trim':
        for pid in args.pid:
            print(trim(pid))
    else:
        pressure(args.target_mb, args.floor_mb, args.hold)


if __name__ == '__main__':
    main()
