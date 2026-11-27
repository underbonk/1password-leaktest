"""Read-only memory search of research-client processes for the research key.

Uses OpenProcess(PROCESS_VM_READ) + VirtualQueryEx/ReadProcessMemory via ctypes.
No code injection, no hooks, no modification of the target. The key is read
from a local file, never printed, and matched byte patterns are never injected
into the target (unlike an agent-based scan, the needle never exists in the
target's memory as part of this tool). Reports counts, region metadata, and
match addresses only -- no memory contents are dumped.

Usage:
    python instrumentation/memory_key_scan.py --key-file tmp/research-key.txt [--pid N ...]
"""
import argparse
import ctypes
from ctypes import wintypes
from pathlib import Path

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
READABLE = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}  # R, RW, WC, XR, XRW, XWC
TYPE_NAMES = {0x1000000: 'IMAGE', 0x40000: 'MAPPED', 0x20000: 'PRIVATE'}
CHUNK = 8 * 1024 * 1024
OVERLAP = 128
MAX_ADDR = 0x7FFFFFFFFFFF


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ('BaseAddress', ctypes.c_ulonglong), ('AllocationBase', ctypes.c_ulonglong),
        ('AllocationProtect', wintypes.DWORD), ('__alignment1', wintypes.DWORD),
        ('RegionSize', ctypes.c_ulonglong), ('State', wintypes.DWORD),
        ('Protect', wintypes.DWORD), ('Type', wintypes.DWORD), ('__alignment2', wintypes.DWORD),
    ]


def utf16le(s: str) -> bytes:
    return s.encode('utf-16-le')


def patterns_from(key: str):
    parts = key.split('-')
    secret = '-'.join(parts[2:]) if len(parts) == 7 else key
    forms = {
        'full_utf8': key, 'full_utf16le': key,
        'secret_utf8': secret, 'secret_utf16le': secret,
        'nodash_full_utf8': key.replace('-', ''), 'nodash_full_utf16le': key.replace('-', ''),
        'nodash_secret_utf8': secret.replace('-', ''), 'nodash_secret_utf16le': secret.replace('-', ''),
        'probe_first_secret_group_utf8': secret.split('-')[0],
        'probe_first_secret_group_utf16le': secret.split('-')[0],
    }
    out = {}
    for name, s in forms.items():
        out[name] = utf16le(s) if name.endswith('utf16le') else s.encode()
    return out


def scan_pid(pid: int, pats: dict):
    k32 = ctypes.windll.kernel32
    handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return {'pid': pid, 'error': f'OpenProcess failed (gle={ctypes.GetLastError()})'}
    results = {name: {'count': 0, 'regions': []} for name in pats}
    stats = {'readable_bytes': 0, 'read_failures': 0}
    try:
        mbi = MEMORY_BASIC_INFORMATION64()
        addr = 0
        buf = (ctypes.c_ubyte * CHUNK)()
        while addr < MAX_ADDR:
            got = k32.VirtualQueryEx(handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not got:
                break
            base, size = mbi.BaseAddress, mbi.RegionSize
            addr = base + size
            if mbi.State != MEM_COMMIT or (mbi.Protect & 0xFF) not in READABLE or (mbi.Protect & PAGE_GUARD):
                continue
            stats['readable_bytes'] += size
            region_hits = {}
            offset = 0
            while offset < size:
                want = min(CHUNK, size - offset)
                n = ctypes.c_size_t(0)
                ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(base + offset), buf, want, ctypes.byref(n))
                if not ok or n.value == 0:
                    if offset == 0:
                        stats['read_failures'] += 1
                    break
                data = bytes(buf[: n.value])
                # Chunks overlap by OVERLAP bytes; any needle starting inside the
                # overlap zone is fully contained in the previous chunk already.
                for name, needle in pats.items():
                    start = OVERLAP if offset else 0
                    while True:
                        i = data.find(needle, start)
                        if i < 0:
                            break
                        entry = region_hits.setdefault(name, {'count': 0, 'addrs': []})
                        entry['count'] += 1
                        if len(entry['addrs']) < 8:
                            entry['addrs'].append(base + offset + i)
                        start = i + 1
                offset += n.value if n.value < CHUNK else CHUNK - OVERLAP
            for name, entry in region_hits.items():
                results[name]['count'] += entry['count']
                results[name]['regions'].append({
                    'base': hex(base), 'size': size, 'type': TYPE_NAMES.get(mbi.Type, hex(mbi.Type)),
                    'count': entry['count'], 'addrs': [hex(a) for a in entry['addrs']],
                })
    finally:
        k32.CloseHandle(handle)
    return {'pid': pid, 'patterns': results, 'stats': stats}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key-file', required=True)
    ap.add_argument('--pid', type=int, action='append')
    args = ap.parse_args()
    key = Path(args.key_file).read_text(encoding='utf-8').strip()
    if not key:
        ap.error('key file is empty')
    pats = patterns_from(key)
    if args.pid:
        pids = args.pid
    else:
        import subprocess
        out = subprocess.run(['powershell', '-NoProfile', '-Command',
                              "(Get-Process -Name 1Password).Id -join ','"],
                             capture_output=True, text=True).stdout.strip()
        pids = [int(x) for x in out.split(',') if x.strip()]
    for pid in pids:
        r = scan_pid(pid, pats)
        if 'error' in r:
            print(f'PID {pid}: {r["error"]}')
            continue
        mb = r['stats']['readable_bytes'] / 1048576
        print(f'PID {pid}: scanned {mb:.0f} MiB readable, read_failures={r["stats"]["read_failures"]}')
        for name, res in r['patterns'].items():
            if res['count']:
                print(f'  {name}: {res["count"]} match(es)')
                for reg in res['regions'][:6]:
                    print(f'    {reg["type"]} region {reg["base"]} size={reg["size"]} count={reg["count"]} addrs={reg["addrs"]}')


if __name__ == '__main__':
    main()
