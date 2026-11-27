"""Scan a pagefile.sys image (e.g., exposed via a VSS shadow copy) for the
research key. Streams the file; prints per-form hit counts and file offsets
only. The key is read from a local file and never printed.

Typical use (elevated):
  $r = (Get-WmiObject -List Win32_ShadowCopy).Create("C:\\", "ClientAccessible")
  $sc = Get-WmiObject Win32_ShadowCopy | ? { $_.ID -eq $r.ShadowID }
  python instrumentation\\pagefile_scan.py --key-file tmp\\research-key.txt `
      --path ($sc.DeviceObject + "\\pagefile.sys")
  $sc.Delete()
"""
import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from memory_key_scan import patterns_from

CHUNK = 32 * 1024 * 1024
OVERLAP = 128


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--key-file', required=True)
    ap.add_argument('--path', required=True)
    args = ap.parse_args()
    key = Path(args.key_file).read_text(encoding='utf-8').strip()
    if not key:
        ap.error('key file is empty')
    pats = patterns_from(key)
    counts = {name: 0 for name in pats}
    offsets = {name: [] for name in pats}
    total = 0
    with open(args.path, 'rb') as f:
        while True:
            block = f.read(CHUNK)
            if not block:
                break
            for name, needle in pats.items():
                start = OVERLAP if total else 0
                while True:
                    i = block.find(needle, start)
                    if i < 0:
                        break
                    counts[name] += 1
                    if len(offsets[name]) < 16:
                        offsets[name].append(hex(total + i))
                    start = i + 1
            total += len(block)
    print(f'scanned {total / 2**30:.2f} GiB of {args.path}')
    any_hit = False
    for name in pats:
        if counts[name]:
            any_hit = True
            print(f'{name}: {counts[name]} hit(s), first offsets={offsets[name]}')
    if not any_hit:
        print('no key material found in pagefile image')


if __name__ == '__main__':
    main()
