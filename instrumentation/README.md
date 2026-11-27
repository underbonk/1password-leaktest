# Auxiliary local scanners

Plain-stdlib Python (ctypes) tools for checking whether a Secret Key is
recoverable *outside* the network path: process memory and `pagefile.sys`.
These are read-only companions to the network viewer in `gui/` — they are not
needed for the network check, and none of them modifies the target process.

All of them read the key from a local file and never print it. The expected
file is a gitignored `.secrets` in the repo root (or `tmp/research-key.txt`):

```text
SECRET_KEY=A3-...
```

Delete the key file when you are done.

## memory_key_scan.py

Read-only memory search (`OpenProcess(PROCESS_VM_READ)` + `VirtualQueryEx` /
`ReadProcessMemory`; no injection, no hooks) of every `1Password.exe` process,
or explicit PIDs. Searches ten encodings of the key (full/secret portion,
UTF-8/UTF-16LE, dashless, plus a first-group probe) and reports counts, region
metadata, and match addresses only — no memory contents are dumped. The needle
stays in the scanner process; it never exists in the target's memory.

```powershell
python instrumentation/memory_key_scan.py --key-file tmp/research-key.txt
python instrumentation/memory_key_scan.py --key-file tmp/research-key.txt --pid 1234
```

Run it after sign-in, then again after locking the app: a formatted copy that
survives lock is the memory result. Read-only caveat: scanning a paged-out
range faults it back into RAM, so scan *before* applying memory pressure, not
after.

## memory_pressure.py

Gives Windows a reason to page, in two phases matching how the OS actually
pages:

```powershell
# Evict the target's pages onto the Modified Page List (still RAM)
python instrumentation/memory_pressure.py trim --pid 1234

# Allocate+touch memory until ~2 GiB free remains, then hold it
python instrumentation/memory_pressure.py pressure --hold 120
```

Verification: watch `\Memory\Modified Page List Bytes`,
`\Paging File(_Total)\% Usage`, and `\Process(1Password*)\Working Set` while
pressure is held. Content proof requires reading `pagefile.sys` afterwards
(see below).

## pagefile_scan.py

Exact scan of a pagefile image (or any large file), streamed in 32 MiB chunks.
Prints per-encoding hit counts and file offsets only. Normally driven by
`scanpagefile.ps1` (elevated; creates a VSS shadow copy of `C:`, scans,
deletes the shadow). Direct use:

```powershell
python instrumentation/pagefile_scan.py --key-file tmp\research-key.txt --path <shadow-device>\pagefile.sys
```

## static_probe.py

File-only helper (pefile + capstone, no process attachment) used to re-derive
and cross-check the DLL's hook offsets when porting to a new `index.node`
build: function bounds, disassembly of a function containing an RVA, xrefs to
an address range, and string search. Expects an analysis copy of the module at
`analysis/index.node` (not published; point it at your own licensed copy).

```powershell
python instrumentation/static_probe.py disasm 0x5F25440
python instrumentation/static_probe.py refs 0x5F25440:0x5F25500
```
