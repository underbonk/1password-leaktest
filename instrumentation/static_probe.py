"""File-only helpers for targeted analysis. Does not attach to a process.

Requires pefile and capstone (`pip install pefile capstone`) and an analysis
copy of the native module at analysis/index.node (not published)."""
import argparse,bisect,json,re,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
import pefile,capstone

ap=argparse.ArgumentParser();ap.add_argument('mode',choices=['refs','prepare','disasm','strings']);ap.add_argument('targets',nargs='+');args=ap.parse_args()
p=pefile.PE(str(ROOT/'analysis/index.node'),fast_load=True)
base=p.OPTIONAL_HEADER.ImageBase
dd=p.OPTIONAL_HEADER.DATA_DIRECTORY[3];pd=p.get_data(dd.VirtualAddress,dd.Size)
bounds=list(struct.iter_unpack('<III',pd[:len(pd)//12*12]));starts=[v[0] for v in bounds]
def containing(rva):
    i=bisect.bisect_right(starts,rva)-1
    if i>=0 and bounds[i][0]<=rva<bounds[i][1]:return bounds[i][:2]
    return None
if args.mode in ['prepare','disasm']:
    c=capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64);items=[];ranges=[]
    for s in args.targets:
        rva=int(s,0);span=containing(rva)
        if not span:raise ValueError('No runtime function for '+s)
        start,end=span;ranges.append([hex(start),hex(end)])
        for ins in c.disasm(p.get_data(start,end-start),base+start):
            if args.mode=='prepare':items.append({'addr':hex(ins.address)})
            else:print(hex(ins.address-base),ins.mnemonic,ins.op_str)
    if args.mode=='prepare':print(json.dumps({'bounds':ranges,'items':items}))
elif args.mode=='refs':
    targets=[]
    for x in args.targets:
        a=x.split(':');lo=int(a[0],0);targets.append((lo,int(a[1],0) if len(a)>1 else lo+1))
    results=[]
    for sec in p.sections:
        if not sec.Characteristics&0x20000000:continue
        data=sec.get_data();rbase=sec.VirtualAddress
        for m in re.finditer(rb'[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d].{4}|\xe8.{4}',data,re.S):
            pos=m.start();size=len(m.group());dest=rbase+pos+size+struct.unpack_from('<i',data,pos+size-4)[0]
            if any(lo<=dest<hi for lo,hi in targets):
                loc=rbase+pos;span=containing(loc)
                results.append({'site':hex(loc),'target':hex(dest),'function':[hex(v) for v in span] if span else None,'kind':'call' if size==5 else 'lea'})
    print(json.dumps(results))
else:
    data=(ROOT/'analysis/index.node').read_bytes()
    for term in args.targets:
        hits=[]
        for m in re.finditer(re.escape(term.encode()),data,re.I):
            hits.append({'rva':hex(p.get_rva_from_offset(m.start())),'context':repr(data[max(0,m.start()-40):m.start()+120])})
        print(json.dumps({'term':term,'hits':hits[:30],'total':len(hits)}))
