#!/usr/bin/env python3
"""Repoint the blob's internal calls to wlc_sendauth / wlc_authresp_client to our glue
hooks (__wrap_*). ld --wrap can't do this for ld -r internal (defined) symbols, so we edit
the ELF directly: add 2 UNDEF global symbols, and rewrite every .rela.text entry that
referenced the real symbols to reference the wraps. The -r link then resolves the call
sites to the glue hooks; the hooks chain to the real (globalized) functions by name.

Layout-safe: grown .symtab/.strtab are appended at EOF and their section headers updated in
place (section data may live after the shdr table; sh_offset is authoritative). Idempotent."""
import struct, sys, os

TARGET = (sys.argv[1] if len(sys.argv) > 1 else
          os.environ.get("BLOB", "wl-src/lib/wlc_hybrid.o_amd64"))
REDIRECTS = {  # real symbol -> wrapper symbol (defined in the glue)
    "wlc_sendauth": "__wrap_wlc_sendauth",
    "wlc_authresp_client": "__wrap_wlc_authresp_client",
    "wlc_recv": "__wrap_wlc_recv",
    "wlc_sendmgmt": "__wrap_wlc_sendmgmt",   # Block Ack frames must be CCMP-protected under PMF
}

def main():
    data = bytearray(open(TARGET, "rb").read())
    assert data[:4] == b"\x7fELF" and data[4] == 2, "not ELF64"
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shnum = struct.unpack_from("<H", data, 0x3c)[0]
    e_shstrndx = struct.unpack_from("<H", data, 0x3e)[0]

    def shdr(i):
        o = e_shoff + i * 64
        name, typ, flags, addr, offset, size, link, info, align, entsize = \
            struct.unpack_from("<IIQQQQIIQQ", data, o)
        return dict(hoff=o, name=name, type=typ, offset=offset, size=size, link=link)
    shs = [shdr(i) for i in range(e_shnum)]
    shstr_off = shs[e_shstrndx]["offset"]
    def secname(sh):
        s = shstr_off + sh["name"]; return data[s:data.index(b"\0", s)].decode()

    symtab = next(s for s in shs if s["type"] == 2)
    strtab = shs[symtab["link"]]
    rela = next(s for s in shs if s["type"] == 4 and secname(s) == ".rela.text")

    nsym = symtab["size"] // 24
    def symname(i):
        nm = struct.unpack_from("<I", data, symtab["offset"] + i * 24)[0]
        s = strtab["offset"] + nm; return data[s:data.index(b"\0", s)].decode()
    name2idx = {symname(i): i for i in range(nsym) if symname(i)}

    if "__wrap_wlc_sendauth" in name2idx:
        print("already patched (__wrap_* present)"); return
    for real in REDIRECTS:
        if real not in name2idx:
            print("ERROR: %s not in symtab" % real); sys.exit(2)

    new_str = bytearray(data[strtab["offset"]:strtab["offset"] + strtab["size"]])
    new_sym = bytearray(data[symtab["offset"]:symtab["offset"] + symtab["size"]])
    wrap_idx = {}
    for k, (real, wrap) in enumerate(REDIRECTS.items()):
        noff = len(new_str); new_str += wrap.encode() + b"\0"
        new_sym += struct.pack("<IBBHQQ", noff, 0x10, 0, 0, 0, 0)  # GLOBAL|NOTYPE, UNDEF
        wrap_idx[real] = nsym + k

    redirected = 0
    for i in range(rela["size"] // 24):
        ro = rela["offset"] + i * 24
        r_info = struct.unpack_from("<Q", data, ro + 8)[0]
        sym, typ = r_info >> 32, r_info & 0xffffffff
        for real, wrap in REDIRECTS.items():
            if sym == name2idx[real]:
                struct.pack_into("<Q", data, ro + 8, (wrap_idx[real] << 32) | typ)
                redirected += 1

    while len(data) % 8:
        data += b"\0"
    so = len(data); data += new_sym
    to = len(data); data += new_str
    struct.pack_into("<Q", data, symtab["hoff"] + 24, so)
    struct.pack_into("<Q", data, symtab["hoff"] + 32, len(new_sym))
    struct.pack_into("<Q", data, strtab["hoff"] + 24, to)
    struct.pack_into("<Q", data, strtab["hoff"] + 32, len(new_str))
    open(TARGET, "wb").write(data)
    print("OK: +%d symbols, %d relocations redirected to wraps" % (len(REDIRECTS), redirected))

main()
