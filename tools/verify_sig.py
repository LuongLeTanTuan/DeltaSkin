#!/usr/bin/env python3
"""Independent verifier for the ad-hoc signature the patcher writes.

Recomputes the CodeDirectory page hashes from the file itself and compares them
with the slots, checks the special slots, the codeLimit, and the LC_LOAD_DYLIB
entry. Exits non-zero on any mismatch, so CI fails loudly instead of shipping a
signature only our own writer believes in.
"""
import struct
import sys
import hashlib

MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_LOAD_DYLIB = 0xC
LC_CODE_SIGNATURE = 0x1D

CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02


def fail(msg):
    print("FAIL " + msg)
    sys.exit(1)


def main(path, want_dylib=None):
    b = open(path, "rb").read()
    if len(b) < 32:
        fail("file too small")
    magic, cputype, cpusub, filetype, ncmds, sizeofcmds, flags, _ = struct.unpack_from("<8I", b, 0)
    if magic != MH_MAGIC_64:
        fail("not MH_MAGIC_64 (0x%x)" % magic)
    if cputype != 0x0100000C:
        fail("not arm64 (0x%x)" % cputype)

    off = 32
    sig = None
    dylibs = []
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", b, off)
        if cmdsize < 8:
            fail("bad cmdsize")
        if cmd == LC_CODE_SIGNATURE:
            _, _, dataoff, datasize = struct.unpack_from("<4I", b, off)
            sig = (dataoff, datasize)
        elif cmd == LC_LOAD_DYLIB:
            name_off = struct.unpack_from("<I", b, off + 8)[0]
            raw = b[off + name_off: off + cmdsize].split(b"\x00")[0]
            dylibs.append(raw.decode("utf-8", "replace"))
        off += cmdsize

    if sig is None:
        fail("no LC_CODE_SIGNATURE")
    dataoff, datasize = sig
    if dataoff + datasize > len(b):
        fail("signature runs past EOF")

    print("cputype      arm64")
    print("filetype     %d" % filetype)
    print("dylibs       %s" % (dylibs or "-"))
    print("sig          off=0x%X size=%d" % (dataoff, datasize))

    if want_dylib and want_dylib not in dylibs:
        fail("expected LC_LOAD_DYLIB %s" % want_dylib)

    s = b[dataoff:dataoff + datasize]
    magic, length, count = struct.unpack_from(">3I", s, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        fail("bad SuperBlob magic 0x%x" % magic)
    if length > datasize:
        fail("SuperBlob length %d > datasize %d" % (length, datasize))

    blobs = {}
    for i in range(count):
        t, o = struct.unpack_from(">2I", s, 12 + i * 8)
        blobs[t] = o

    if 0 not in blobs:
        fail("no CodeDirectory")
    cd = s[blobs[0]:]
    cms_len = 0
    if 0x10000 in blobs:
        cms_magic, cms_len = struct.unpack_from(">2I", s, blobs[0x10000])
        if cms_magic != 0xFADE0B01:
            fail("CMS blob magic 0x%x, expected 0xFADE0B01" % cms_magic)
        cms_len -= 8
        print("cms          %d bytes" % cms_len)

    (cdmagic, cdlen, version, cdflags, hash_off, ident_off, nspecial, ncode,
     code_limit) = struct.unpack_from(">9I", cd, 0)
    if cdmagic != CSMAGIC_CODEDIRECTORY:
        fail("bad CodeDirectory magic 0x%x" % cdmagic)
    hash_size, hash_type, platform, page_shift = struct.unpack_from("<4B", cd, 36)
    (code_limit64, exec_base, exec_limit, exec_flags) = struct.unpack_from(">4Q", cd, 56)

    ident = cd[ident_off:cd.index(b"\x00", ident_off)].decode()
    print("version      0x%X" % version)
    print("flags        0x%X" % cdflags)
    print("ident        %s" % ident)
    print("codeLimit    0x%X (file says %d)" % (code_limit, dataoff))
    print("slots        code=%d special=%d" % (ncode, nspecial))
    print("execSeg      0x%X..0x%X flags 0x%X" % (exec_base, exec_limit, exec_flags))

    if cdflags & 0x2 == 0 and not cms_len:
        fail("neither CS_ADHOC nor a CMS blob is present")
    if hash_size != 32 or hash_type != 2:
        fail("expected SHA-256 slots")
    if code_limit != dataoff:
        fail("codeLimit 0x%X != signature offset 0x%X" % (code_limit, dataoff))
    if len(cd) < hash_off + ncode * hash_size:
        fail("CodeDirectory shorter than its slot table")

    page = 1 << page_shift
    expect_ncode = (code_limit + page - 1) // page
    if ncode != expect_ncode:
        fail("nCodeSlots %d != ceil(%d/%d) = %d" % (ncode, code_limit, page, expect_ncode))

    bad = 0
    for i in range(ncode):
        start = i * page
        n = min(page, code_limit - start)
        h = hashlib.sha256(b[start:start + n]).digest()
        got = cd[hash_off + i * hash_size: hash_off + (i + 1) * hash_size]
        if h != got:
            if bad < 3:
                print("  page %d mismatch (offset 0x%X)" % (i, start))
            bad += 1
    if bad:
        fail("%d/%d page hashes do not match the file" % (bad, ncode))

    if nspecial >= 1 and 5 in blobs:
        ent_blob = s[blobs[5]:]
        emagic, elen = struct.unpack_from(">2I", ent_blob, 0)
        ent = ent_blob[8:elen] if emagic == 0xFADE7171 else ent_blob[:elen]
        want = hashlib.sha256(ent).digest()
        slot = cd[hash_off - hash_size: hash_off]
        if want != slot:
            fail("entitlements slot hash mismatch")
        print("entitlements %d bytes, slot -1 ok" % len(ent))

    print("OK  %d/%d page hashes verified" % (ncode, ncode))
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: verify_sig.py <macho> [expected-dylib-path]")
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None))
