#!/usr/bin/env python3
"""Replay ds_load_table() over src/SkinTable.h and check every id against the
vendor catalog. Exit 1 on any mismatch. Writes the summary to verify.txt.

Run from the repo root:  python tools/verify_table.py
"""
import collections
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TABLE = os.path.join(ROOT, "src", "SkinTable.h")
PXFFI = os.environ.get(
    "PXEXTFFI",
    r"D:\delta\Payload\DeltaForceClient.app\Frameworks\PxExtFFi.framework\PxExtFFi",
)
XOR = 0x5A
KIND = 6
NAME_TAG = 0x00300000


def load_table():
    src = open(TABLE, encoding="utf8").read()
    weapons = int(re.search(r"DS_WEAPON_COUNT\s+(\d+)", src).group(1))
    rows = int(re.search(r"DS_SKIN_ROW_COUNT\s+(\d+)", src).group(1))
    body = re.search(r"ds_blob\[(\d+)\]\s*=\s*\{(.*?)\};", src, re.S)
    size = int(body.group(1))
    raw = bytes(int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", body.group(2)))
    assert len(raw) == size, "declared blob size %d != %d bytes" % (size, len(raw))

    # ds_blob_str(): XOR 0x5A, capped at 256 bytes, must be valid UTF-8.
    d = bytes(b ^ XOR for b in raw)
    p = 0
    names = []
    for _ in range(weapons):
        n = d[p]
        names.append(d[p + 1:p + 1 + n].decode("utf8"))
        p += 1 + n
    table = []
    for _ in range(rows):
        w = d[p]
        sid = struct.unpack_from("<I", d, p + 1)[0]
        n = d[p + 5]
        table.append((w, sid, d[p + 6:p + 6 + n].decode("utf8")))
        p += 6 + n
    return weapons, rows, size, names, table, p


def vendor_ids():
    data = open(PXFFI, "rb").read()
    n = len(data)

    def cstr(off, cap=200):
        if off <= 0 or off >= n:
            return None
        end = data.find(b"\x00", off, off + cap)
        if end < 0:
            return None
        try:
            return data[off:end].decode("utf8") or None
        except UnicodeDecodeError:
            return None

    ids, ghosts = set(), []
    i = 0
    while i + 16 <= n:
        if data[i + 4:i + 8] == struct.pack("<I", KIND) and \
           data[i + 12:i + 16] == struct.pack("<I", NAME_TAG):
            idv = struct.unpack_from("<I", data, i)[0]
            if cstr(struct.unpack_from("<I", data, i + 8)[0]):
                ids.add(idv)
            else:
                ghosts.append((i, idv))
            i += 16
            continue
        i += 4
    return ids, ghosts


def main():
    weapons, rows, size, names, table, consumed = load_table()
    fails = []

    if consumed != size:
        fails.append("consumed %d of %d blob bytes" % (consumed, size))
    ids = [r[1] for r in table]
    if len(set(ids)) != len(ids):
        dup = [hex(k) for k, v in collections.Counter(ids).items() if v > 1]
        fails.append("duplicate ids: %s" % ", ".join(dup))
    if any(r[0] >= weapons for r in table):
        fails.append("row points past the weapon array")
    if any(not r[2] for r in table):
        fails.append("empty skin name")
    if any(not w for w in names):
        fails.append("empty weapon name")
    if sum(1 for i in range(weapons) if not any(r[0] == i for r in table)):
        fails.append("weapon group with no skins")

    vids, ghosts = vendor_ids()
    missing = sorted(set(ids) - vids)
    extra = sorted(vids - set(ids))
    if missing:
        fails.append("ids not in vendor catalog: %s" % [hex(x) for x in missing])
    if extra:
        fails.append("vendor ids missing from table: %s" % [hex(x) for x in extra])

    lines = [
        "consumed %d/%d blob bytes" % (consumed, size),
        "%d weapon groups / %d skin rows / %d unique ids" % (weapons, rows, len(set(ids))),
        "vendor catalog: %d ids (%d ghost records dropped)" % (len(vids), len(ghosts)),
        "table ids == vendor ids: %s" % (not missing and not extra),
    ]
    print("\n".join(lines))
    if fails:
        print("\nFAIL")
        for f in fails:
            print("  " + f)
        sys.exit(1)
    print("OK")
    with open(os.path.join(ROOT, "verify.txt"), "w", encoding="utf8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
