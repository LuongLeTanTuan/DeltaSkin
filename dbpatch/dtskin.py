#!/usr/bin/env python3
"""dtskin.py - client-side skin mod for Delta Force iOS, no code injection.

The game reads /Documents/DeltaForce/Saved/GameData/DataTable.bytes (SQLite) and
never rewrites an existing copy. Each row of WeaponSkinAppearanceTable_CombineTable
holds the appearance blob the client renders for one skin id. Copying a premium
row's blob onto a row you own makes the client draw the premium look while the
server still sees the original skin.

Run on device, in the same folder as DataTable.bytes.

usage:
  python3 dtskin.py list [weapon]         rows for one weapon (or all)
  python3 dtskin.py apply <weapon> [row]  copy richest row onto every body row
  python3 dtskin.py apply-all             same, for every weapon
  python3 dtskin.py copy <src> <dst>      copy one row onto another
  python3 dtskin.py show <row>            dump one row's fields
  python3 dtskin.py restore               put the untouched DB back
"""
import os, re, shutil, sqlite3, struct, sys

GD = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(GD, "DataTable.bytes")
BAK = os.path.join(GD, "DTB_ORIG.bak")
T = "WeaponSkinAppearanceTable_CombineTable"
NAMET = T + "_nametable"

WEAPON_RE = re.compile(r"/Models/Weapons/Parts/[^/]+/[^/]+/([^/]+)/")


def load_names(con):
    out = {}
    for h, byt in con.execute('SELECT hash, bytes FROM "%s"' % NAMET):
        n = struct.unpack_from("<i", byt, 0)[0]
        out[h & 0xFFFFFFFFFFFFFFFF] = byt[4:4 + n - 1].decode("utf-8", "replace")
    return out


def fname(nm, blob, off):
    if off + 8 > len(blob):
        return None
    return nm.get(struct.unpack_from("<Q", blob, off)[0])


def weapon_of(mat):
    m = WEAPON_RE.search(mat or "")
    return m.group(1) if m else None


def skin_tag(mat):
    return (mat or "").split("/")[-1].split("_ForParts")[0]


def body_rows(nm, rows):
    """rows of set() that are whole-weapon skins, not attachment slots."""
    out = []
    for rn, blob in rows:
        if rn == "NewRow":
            continue
        mat = fname(nm, blob, 0x32) or ""
        # adapter slots have an EAdapterItemType::* marker at 0x46 and a
        # per-part material; copying a body blob into them breaks that slot
        if not (fname(nm, blob, 0x46) or "").startswith("EWeaponSkinRareType"):
            continue
        w = weapon_of(mat)
        if w:
            out.append((rn, w, blob, skin_tag(mat)))
    return out


def ensure_backup():
    if not os.path.exists(BAK):
        print("backup ->", BAK)
        shutil.copyfile(DB, BAK)


def write_rows(pairs):
    """pairs: (row_name, blob_with_row_id_already_patched)"""
    con = sqlite3.connect(DB)
    con.execute("PRAGMA journal_mode=DELETE")
    for rn, blob, src_id in pairs:
        con.execute('UPDATE "%s" SET RowBlob=?, SkinAppearanceId=? '
                    'WHERE RowName=?' % T, (blob, src_id, rn))
    con.commit()
    ok = con.execute("PRAGMA integrity_check").fetchone()[0]
    con.close()
    return ok


def stamp(blob, row_id):
    b = bytearray(blob)
    struct.pack_into("<I", b, 0, int(row_id))
    return bytes(b)


def cmd_list(arg):
    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    nm = load_names(con)
    rows = body_rows(nm, con.execute('SELECT RowName, RowBlob FROM "%s"' % T))
    con.close()
    per = {}
    for rn, w, blob, tag in rows:
        per.setdefault(w, []).append((rn, len(blob), tag))
    for w in sorted(per):
        if arg and arg.lower() not in w.lower():
            continue
        v = sorted(per[w], key=lambda r: int(r[0]))
        best = max(v, key=lambda r: r[1])
        print("\n%s  (%d body rows, richest %s %dB)"
              % (w, len(v), best[0], best[1]))
        for rn, n, tag in v:
            mark = "*" if rn == best[0] else " "
            print("  %s %-7s %6dB  %s" % (mark, rn, n, tag))
    print("\n%d weapons, %d body rows" % (len(per), len(rows)))


def cmd_apply(weapon, src_row=None):
    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    nm = load_names(con)
    rows = body_rows(nm, con.execute('SELECT RowName, RowBlob FROM "%s"' % T))
    allrows = {rn: blob for rn, blob in
               con.execute('SELECT RowName, RowBlob FROM "%s"' % T)}
    con.close()

    target = [r for r in rows if weapon.lower() in r[1].lower()]
    if not target:
        sys.exit("no body rows match %r" % weapon)
    if src_row:
        if src_row not in allrows:
            sys.exit("row %s not found" % src_row)
        src_id, src_blob = src_row, allrows[src_row]
    else:
        src_id, _, src_blob, _tag = max(target, key=lambda r: len(r[2]))
    print("source row %s (%d bytes)" % (src_id, len(src_blob)))
    pairs = [(rn, stamp(src_blob, rn), src_id) for rn, w, b, t in target]
    ok = write_rows(pairs)
    print("patched %d rows of %s  integrity=%s" % (len(pairs), target[0][1], ok))


def cmd_apply_all():
    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    nm = load_names(con)
    rows = body_rows(nm, con.execute('SELECT RowName, RowBlob FROM "%s"' % T))
    con.close()
    per = {}
    for rn, w, blob, tag in rows:
        per.setdefault(w, []).append((rn, blob))
    pairs = []
    for w, v in per.items():
        src_rn, src_blob = max(v, key=lambda r: len(r[1]))
        for rn, _ in v:
            pairs.append((rn, stamp(src_blob, rn), src_rn))
    ok = write_rows(pairs)
    print("patched %d body rows across %d weapons  integrity=%s"
          % (len(pairs), len(per), ok))


def cmd_copy(src, dst):
    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    row = con.execute('SELECT RowBlob FROM "%s" WHERE RowName=?' % T,
                      (src,)).fetchone()
    con.close()
    if not row:
        sys.exit("source row %s not found" % src)
    ok = write_rows([(dst, stamp(row[0], dst), src)])
    print("row %s <- %s (%d bytes)  integrity=%s" % (dst, src, len(row[0]), ok))


def cmd_show(row):
    con = sqlite3.connect("file:%s?mode=ro" % DB, uri=True)
    nm = load_names(con)
    r = con.execute('SELECT RowBlob FROM "%s" WHERE RowName=?' % T,
                    (row,)).fetchone()
    con.close()
    if not r:
        sys.exit("row %s not found" % row)
    b = r[0]
    print("row %s  %d bytes" % (row, len(b)))
    i = 0
    while i < len(b):
        if i + 8 <= len(b):
            v = struct.unpack_from("<Q", b, i)[0]
            if v in nm:
                print("  0x%03x  %s" % (i, nm[v]))
                i += 8
                continue
        i += 1


def cmd_restore():
    if not os.path.exists(BAK):
        sys.exit("no backup at %s" % BAK)
    shutil.copyfile(BAK, DB)
    print("restored", DB)


def main():
    a = sys.argv[1:]
    if not a:
        sys.exit(__doc__)
    op = a[0]
    if op == "restore":
        cmd_restore()
        return
    if op == "list":
        cmd_list(a[1] if len(a) > 1 else None)
    elif op == "show":
        cmd_show(a[1])
    elif op == "apply":
        ensure_backup()
        cmd_apply(a[1], a[2] if len(a) > 2 else None)
    elif op == "apply-all":
        ensure_backup()
        cmd_apply_all()
    elif op == "copy":
        ensure_backup()
        cmd_copy(a[1], a[2])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
