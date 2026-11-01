#!/usr/bin/env python3
"""Build a TrollStore .tipa whose payload is the game itself.

The difference from DeltaSkin.tipa: that one installs a small patcher app with
its own bundle id and patches the game in place. This one keeps the game's own
identity (com.garena.game.df), so TrollStore installs it *as* the game and the
dylib is already inside at first launch. Use it when you cannot or do not want
to run the patcher on the device.

What changes inside the payload, and nothing else:
  * CFBundleIdentifier is forced to --bundle-id (default com.garena.game.df)
  * the executable gains one LC_LOAD_DYLIB for @executable_path/Frameworks/<dylib>
  * Frameworks/DeltaSkin.dylib is added
Every other file is copied byte for byte.

The executable is rewritten by LIEF, which drops the old LC_CODE_SIGNATURE --
expected: TrollStore signs the bundle on install.

    python tools/make_game_tipa.py --app D:\\delta\\Payload\\DeltaForceClient.app \\
        --dylib build/DeltaSkin.dylib --out DeltaForce-patched.tipa

Needs: pip install lief
"""

import argparse
import os
import plistlib
import sys
import zipfile

LOAD_PATH = "@executable_path/Frameworks/"


def inject(exe_path, payload, load_path, scratch):
    import lief

    binary = lief.MachO.parse(exe_path).__getitem__(0)
    if binary is None:
        raise SystemExit("not a Mach-O: %s" % exe_path)
    if any(c.name == load_path for c in binary.libraries):
        return None                      # already injected, reuse the file
    binary.add_library(load_path)
    out = os.path.join(scratch, os.path.basename(exe_path))
    binary.write(out)
    if not os.path.exists(out):
        raise SystemExit("LIEF produced no output for %s" % exe_path)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--app", required=True, help="source .app directory")
    ap.add_argument("--dylib", required=True, help="DeltaSkin.dylib to embed")
    ap.add_argument("--out", required=True, help="output .tipa")
    ap.add_argument("--bundle-id", default="com.garena.game.df")
    args = ap.parse_args()

    app = os.path.abspath(args.app)
    plist_path = os.path.join(app, "Info.plist")
    with open(plist_path, "rb") as f:
        info = plistlib.load(f)
    exe_name = info.get("CFBundleExecutable") or ""
    if not exe_name:
        raise SystemExit("Info.plist has no CFBundleExecutable")
    exe_path = os.path.join(app, exe_name)
    if not os.path.isfile(exe_path):
        raise SystemExit("missing executable: %s" % exe_path)
    if not os.path.isfile(args.dylib):
        raise SystemExit("missing dylib: %s" % args.dylib)

    scratch = os.path.join(os.path.dirname(os.path.abspath(args.out)), "_tipa_scratch")
    os.makedirs(scratch, exist_ok=True)

    load_path = LOAD_PATH + os.path.basename(args.dylib)
    print("injecting %s -> %s" % (load_path, exe_name))
    injected = inject(exe_path, args.dylib, load_path, scratch)

    info["CFBundleIdentifier"] = args.bundle_id
    with open(plist_path, "rb") as f:
        old_plist = f.read()
    new_plist = plistlib.dumps(info, fmt=plistlib.FMT_XML)

    app_name = os.path.basename(app)
    root = "Payload/" + app_name
    dylib_entry = root + "/Frameworks/" + os.path.basename(args.dylib)
    exe_entry = root + "/" + exe_name
    plist_entry = root + "/Info.plist"

    written = {"exe": False, "dylib": False, "plist": False}
    total = 0
    with zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as z:
        for dirpath, _dirnames, filenames in os.walk(app):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, app).replace(os.sep, "/")
                entry = root + "/" + rel
                if entry == exe_entry and injected:
                    z.write(injected, entry)
                    written["exe"] = True
                elif entry == plist_entry and new_plist != old_plist:
                    z.writestr(entry, new_plist)
                    written["plist"] = True
                elif entry == dylib_entry:
                    z.write(args.dylib, entry)       # always the fresh build
                    written["dylib"] = True
                else:
                    z.write(full, entry)
                total += os.path.getsize(full)
        if not written["dylib"]:
            z.write(args.dylib, dylib_entry)
            written["dylib"] = True

    # Self-check: reopen and prove the three things that matter.
    with zipfile.ZipFile(args.out) as z:
        names = set(z.namelist())
        assert dylib_entry in names, "dylib missing from the archive"
        assert exe_entry in names, "executable missing from the archive"
        got = plistlib.loads(z.read(plist_entry))
        assert got["CFBundleIdentifier"] == args.bundle_id, "bundle id not set"
        blob = z.read(exe_entry)
        assert load_path.encode() in blob, "load command not in the executable"

    print("ok  %s  %.1f MB (payload %.1f MB)  id=%s"
          % (args.out, os.path.getsize(args.out) / 1e6, total / 1e6, args.bundle_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
