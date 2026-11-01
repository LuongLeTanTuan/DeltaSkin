// DeltaSkin - UE5 skin mod bridge for DeltaForceClient (iOS, arm64)
// Standalone dylib. No Substrate/Cydia dependency: designed to be injected into
// the sideloaded IPA (eSign/Sideloadly) so it also works on non-jailbroken iOS.
//
// Layout knowledge below is derived from static analysis of PxMenu.dylib
// (see REPORT.md): the original resolves GNames/GObjects at runtime by scanning
// the host image __DATA range, then walks the UObject array by chunk.
// Nothing here swizzles or patches engine/anti-cheat code; it only reads engine
// objects and calls a UFunction native entry with a parameter block.

#import <UIKit/UIKit.h>
#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/sysctl.h>
#import <libkern/OSCacheControl.h>
#import <unistd.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>

// ---------------------------------------------------------------- obfuscation
// Engine identifiers are stored XOR'd so the strings never appear in __cstring.
// This is cheap hygiene against naive string scanning by the anti-cheat.
// The volatile salt is always 0; it exists so clang cannot constant-fold the
// decoder and re-emit every plaintext string into the binary (it does that at
// -O2 if the loop is provably constant, which is exactly what we must avoid).
static volatile unsigned char gMaskSalt = 0;

__attribute__((noinline))
static NSString *DSDecode(const unsigned char *buf, size_t len, unsigned char key) {
    char tmp[128] = {0};
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    key ^= gMaskSalt;
    for (size_t i = 0; i < len; i++) tmp[i] = (char)(buf[i] ^ key);
    return [NSString stringWithUTF8String:tmp];
}

#define DSSTR(name, key, ...) \
    static NSString *name(void) { \
        static const unsigned char b[] = { __VA_ARGS__ }; \
        return DSDecode(b, sizeof(b), key); \
    }

DSSTR(kClassWeaponDesc, 0x5A,
      0x17, 0x35, 0x3E, 0x2F, 0x36, 0x3B, 0x28, 0x0D, 0x3F, 0x3B, 0x2A, 0x35, 0x34, 0x1E, 0x3F, 0x29, 0x39)
DSSTR(kClassGPWeaponDesc, 0x5A,
      0x1D, 0x0A, 0x17, 0x35, 0x3E, 0x2F, 0x36, 0x3B, 0x28, 0x0D, 0x3F, 0x3B, 0x2A, 0x35, 0x34, 0x1E, 0x3F, 0x29, 0x39)
DSSTR(kClassDataAppearance, 0x33,
      0x7E, 0x5C, 0x57, 0x46, 0x5F, 0x52, 0x41, 0x64, 0x56, 0x52, 0x43, 0x5C, 0x5D, 0x77, 0x52, 0x47, 0x52, 0x70, 0x5C, 0x5E, 0x43, 0x5C, 0x5D, 0x56, 0x5D, 0x47, 0x72, 0x43, 0x43, 0x56, 0x52, 0x41, 0x52, 0x5D, 0x50, 0x56)
DSSTR(kClassFuncAppearance, 0x33,
      0x7E, 0x5C, 0x57, 0x46, 0x5F, 0x52, 0x41, 0x64, 0x56, 0x52, 0x43, 0x5C, 0x5D, 0x75, 0x46, 0x5D, 0x50, 0x70, 0x5C, 0x5E, 0x43, 0x5C, 0x5D, 0x56, 0x5D, 0x47, 0x72, 0x43, 0x43, 0x56, 0x52, 0x41, 0x52, 0x5D, 0x50, 0x56)
// The setter names below are the ones the vendor menu (PxMenu.dylib 0x18D26)
// looks for, minus "SetSkinId": that name does not exist anywhere in this game
// build, so keeping it at the top of the ranking only ever produced an empty
// pass. Verified present in the DeltaForceClient binary: SetSkinApperanceId,
// SetSkinInfo, SetSkin, SetSkin_BS, SetSkin_ES, ApplySkin.
DSSTR(kFnSetSkinAppearance, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F, 0x00, 0x31, 0x31, 0x24, 0x33, 0x20, 0x2F, 0x22, 0x24, 0x08, 0x25)
DSSTR(kFnSetSkinInfo, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F, 0x08, 0x2F, 0x27, 0x2E)
DSSTR(kFnSetSkin, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F)
DSSTR(kFnApplySkin, 0x41,
      0x00, 0x31, 0x31, 0x2D, 0x38, 0x12, 0x2A, 0x28, 0x2F)
DSSTR(kFnSetSkinBS, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F, 0x1E, 0x03, 0x12)
DSSTR(kFnSetSkinES, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F, 0x1E, 0x04, 0x12)
DSSTR(kHostImage, 0x13,
      0x57, 0x76, 0x7F, 0x67, 0x72, 0x55, 0x7C, 0x61, 0x70, 0x76, 0x50, 0x7F, 0x7A, 0x76, 0x7D, 0x67)
// Bundle id of the game. The host image is the main executable when the dylib is
// injected into the app, and a re-signed IPA can rename that executable -- the
// vendor menu and every clone so far keyed on the file name and went blind the
// moment it changed. The bundle id survives re-signing.
DSSTR(kHostBundle, 0x5A,
      0x39, 0x35, 0x37, 0x74, 0x3D, 0x3B, 0x28, 0x3F, 0x34, 0x3B, 0x74, 0x3D, 0x3B, 0x37, 0x3F, 0x74, 0x3E, 0x3C)

// ACE export names stay encoded too: a dylib carrying "AnoSDK..." in plain
// sight is the easiest thing in the world for ACE to find in the image list.
DSSTR(kAce0, 0x37,
      0x76, 0x59, 0x58, 0x64, 0x73, 0x7C, 0x70, 0x52, 0x43, 0x65, 0x52, 0x47, 0x58, 0x45, 0x43, 0x73, 0x56, 0x43, 0x56)
DSSTR(kAce1, 0x37,
      0x76, 0x59, 0x58, 0x64, 0x73, 0x7C, 0x70, 0x52, 0x43, 0x65, 0x52, 0x47, 0x58, 0x45, 0x43, 0x73, 0x56, 0x43, 0x56, 0x05)
DSSTR(kAce2, 0x37,
      0x76, 0x59, 0x58, 0x64, 0x73, 0x7C, 0x70, 0x52, 0x43, 0x65, 0x52, 0x47, 0x58, 0x45, 0x43, 0x73, 0x56, 0x43, 0x56, 0x04)
DSSTR(kAce3, 0x37,
      0x76, 0x59, 0x58, 0x64, 0x73, 0x7C, 0x70, 0x52, 0x43, 0x65, 0x52, 0x47, 0x58, 0x45, 0x43, 0x73, 0x56, 0x43, 0x56, 0x03)
DSSTR(kAce4, 0x37,
      0x76, 0x59, 0x58, 0x64, 0x73, 0x7C, 0x73, 0x52, 0x5B, 0x65, 0x52, 0x47, 0x58, 0x45, 0x43, 0x73, 0x56, 0x43, 0x56)
DSSTR(kAce5, 0x37,
      0x76, 0x59, 0x58, 0x64, 0x73, 0x7C, 0x73, 0x52, 0x5B, 0x65, 0x52, 0x47, 0x58, 0x45, 0x43, 0x73, 0x56, 0x43, 0x56, 0x04)
DSSTR(kAce6, 0x37,
      0x76, 0x59, 0x58, 0x64, 0x73, 0x7C, 0x73, 0x52, 0x5B, 0x65, 0x52, 0x47, 0x58, 0x45, 0x43, 0x73, 0x56, 0x43, 0x56, 0x03)

// "has been jailbroken, which poses a security risk" ^0x2B - the anchor ACE
// uses for its "leave the game" dialog on jailbroken devices.
DSSTR(kJailbreakMessage, 0x2B,
      0x43, 0x4A, 0x58, 0x0B, 0x49, 0x4E, 0x4E, 0x45, 0x0B, 0x41, 0x4A, 0x42,
      0x47, 0x49, 0x59, 0x44, 0x40, 0x4E, 0x45, 0x07, 0x0B, 0x5C, 0x43, 0x42,
      0x48, 0x43, 0x0B, 0x5B, 0x44, 0x58, 0x4E, 0x58, 0x0B, 0x4A, 0x0B, 0x58,
      0x4E, 0x48, 0x5E, 0x59, 0x42, 0x5F, 0x52, 0x0B, 0x59, 0x42, 0x58, 0x40)

// -------------------------------------------------------- weapon / skin table
// Generated by tools/build_table.py from PxExtFFi (the vendor menu's own UI
// framework): 64 groups / 705 rows, every id read verbatim from the vendor's
// static catalog. PxMenu.dylib's table was used before and it was wrong twice:
// its "weapon" list carried skin entries as if they were weapons ("ASh-12
// Battle Rifle-Goose Goose Duck", "KC17 Assault Rifle-SAW", 22 of 85), and the
// loose 4-byte scan that built the old table also picked up three ghost records
// whose name pointer resolves to nothing -- those ids applied whatever the game
// happened to have there, which is the "skin lands on the wrong gun" symptom.
// The blob is XOR 0x5A so no weapon or skin name sits in the binary readable.
#include "SkinTable.h"

static NSArray<NSString *> *gWeaponNames = nil;
static NSArray<NSArray<NSString *> *> *gSkinNames = nil;
static NSArray<NSArray<NSNumber *> *> *gSkinIds = nil;

__attribute__((noinline))
static NSString *ds_blob_str(const unsigned char *p, size_t n) {
    if (n >= 256) return @"";
    char tmp[256];
    unsigned char k = (unsigned char)(0x5A ^ gMaskSalt);
    for (size_t i = 0; i < n; i++) tmp[i] = (char)(p[i] ^ k);
    tmp[n] = 0;
    return [NSString stringWithUTF8String:tmp] ?: @"";
}

// Decoded once, on the main thread (only the picker touches these arrays).
static void ds_load_table(void) {
    if (gWeaponNames) return;
    const unsigned char *p = ds_blob;

    NSMutableArray<NSString *> *wn = [NSMutableArray arrayWithCapacity:DS_WEAPON_COUNT];
    for (int i = 0; i < DS_WEAPON_COUNT; i++) {
        size_t n = *p++;
        [wn addObject:ds_blob_str(p, n)];
        p += n;
    }

    NSMutableArray<NSMutableArray<NSString *> *> *names = [NSMutableArray array];
    NSMutableArray<NSMutableArray<NSNumber *> *> *ids = [NSMutableArray array];
    for (int i = 0; i < DS_WEAPON_COUNT; i++) {
        [names addObject:[NSMutableArray array]];
        [ids addObject:[NSMutableArray array]];
    }

    for (int r = 0; r < DS_SKIN_ROW_COUNT; r++) {
        unsigned w = *p++;
        uint32_t sid = 0;
        memcpy(&sid, p, sizeof(sid));           // little-endian on both targets
        p += sizeof(sid);
        size_t n = *p++;
        NSString *nm = ds_blob_str(p, n);
        p += n;
        if (w >= DS_WEAPON_COUNT) continue;
        [names[w] addObject:nm];
        [ids[w] addObject:@(sid)];
    }

    gWeaponNames = wn;
    gSkinNames = names;
    gSkinIds = ids;
}

static NSUInteger ds_weapon_count(void) { ds_load_table(); return gWeaponNames.count; }

static NSString *ds_weapon_name(NSUInteger i) {
    ds_load_table();
    return i < gWeaponNames.count ? gWeaponNames[i] : @"";
}

static NSUInteger ds_skin_count(NSUInteger w) {
    ds_load_table();
    return w < gSkinNames.count ? gSkinNames[w].count : 0;
}

static NSString *ds_skin_name(NSUInteger w, NSUInteger i) {
    ds_load_table();
    return (w < gSkinNames.count && i < gSkinNames[w].count) ? gSkinNames[w][i] : @"";
}

static uint32_t ds_skin_id(NSUInteger w, NSUInteger i) {
    ds_load_table();
    return (w < gSkinIds.count && i < gSkinIds[w].count) ? gSkinIds[w][i].unsignedIntValue : 0;
}

// ------------------------------------------------------------------- globals
static uint64_t gGenObjects = 0;   // async, set on main thread
static BOOL     gReady = NO;
static NSString *gStatus = @"idle";
static int      gAceHits = 0;

typedef struct {
    uint64_t lo;
    uint64_t hi;
} DSRange;

#define DS_MAX_RANGES 8192
static DSRange gRanges[DS_MAX_RANGES];
static int     gRangeCount = 0;

static DSRange gHostData[8];
static int     gHostDataCount = 0;
static uint64_t gHostHeader = 0;
static int64_t  gHostSlide = 0;

// -------------------------------------------------------------- memory ranges
// Binary search over the VM map snapshot: called for every candidate pointer,
// so it must stay O(log n).
static BOOL ds_is_mapped(uint64_t addr, uint64_t len) {
    if (addr < 0x1000) return NO;
    uint64_t end = addr + len;
    if (end < addr) return NO;                 // overflow
    int lo = 0, hi = gRangeCount - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (addr < gRanges[mid].lo) { hi = mid - 1; }
        else if (addr >= gRanges[mid].hi) { lo = mid + 1; }
        else return end <= gRanges[mid].hi;
    }
    return NO;
}

static BOOL ds_readable_ptrs(uint64_t addr) { return ds_is_mapped(addr, sizeof(uint64_t)); }

// Substitutes the vm_region_recurse walk the original menu performs before every
// raw pointer dereference. Bounded, fail-closed.
static void ds_collect_ranges(void) {
    if (gRangeCount) return;

    vm_address_t address = 0;
    int guard = 0;
    while (guard++ < DS_MAX_RANGES) {
        vm_size_t size = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = vm_region_recurse_64(mach_task_self(), &address, &size, &depth,
                                                 (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS || size == 0) break;
        if (!info.is_submap && (info.protection & VM_PROT_READ)) {
            gRanges[gRangeCount].lo = address;
            gRanges[gRangeCount].hi = address + size;
            gRangeCount++;
        }
        address += size;
    }
    NSLog(@"[DeltaSkin] mapped ranges: %d", gRangeCount);
}

// --------------------------------------------------------------- host image
// Pulls the __DATA segments out of one dyld image and adopts it as the host.
static BOOL ds_host_from_image(uint32_t i) {
    const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
    if (!mh || mh->magic != MH_MAGIC_64) return NO;

    gHostHeader = (uint64_t)mh;
    gHostSlide = _dyld_get_image_vmaddr_slide(i);

    uint64_t p = (uint64_t)mh + sizeof(struct mach_header_64);
    for (uint32_t c = 0; c < mh->ncmds && gHostDataCount < 8; c++) {
        const struct load_command *lc = (const struct load_command *)p;
        if (lc->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
            if (strncmp(seg->segname, "__DATA", 6) == 0) {
                gHostData[gHostDataCount].lo = seg->vmaddr + gHostSlide;
                gHostData[gHostDataCount].hi = gHostData[gHostDataCount].lo + seg->vmsize;
                gHostDataCount++;
            }
        }
        if (lc->cmdsize < 8) break;   // corrupted table -> stop, no guesses
        p += lc->cmdsize;
    }
    return YES;
}

static void ds_locate_host(void) {
    if (gHostHeader) return;

    // Injected into the game: the host is the main executable, and the bundle id
    // is the stable way to say so. Image 0 is always the main executable.
    NSString *bid = [NSBundle mainBundle].bundleIdentifier;
    if ([bid isEqualToString:kHostBundle()] && ds_host_from_image(0)) {
        NSLog(@"[DeltaSkin] host=0x%llx data segs=%d (main exec, %@)",
              gHostHeader, gHostDataCount, bid);
        return;
    }

    // Otherwise (dylib loaded into some other process) fall back to the name.
    NSString *want = kHostImage();
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        const char *base = strrchr(nm, '/');
        base = base ? base + 1 : nm;
        if (strcmp(base, want.UTF8String) != 0) continue;
        if (!ds_host_from_image(i)) continue;
        break;
    }
    NSLog(@"[DeltaSkin] host=0x%llx data segs=%d", gHostHeader, gHostDataCount);
}

// -------------------------------------------------------------------- names
// UE5 FNameEntry: uint16 header (bit0 wide, bits1.. len), chars after.
static BOOL ds_name_entry(uint64_t entry, char *out, size_t cap) {
    if (!ds_is_mapped(entry, 2)) return NO;
    uint16_t hdr = *(uint16_t *)entry;
    int len = hdr >> 1;
    BOOL wide = (hdr & 1) != 0;
    if (len <= 0 || len >= 120) return NO;
    if (!ds_is_mapped(entry + 2, (uint64_t)len * (wide ? 2 : 1))) return NO;
    if (wide) {
        const uint16_t *w = (const uint16_t *)(entry + 2);
        for (int i = 0; i < len && (size_t)i + 1 < cap; i++) {
            uint16_t ch = w[i];
            if (ch < 0x20 || ch > 0x7E) return NO;
            out[i] = (char)ch;
        }
    } else {
        const char *s = (const char *)(entry + 2);
        for (int i = 0; i < len && (size_t)i + 1 < cap; i++) {
            if (s[i] < 0x20 || s[i] > 0x7E) return NO;
            out[i] = s[i];
        }
    }
    return YES;
}

static uint64_t gNameBlocks[4] = {0};

// Finds the FNamePool blocks array the same way the original does: scan the host
// __DATA range for the pointer whose entry decodes to "None".
static BOOL ds_find_gnames(void) {
    if (gNameBlocks[0]) return YES;
    if (!gHostHeader) return NO;

    for (int seg = 0; seg < gHostDataCount; seg++) {
        uint64_t lo = gHostData[seg].lo, hi = gHostData[seg].hi;
        if (!ds_is_mapped(lo, hi - lo)) continue;
        for (uint64_t p = lo; p + 8 <= hi; p += 8) {
            uint64_t v = *(uint64_t *)p;
            if ((v & 7) || !ds_is_mapped(v, 8 + 4)) continue;
            uint32_t hdr = *(uint32_t *)v;
            if (hdr != 0x6F4E0008) continue;  // header 8 ("None") + "No"
            if (*(uint16_t *)(v + 4) != 0x656E) continue;   // "ne"

            // Blocks[1..3] must be plausible name entries (the original checks 4).
            int good = 0;
            for (int i = 1; i < 4; i++) {
                uint64_t e = *(uint64_t *)(p + 8 * i);
                if (e == 0) { good++; continue; }
                if (!ds_is_mapped(e, 8)) continue;
                uint32_t h = *(uint32_t *)e;
                if ((h & 1) == 0 && (h >> 1) > 0 && (h >> 1) < 1024) good++;
            }
            if (good < 1) continue;

            for (int i = 0; i < 4; i++) gNameBlocks[i] = *(uint64_t *)(p + 8 * i);
            NSLog(@"[DeltaSkin] pool @0x%llx", p);
            return YES;
        }
    }
    return NO;
}

// --------------------------------------------------------------- pool dump
// This build transforms the character bytes inside the FName pool. The header
// of index 0 still reads as "4 chars, narrow", so the pool is right where it
// always was, but nothing after the header decodes to ASCII and every
// name-based lookup in this file fails on it. The vendor menu fails on this
// build too (device log: "crypted=1", "layout calibration failed ... score=0"),
// so there is no reference decoder to copy. One run on device writes the raw
// bytes to the log; the transform is then derived offline from entries whose
// plaintext is already known ("None", "Object", "Class", "Package", ...).

enum { DS_POOL_BLOCK = 0x10000 };

// Counts the consecutive entries a block yields when only the plaintext header
// is trusted. A real pool block walks hundreds of entries before it stops; a
// random pointer that happens to look like a header stops after one or two.
static int ds_block_score(uint64_t base) {
    if (!base || (base & 1)) return 0;
    int off = 0, n = 0;
    while (off < DS_POOL_BLOCK - 2 && ds_is_mapped(base + off, 2)) {
        uint16_t hdr = *(uint16_t *)(base + off);
        int len = hdr >> 1;
        if (len == 0 || len > 512) break;
        int step = 2 + ((hdr & 1) ? len * 2 : len);
        if (step & 1) step++;                   // entries stay 2-byte aligned
        if (off + step > DS_POOL_BLOCK) break;
        off += step;
        n++;
    }
    return n;
}

// Validates one candidate blocks-array address and installs it when the first
// block walks. Returns YES only on a real pool.
static BOOL ds_try_blocks(uint64_t arr) {
    if (!arr || (arr & 7) || !ds_is_mapped(arr, 32)) return NO;
    uint64_t b0 = *(uint64_t *)arr;
    if (!b0 || (b0 & 1) || !ds_is_mapped(b0, 8)) return NO;
    if (*(uint16_t *)b0 != 8) return NO;      // index 0 is "None": 4 narrow chars
    int s0 = ds_block_score(b0);
    if (s0 < 32) return NO;

    uint64_t blocks[4] = { b0, 0, 0, 0 };
    int scores[4] = { s0, 0, 0, 0 };
    for (int i = 1; i < 4; i++) {
        uint64_t e = *(uint64_t *)(arr + 8 * i);
        if (!e) break;
        scores[i] = ds_block_score(e);
        if (scores[i] < 8) break;
        blocks[i] = e;
    }
    memcpy(gNameBlocks, blocks, sizeof(blocks));
    NSLog(@"[DeltaSkin] pool(struct) arr=0x%llx scores=%d/%d/%d/%d",
          arr, scores[0], scores[1], scores[2], scores[3]);
    return YES;
}

// Same job as ds_find_gnames() but never looks at a character byte, so it still
// works when the characters are encrypted.
static BOOL ds_find_gnames_struct(void) {
    if (gNameBlocks[0]) return YES;
    if (!gHostHeader) return NO;

    // Pass A: the blocks array is a static global, so its address sits in the
    // host's own __DATA.
    for (int seg = 0; seg < gHostDataCount; seg++) {
        uint64_t lo = gHostData[seg].lo, hi = gHostData[seg].hi;
        if (!ds_is_mapped(lo, hi - lo)) continue;
        for (uint64_t p = lo; p + 8 <= hi; p += 8)
            if (ds_try_blocks(*(uint64_t *)p)) return YES;
    }

    // Pass B: on this build the pool hangs off a heap object (the vendor menu
    // reads it as GNames + 0xC8), so the static global is that object and the
    // array pointer lives inside it. Bounded: UE globals sit early in __DATA.
    int tried = 0;
    for (int seg = 0; seg < gHostDataCount; seg++) {
        uint64_t lo = gHostData[seg].lo, hi = gHostData[seg].hi;
        if (!ds_is_mapped(lo, hi - lo)) continue;
        for (uint64_t p = lo; p + 8 <= hi; p += 8) {
            uint64_t v = *(uint64_t *)p;
            if (!v || (v & 7) || !ds_is_mapped(v, 0x400)) continue;
            if (++tried > 32768) return NO;
            for (uint64_t off = 0; off < 0x400; off += 8)
                if (ds_try_blocks(*(uint64_t *)(v + off))) return YES;
        }
    }
    return NO;
}

// 64 bytes per line: short enough for any log channel to keep whole.
static void ds_dump_hex(uint64_t base, size_t len, const char *tag) {
    if (!base || !len) return;
    if (!ds_is_mapped(base, len)) {
        NSLog(@"[DeltaSkin] POOL %s @0x%llx unmapped", tag, base);
        return;
    }
    const uint8_t *p = (const uint8_t *)base;
    for (size_t off = 0; off < len; off += 64) {
        size_t n = (len - off < 64) ? (len - off) : 64;
        NSMutableString *line = [NSMutableString stringWithCapacity:160];
        for (size_t i = 0; i < n; i++) [line appendFormat:@"%02x", p[off + i]];
        NSLog(@"[DeltaSkin] POOL %s +%04lx %@", tag, (unsigned long)off, line);
    }
}

// Block 0 index 0..~600 is the engine core vocabulary, which is exactly the set
// of names whose plaintext is known, so 2KB there is enough to solve the
// transform. The other blocks get a taste so an index-dependent cipher (rather
// than a per-character one) shows up immediately.
static void ds_dump_pool(void) {
    ds_dump_hex(gNameBlocks[0], 0x800, "b0");
    for (int i = 1; i < 4; i++) ds_dump_hex(gNameBlocks[i], 0x200, i == 1 ? "b1" : (i == 2 ? "b2" : "b3"));
}

// FName (int32 index, int32 number) -> text
static BOOL ds_fname_text(uint64_t pooledIndex, char *out, size_t cap) {
    if (!gNameBlocks[0]) return NO;
    uint32_t index = (uint32_t)pooledIndex;
    uint32_t block = index >> 16;
    uint32_t off = index & 0xFFFF;
    if (block >= 4 || !gNameBlocks[block]) return NO;
    return ds_name_entry(gNameBlocks[block] + 2ull * off, out, cap);
}

// ------------------------------------------------------------------ objects
// UObject: ClassPrivate @0x10, NamePrivate @0x18.
static uint64_t ds_obj_class(uint64_t o) { return ds_is_mapped(o + 0x10, 8) ? *(uint64_t *)(o + 0x10) : 0; }
static uint64_t ds_obj_outer(uint64_t o) { return ds_is_mapped(o + 0x20, 8) ? *(uint64_t *)(o + 0x20) : 0; }
static uint64_t ds_obj_fname(uint64_t o) { return ds_is_mapped(o + 0x18, 8) ? *(uint64_t *)(o + 0x18) : 0; }

static BOOL ds_obj_name(uint64_t o, char *out, size_t cap) {
    uint64_t fname = ds_obj_fname(o);
    if (!fname) return NO;
    return ds_fname_text(fname, out, cap);
}

// GObjects: array of 65536-entry chunks, FUObjectItem = 24 bytes, item[0]=UObject*.
static int gChunkBits = 16;
static int gItemStride = 24;

static uint64_t ds_object_at(uint64_t arrayPtr, uint32_t index) {
    uint32_t chunk = index >> gChunkBits;
    uint32_t slot = index & ((1u << gChunkBits) - 1);
    uint64_t slotAddr = arrayPtr + 8ull * chunk;
    if (!ds_readable_ptrs(slotAddr)) return 0;
    uint64_t base = *(uint64_t *)slotAddr;
    if (!base || (base & 7)) return 0;
    uint64_t item = base + (uint64_t)gItemStride * slot;
    if (!ds_is_mapped(item, 8)) return 0;
    uint64_t obj = *(uint64_t *)item;
    if (!obj || (obj & 7)) return 0;
    return obj;
}

static BOOL ds_find_gobjects(void) {
    if (gGenObjects) return YES;
    uint64_t candidates[64];
    int cand = 0;

    for (int seg = 0; seg < gHostDataCount; seg++) {
        uint64_t lo = gHostData[seg].lo, hi = gHostData[seg].hi;
        for (uint64_t p = lo; p + 8 <= hi && cand < 64; p += 8) {
            uint64_t arr = *(uint64_t *)p;
            if ((arr & 7) || !ds_is_mapped(arr, 8 * 4)) continue;
            uint64_t chunk0 = *(uint64_t *)arr;
            if (!chunk0 || (chunk0 & 7) || !ds_is_mapped(chunk0, 24 * 8)) continue;
            uint64_t obj0 = *(uint64_t *)chunk0;
            if (!obj0 || (obj0 & 7)) continue;
            uint64_t cls = ds_obj_class(obj0);
            if (!cls || !ds_is_mapped(cls, 0x40)) continue;
            char nm[128] = {0};
            if (!ds_obj_name(obj0, nm, sizeof(nm))) continue;
            if (strlen(nm) < 3) continue;
            candidates[cand++] = arr;
        }
    }
    if (!cand) return NO;

    // Validate by walking a spread of indices; the first candidate that resolves
    // many valid objects is the real array.
    uint64_t best = 0;
    int bestHits = 0;
    for (int i = 0; i < cand; i++) {
        int hits = 0;
        for (uint32_t idx = 0; idx < 4096; idx += 7) {
            uint64_t o = ds_object_at(candidates[i], idx);
            if (!o) continue;
            char nm[128] = {0};
            if (ds_obj_name(o, nm, sizeof(nm)) && strlen(nm) >= 2) hits++;
        }
        if (hits > bestHits) { bestHits = hits; best = candidates[i]; }
    }
    if (bestHits < 50) return NO;
    gGenObjects = best;
    NSLog(@"[DeltaSkin] objects @0x%llx hits=%d", best, bestHits);
    return YES;
}

// ------------------------------------------------------------------ scanning
// Objects are laid out in class-grouped runs, so the FName decode is done only
// when the class pointer changes. Without that cache this scan is minutes.
typedef void (^DSObjectBlock)(uint64_t obj);

static int   gMaxChunks  = 512;
static BOOL  ds_scan_objects(DSObjectBlock block) {
    uint64_t arr = gGenObjects;
    if (!arr || !block) return NO;

    uint64_t cachedClass = 0;
    char     cachedName[128] = {0};
    BOOL     cachedOk = NO;
    int      liveChunks = 0;

    for (int chunk = 0; chunk < gMaxChunks; chunk++) {
        uint64_t slotAddr = arr + 8ull * chunk;
        if (!ds_readable_ptrs(slotAddr)) break;
        uint64_t base = *(uint64_t *)slotAddr;
        if (!base || (base & 7) || !ds_is_mapped(base, 24)) break;   // end of chunks
        liveChunks++;

        for (uint32_t slot = 0; slot < (1u << gChunkBits); slot++) {
            uint64_t item = base + (uint64_t)gItemStride * slot;
            if (!ds_is_mapped(item, 8)) break;
            uint64_t obj = *(uint64_t *)item;
            if (!obj || (obj & 7) || !ds_is_mapped(obj, 0x40)) continue;

            uint64_t cls = ds_obj_class(obj);
            if (cls != cachedClass) {
                cachedClass = cls;
                cachedOk = cls && ds_obj_name(cls, cachedName, sizeof(cachedName));
                if (!cachedOk) cachedName[0] = 0;
            }
            if (!cachedOk) continue;
            block(obj);
        }
    }
    NSLog(@"[DeltaSkin] scanned %d chunks", liveChunks);
    return liveChunks > 0;
}

// Returns the class name of `obj`; used only for the sparse reporting paths.
static BOOL ds_class_name_of(uint64_t obj, char *out, size_t cap) {
    uint64_t cls = ds_obj_class(obj);
    if (!cls) return NO;
    return ds_obj_name(cls, out, cap);
}

static uint64_t ds_find_class(NSArray<NSString *> *names) {
    __block uint64_t found = 0;
    ds_scan_objects(^(uint64_t obj) {
        if (found) return;
        char cname[128] = {0};
        if (!ds_class_name_of(obj, cname, sizeof(cname))) return;
        for (NSString *want in names) {
            if (strcmp(cname, want.UTF8String) == 0) {
                // `obj` is an instance; its ClassPrivate is the UClass we need.
                found = ds_obj_class(obj);
                return;
            }
        }
    });
    return found;
}

// Native entry of a UFunction: the first pointer into the host __TEXT window.
static void *ds_func_entry(uint64_t ufunc) {
    for (uint32_t off = 0x80; off < 0x180; off += 8) {
        if (!ds_is_mapped(ufunc + off, 8)) continue;
        uint64_t v = *(uint64_t *)(ufunc + off);
        if (!v) continue;
        if (v >= gHostHeader && v < gHostHeader + 0x40000000ull) return (void *)v;
    }
    return NULL;
}

// ------------------------------------------------------------------ the mod
// Param block: UE writes the first int in the frame for a skin id arg.
typedef void (*DSNativeInvoke)(void *self, void *params);

// Ranked so the most specific setter wins in a single pass. SetSkinApperanceId
// takes the bare appearance id, which is exactly the one int pushed into the
// param block; everything below it takes a struct or does extra work, so those
// are only used when the id-only setter is missing on that class.
static int ds_setter_rank(const char *name) {
    if (strcmp(name, kFnSetSkinAppearance().UTF8String) == 0) return 5;
    if (strcmp(name, kFnSetSkinInfo().UTF8String) == 0) return 4;
    if (strcmp(name, kFnSetSkin().UTF8String) == 0) return 3;
    if (strcmp(name, kFnApplySkin().UTF8String) == 0) return 2;
    if (strcmp(name, kFnSetSkinBS().UTF8String) == 0) return 1;
    if (strcmp(name, kFnSetSkinES().UTF8String) == 0) return 1;
    return 0;
}

// Finds the best setter UFunction owned by `cls` and its native entry.
static uint64_t ds_resolve_setter(uint64_t cls, void **entryOut) {
    if (entryOut) *entryOut = NULL;
    if (!cls) return 0;
    __block uint64_t best = 0;
    __block int bestRank = 0;
    ds_scan_objects(^(uint64_t obj) {
        if (ds_obj_outer(obj) != cls) return;
        char nm[128] = {0};
        if (!ds_obj_name(obj, nm, sizeof(nm))) return;
        int r = ds_setter_rank(nm);
        if (r > bestRank) { bestRank = r; best = obj; }
    });
    if (best && entryOut) *entryOut = ds_func_entry(best);
    return best;
}

static long ds_apply_skin(uint64_t target, void *entry, int skinId) {
    if (!target || !entry || !ds_is_mapped(target, 0x40)) return -1;
    uint8_t params[64] = {0};
    memcpy(params, &skinId, sizeof(int));
    ((DSNativeInvoke)entry)((void *)target, params);
    return 1;
}

static NSArray<NSString *> *ds_weapon_classes(void) {
    return @[ kClassWeaponDesc(), kClassGPWeaponDesc() ];
}

static int ds_apply_all(int skinId) {
    if (!gReady) return 0;

    // Resolve each weapon class once, then apply everything that shares it.
    NSMutableArray<NSNumber *> *classes = [NSMutableArray array];
    NSMutableArray<NSValue *> *entries = [NSMutableArray array];
    for (NSString *nm in ds_weapon_classes()) {
        uint64_t cls = ds_find_class(@[ nm ]);
        if (!cls) continue;
        void *entry = NULL;
        if (!ds_resolve_setter(cls, &entry) || !entry) continue;
        [classes addObject:@(cls)];
        [entries addObject:[NSValue valueWithPointer:entry]];
    }
    if (!classes.count) return -4;

    __block int applied = 0;
    __block int seen = 0;
    ds_scan_objects(^(uint64_t obj) {
        uint64_t cls = ds_obj_class(obj);
        for (NSUInteger i = 0; i < classes.count; i++) {
            if (classes[i].unsignedLongLongValue != cls) continue;
            seen++;
            void *entry = (void *)entries[i].pointerValue;
            if (ds_apply_skin(obj, entry, skinId) > 0) applied++;
            return;
        }
    });
    NSLog(@"[DeltaSkin] apply %d: seen=%d applied=%d", skinId, seen, applied);
    return applied;
}

static void ds_bootstrap(void) {
    gStatus = @"scanning";
    ds_collect_ranges();
    ds_locate_host();
    if (!ds_find_gnames()) {
        // Names are encrypted on this build: find the pool by structure and
        // log the raw bytes so the decoder can be derived offline.
        if (ds_find_gnames_struct()) {
            ds_dump_pool();
            gStatus = @"pool encrypted - dump logged";
        } else {
            gStatus = @"pool not found";
        }
        return;
    }
    if (!ds_find_gobjects()) { gStatus = @"objects not found"; return; }
    gReady = YES;
    gStatus = @"ready";
    NSLog(@"[DeltaSkin] ready");
}

// ------------------------------------------------------------------- the UI
// Floating button plus a menu in its own UIWindow, as in the working no-jailbreak
// build (D:\delta\PxExtNoJB, PxMenuView.m). Three properties matter more than
// the looks:
//
//   1. the button is a 52x52 view added to the game window. It is never a
//      full-screen transparent container -- that is exactly what made an earlier
//      revision swallow every touch after the panel was hidden: a clear view
//      with userInteractionEnabled = YES still wins hit-testing over everything
//      underneath, hidden subviews notwithstanding.
//   2. the menu window is hidden, detached from its scene and released on close.
//      A hidden-but-still-attached window stays in the window list, takes key
//      status back, and the game stops receiving touches.
//   3. the picker is two side-by-side lists (weapon -> that weapon's skins),
//      laid out by Auto Layout against the live window bounds. The earlier
//      build used two action-sheet combos over fixed frames computed once from
//      UIScreen.bounds, which is why the panel sat in the wrong place in
//      landscape and why the id in the text field could disagree with the cell
//      that was just tapped.

static void ds_toast(NSString *message);

@interface DSMenu : NSObject <UITableViewDataSource, UITableViewDelegate>
@property (nonatomic, strong) UIButton *fab;
@property (nonatomic, strong) UIWindow *window;
@property (nonatomic, strong) UIView *panel;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) UILabel *idLabel;
@property (nonatomic, strong) UITableView *weaponTable;
@property (nonatomic, strong) UITableView *skinTable;
@property (nonatomic, assign) NSInteger weaponIdx;
@property (nonatomic, assign) NSInteger skinIdx;
@property (nonatomic, assign) BOOL dragging;
@end

@implementation DSMenu

+ (instancetype)shared {
    static DSMenu *m;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ m = [DSMenu new]; });
    return m;
}

// Lowest-level visible window that is not ours. Asking for "the key window"
// after the menu closed can return the menu window itself and keep key input
// away from the game, which is the second half of the "screen is dead" bug.
static UIWindow *ds_host_window(void) {
    UIWindow *best = nil;
    for (UIWindow *w in UIApplication.sharedApplication.windows) {
        if (w.hidden) continue;
        if (w.windowLevel >= UIWindowLevelAlert) continue;
        if (!best || w.windowLevel < best.windowLevel) best = w;
    }
    return best;
}

// The game runs in landscape, and UIScreen.mainScreen.bounds can still describe
// the device in its physical (portrait) orientation when a window is created
// outside the scene's rotation callback. A panel laid out from that is half off
// screen and every cell sits somewhere other than where the finger lands.
static CGRect ds_screen_bounds(void) {
    UIWindow *host = ds_host_window();
    if (host && host.bounds.size.width > 1 && host.bounds.size.height > 1) return host.bounds;
    return UIScreen.mainScreen.bounds;
}

// ------------------------------------------------------------ floating button
static BOOL gFabInstalled = NO;

- (void)install {
    if (gFabInstalled || self.fab) return;
    UIWindow *host = ds_host_window();
    if (!host) {
        // The game builds its window after the skin engine is ready; retry for
        // a few seconds instead of giving up on the first miss.
        static int tries = 0;
        if (tries++ < 40) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{ [self install]; });
        }
        return;
    }

    CGFloat side = 52.0;
    CGRect b = host.bounds;
    UIButton *fab = [UIButton buttonWithType:UIButtonTypeCustom];
    fab.frame = CGRectMake(b.size.width - side - 12.0, b.size.height * 0.35, side, side);
    fab.backgroundColor = [UIColor colorWithRed:0.06 green:0.07 blue:0.09 alpha:0.92];
    fab.layer.cornerRadius = side / 2.0;
    fab.layer.borderWidth = 1;
    fab.layer.borderColor = [UIColor colorWithRed:0.20 green:0.85 blue:0.52 alpha:0.85].CGColor;
    fab.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightBold];
    [fab setTitle:@"DS" forState:UIControlStateNormal];
    [fab setTitleColor:[UIColor colorWithRed:0.35 green:0.95 blue:0.60 alpha:1]
              forState:UIControlStateNormal];
    [fab addTarget:self action:@selector(fabTapped) forControlEvents:UIControlEventTouchUpInside];
    UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:self
                                                                         action:@selector(fabPan:)];
    [fab addGestureRecognizer:pan];
    [host addSubview:fab];
    self.fab = fab;
    gFabInstalled = YES;
}

- (void)fabTapped {
    // A drag ends with the pan already back in Ended/Failed, so the flag is the
    // only reliable signal that this touch was a drag and not a tap.
    if (self.dragging) { self.dragging = NO; return; }
    [self toggle];
}

- (void)fabPan:(UIPanGestureRecognizer *)pan {
    UIView *host = self.fab.superview;
    CGPoint t = [pan translationInView:host];
    [pan setTranslation:CGPointZero inView:host];

    CGRect bounds = host.bounds;
    CGFloat half = self.fab.bounds.size.width / 2.0;
    CGPoint c = CGPointMake(self.fab.center.x + t.x, self.fab.center.y + t.y);
    c.x = MAX(half + 4.0, MIN(bounds.size.width - half - 4.0, c.x));
    c.y = MAX(half + 4.0, MIN(bounds.size.height - half - 4.0, c.y));

    if (pan.state == UIGestureRecognizerStateBegan) {
        self.dragging = YES;
        self.fab.transform = CGAffineTransformMakeScale(1.08, 1.08);
    } else if (pan.state == UIGestureRecognizerStateEnded ||
               pan.state == UIGestureRecognizerStateCancelled) {
        self.fab.transform = CGAffineTransformIdentity;
    }
    self.fab.center = c;
}

// ----------------------------------------------------------------- show / hide
- (void)toggle {
    if (self.window) [self hide];
    else [self show];
}

- (void)show {
    if (self.window) return;

    UIWindow *w = [[UIWindow alloc] initWithFrame:ds_screen_bounds()];
    w.windowLevel = UIWindowLevelAlert + 60;
    w.backgroundColor = UIColor.clearColor;
    w.rootViewController = [UIViewController new];
    w.rootViewController.view.backgroundColor = UIColor.clearColor;
    // A window with no scene never attaches on iOS 13+, so it would be built,
    // hidden = NO, and invisible.
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in UIApplication.sharedApplication.connectedScenes) {
            if ([s isKindOfClass:UIWindowScene.class]) { w.windowScene = (UIWindowScene *)s; break; }
        }
    }
    self.window = w;

    UIView *root = w.rootViewController.view;
    // From the window, not root.bounds: the root view has not been sized yet at
    // this point, and a zero there collapses every constraint below.
    const CGFloat rw = w.bounds.size.width, rh = w.bounds.size.height;
    const CGFloat W = rw > 48.0 ? MIN(rw - 24.0, 720.0) : rw;
    const CGFloat H = rh > 48.0 ? MIN(rh - 24.0, 620.0) : rh;
    UIView *dim = [[UIView alloc] initWithFrame:root.bounds];
    dim.backgroundColor = [UIColor colorWithWhite:0 alpha:0.35];
    dim.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [dim addGestureRecognizer:[[UITapGestureRecognizer alloc] initWithTarget:self
                                                                     action:@selector(hide)]];
    [root addSubview:dim];

    // Rebuilt on every open, against the live window bounds. The panel used to be
    // built once and cached, so a stale size from the first open (or from before
    // the game finished rotating to landscape) put every cell where the finger
    // was not.
    self.panel = nil;
    [self buildPanel];
    [root addSubview:self.panel];

    [NSLayoutConstraint activateConstraints:@[
        [self.panel.centerXAnchor constraintEqualToAnchor:root.centerXAnchor],
        [self.panel.centerYAnchor constraintEqualToAnchor:root.centerYAnchor],
        [self.panel.widthAnchor constraintEqualToConstant:W],
        [self.panel.heightAnchor constraintEqualToConstant:H],
        [self.panel.widthAnchor constraintLessThanOrEqualToAnchor:root.widthAnchor constant:-16.0],
        [self.panel.heightAnchor constraintLessThanOrEqualToAnchor:root.heightAnchor constant:-16.0],
    ]];

    w.hidden = NO;
    [w makeKeyWindow];     // the tables need a key window for their first layout
    [self refresh];
}

- (void)hide {
    UIWindow *w = self.window;
    self.window = nil;
    if (!w) return;

    [self.panel removeFromSuperview];     // keep the panel, drop the window

    w.rootViewController.view.userInteractionEnabled = NO;
    w.hidden = YES;
    if (@available(iOS 13.0, *)) w.windowScene = nil;   // not just hidden: detached

    UIWindow *target = ds_host_window();
    if (target) [target makeKeyWindow];
}

- (void)setStatusText:(NSString *)s {
    dispatch_async(dispatch_get_main_queue(), ^{
        gStatus = s;
        self.status.text = s;
    });
}

// ------------------------------------------------------------------- the panel
static UILabel *ds_label(NSString *text, CGFloat size, UIColor *color) {
    UILabel *l = [UILabel new];
    l.text = text;
    l.font = [UIFont systemFontOfSize:size weight:UIFontWeightSemibold];
    l.textColor = color;
    return l;
}

static UIButton *ds_row_button(NSString *title, id target, SEL action) {
    UIButton *b = [UIButton buttonWithType:UIButtonTypeCustom];
    b.backgroundColor = [UIColor colorWithWhite:1 alpha:0.06];
    b.layer.cornerRadius = 8;
    b.titleLabel.font = [UIFont systemFontOfSize:12];
    b.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeft;
    b.titleEdgeInsets = UIEdgeInsetsMake(0, 10, 0, 10);
    b.titleLabel.lineBreakMode = NSLineBreakByTruncatingTail;
    [b setTitle:title forState:UIControlStateNormal];
    [b setTitleColor:[UIColor colorWithWhite:0.87 alpha:1] forState:UIControlStateNormal];
    [b addTarget:target action:action forControlEvents:UIControlEventTouchUpInside];
    return b;
}

- (UITableView *)tableWithPlaceholder:(NSString *)placeholder {
    UITableView *t = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStylePlain];
    t.translatesAutoresizingMaskIntoConstraints = NO;
    t.backgroundColor = [UIColor colorWithWhite:1 alpha:0.04];
    t.layer.cornerRadius = 10;
    t.layer.masksToBounds = YES;
    t.separatorStyle = UITableViewCellSeparatorStyleNone;
    t.rowHeight = UITableViewAutomaticDimension;
    t.estimatedRowHeight = 42;
    t.dataSource = self;
    t.delegate = self;
    t.tintColor = [UIColor colorWithRed:0.20 green:0.80 blue:0.50 alpha:1];
    [t registerClass:[UITableViewCell class] forCellReuseIdentifier:@"dsrow"];
    (void)placeholder;
    return t;
}

- (void)buildPanel {
    if (self.panel) return;

    UIView *panel = [UIView new];
    panel.translatesAutoresizingMaskIntoConstraints = NO;
    panel.backgroundColor = [UIColor colorWithRed:0.055 green:0.058 blue:0.070 alpha:0.98];
    panel.layer.cornerRadius = 16;
    panel.layer.borderWidth = 1;
    panel.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.08].CGColor;
    self.panel = panel;

    UILabel *title = ds_label(@"SKIN MOD", 15, [UIColor colorWithWhite:0.95 alpha:1]);
    title.translatesAutoresizingMaskIntoConstraints = NO;
    [panel addSubview:title];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.translatesAutoresizingMaskIntoConstraints = NO;
    [close setTitle:@"\u2715" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor colorWithWhite:0.55 alpha:1] forState:UIControlStateNormal];
    [close.titleLabel setFont:[UIFont systemFontOfSize:17]];
    [close addTarget:self action:@selector(hide) forControlEvents:UIControlEventTouchUpInside];
    [panel addSubview:close];

    self.status = ds_label(gStatus, 10, [UIColor colorWithWhite:0.42 alpha:1]);
    self.status.translatesAutoresizingMaskIntoConstraints = NO;
    self.status.lineBreakMode = NSLineBreakByTruncatingTail;
    [panel addSubview:self.status];

    // Two panes, like the vendor menu: every weapon on the left, and only that
    // weapon's skins on the right. The previous build used two action-sheet
    // combos, which hid the mapping -- you could not see which weapon a skin
    // belonged to, and nothing on screen proved the grouping was right.
    self.weaponTable = [self tableWithPlaceholder:@"Weapon"];
    self.skinTable = [self tableWithPlaceholder:@"Skin"];
    [panel addSubview:self.weaponTable];
    [panel addSubview:self.skinTable];

    UIButton *apply = ds_row_button(@"Apply Skin", self, @selector(applyTapped));
    apply.translatesAutoresizingMaskIntoConstraints = NO;
    apply.contentHorizontalAlignment = UIControlContentHorizontalAlignmentCenter;
    apply.backgroundColor = [UIColor colorWithRed:0.20 green:0.80 blue:0.50 alpha:0.95];
    [apply setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    apply.titleLabel.font = [UIFont systemFontOfSize:13 weight:UIFontWeightSemibold];
    [panel addSubview:apply];

    UIButton *restore = ds_row_button(@"Default", self, @selector(restoreTapped));
    restore.translatesAutoresizingMaskIntoConstraints = NO;
    restore.contentHorizontalAlignment = UIControlContentHorizontalAlignmentCenter;
    [panel addSubview:restore];

    self.idLabel = ds_label(@"0x00000000", 11, [UIColor colorWithWhite:0.55 alpha:1]);
    self.idLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.idLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightMedium];
    [panel addSubview:self.idLabel];

    UIButton *runtime = [UIButton buttonWithType:UIButtonTypeSystem];
    runtime.translatesAutoresizingMaskIntoConstraints = NO;
    [runtime setTitle:@"runtime" forState:UIControlStateNormal];
    [runtime.titleLabel setFont:[UIFont systemFontOfSize:10]];
    [runtime setTitleColor:[UIColor colorWithWhite:0.40 alpha:1] forState:UIControlStateNormal];
    [runtime addTarget:self action:@selector(statusTapped) forControlEvents:UIControlEventTouchUpInside];
    [panel addSubview:runtime];

    // The ID is read-only: the old build let a stale typed value win over the
    // picked cell, so choosing a different skin in the list applied the previous
    // one. There is no way to pick a skin and get a different id now.
    [NSLayoutConstraint activateConstraints:@[
        [title.topAnchor constraintEqualToAnchor:panel.topAnchor constant:12.0],
        [title.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:16.0],

        [close.topAnchor constraintEqualToAnchor:panel.topAnchor constant:4.0],
        [close.trailingAnchor constraintEqualToAnchor:panel.trailingAnchor constant:-8.0],
        [close.widthAnchor constraintEqualToConstant:40.0],
        [close.heightAnchor constraintEqualToConstant:40.0],

        [self.status.topAnchor constraintEqualToAnchor:title.bottomAnchor constant:2.0],
        [self.status.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:16.0],
        [self.status.trailingAnchor constraintEqualToAnchor:close.leadingAnchor constant:-4.0],

        [self.weaponTable.topAnchor constraintEqualToAnchor:self.status.bottomAnchor constant:10.0],
        [self.weaponTable.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:16.0],
        [self.weaponTable.bottomAnchor constraintEqualToAnchor:apply.topAnchor constant:-10.0],
        [self.weaponTable.widthAnchor constraintEqualToAnchor:panel.widthAnchor multiplier:0.40],

        [self.skinTable.topAnchor constraintEqualToAnchor:self.weaponTable.topAnchor],
        [self.skinTable.leadingAnchor constraintEqualToAnchor:self.weaponTable.trailingAnchor constant:8.0],
        [self.skinTable.trailingAnchor constraintEqualToAnchor:panel.trailingAnchor constant:-16.0],
        [self.skinTable.bottomAnchor constraintEqualToAnchor:self.weaponTable.bottomAnchor],

        [apply.trailingAnchor constraintEqualToAnchor:panel.trailingAnchor constant:-16.0],
        [apply.bottomAnchor constraintEqualToAnchor:panel.bottomAnchor constant:-12.0],
        [apply.heightAnchor constraintEqualToConstant:38.0],
        [apply.widthAnchor constraintEqualToConstant:136.0],

        [restore.trailingAnchor constraintEqualToAnchor:apply.leadingAnchor constant:-8.0],
        [restore.centerYAnchor constraintEqualToAnchor:apply.centerYAnchor],
        [restore.heightAnchor constraintEqualToConstant:38.0],
        [restore.widthAnchor constraintEqualToConstant:96.0],

        [runtime.leadingAnchor constraintEqualToAnchor:panel.leadingAnchor constant:16.0],
        [runtime.centerYAnchor constraintEqualToAnchor:apply.centerYAnchor],

        [self.idLabel.leadingAnchor constraintEqualToAnchor:runtime.trailingAnchor constant:8.0],
        [self.idLabel.centerYAnchor constraintEqualToAnchor:apply.centerYAnchor],
        [self.idLabel.trailingAnchor constraintLessThanOrEqualToAnchor:restore.leadingAnchor constant:-8.0],
    ]];
}

// ------------------------------------------------------------------ selection
- (void)refresh {
    if (!self.panel) return;

    if (self.weaponIdx < 0 || self.weaponIdx >= (NSInteger)ds_weapon_count()) self.weaponIdx = 0;
    NSInteger n = (NSInteger)ds_skin_count((NSUInteger)self.weaponIdx);
    if (self.skinIdx < 0 || self.skinIdx >= n) self.skinIdx = 0;

    self.status.text = gStatus;
    self.idLabel.text = [NSString stringWithFormat:@"0x%08X",
                         ds_skin_id((NSUInteger)self.weaponIdx, (NSUInteger)self.skinIdx)];

    [self.weaponTable reloadData];
    [self.skinTable reloadData];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)section {
    if (tv == self.weaponTable) return (NSInteger)ds_weapon_count();
    return (NSInteger)ds_skin_count((NSUInteger)self.weaponIdx);
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:@"dsrow"];
    c.backgroundColor = UIColor.clearColor;

    UIView *bg = [UIView new];
    bg.backgroundColor = [UIColor colorWithRed:0.20 green:0.80 blue:0.50 alpha:0.20];
    c.selectedBackgroundView = bg;

    c.textLabel.numberOfLines = 2;
    c.textLabel.lineBreakMode = NSLineBreakByTruncatingTail;

    if (tv == self.weaponTable) {
        BOOL picked = (ip.row == self.weaponIdx);
        c.textLabel.text = ds_weapon_name((NSUInteger)ip.row);
        c.textLabel.textColor = picked ? [UIColor colorWithRed:0.40 green:0.95 blue:0.65 alpha:1]
                                       : [UIColor colorWithWhite:0.82 alpha:1];
        c.textLabel.font = [UIFont systemFontOfSize:12 weight:picked ? UIFontWeightSemibold
                                                                    : UIFontWeightRegular];
    } else {
        c.textLabel.text = ds_skin_name((NSUInteger)self.weaponIdx, (NSUInteger)ip.row);
        c.textLabel.textColor = [UIColor colorWithWhite:0.90 alpha:1];
        c.textLabel.font = [UIFont systemFontOfSize:12 weight:UIFontWeightRegular];
    }
    return c;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:NO];

    if (tv == self.weaponTable) {
        if (ip.row == self.weaponIdx) return;
        self.weaponIdx = ip.row;
        self.skinIdx = 0;
        [self.skinTable setContentOffset:CGPointZero animated:NO];
    } else {
        self.skinIdx = ip.row;
    }
    [self refresh];
}

// -------------------------------------------------------------------- actions
- (void)applyTapped {
    uint32_t sid = ds_skin_id((NSUInteger)self.weaponIdx, (NSUInteger)self.skinIdx);
    if (sid == 0) {
        ds_toast(@"Pick a weapon, then a skin.");
        return;
    }

    [self setStatusText:@"applying..."];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        if (!gReady) ds_bootstrap();
        if (!gReady) { [self setStatusText:gStatus]; return; }
        int n = ds_apply_all((int)sid);
        NSString *msg = n > 0
            ? [NSString stringWithFormat:@"Skin 0x%X applied to %d object(s).", sid, n]
            : [NSString stringWithFormat:@"Nothing applied (code %d). Hold the gun in a match.", n];
        [self setStatusText:msg];
        ds_toast(msg);
    });
}

- (void)restoreTapped {
    [self setStatusText:@"restoring..."];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        if (!gReady) ds_bootstrap();
        if (!gReady) { [self setStatusText:gStatus]; return; }
        int n = ds_apply_all(0);
        NSString *msg = n > 0 ? @"Default weapon appearance restored."
                              : @"Nothing to restore yet (hold the weapon in a match).";
        [self setStatusText:msg];
        ds_toast(msg);
    });
}

- (void)statusTapped {
    ds_toast([NSString stringWithFormat:@"%@\n%lu weapons / %d skins / ace %d/7",
              gStatus, (unsigned long)ds_weapon_count(), DS_SKIN_ROW_COUNT, gAceHits]);
}

@end

static void ds_toast(NSString *message) {
    if (message.length == 0) return;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *host = nil;
        UIWindow *menu = [DSMenu shared].window;
        if (menu && !menu.hidden) host = menu.rootViewController;
        if (!host) {
            for (UIWindow *w in UIApplication.sharedApplication.windows) {
                if (w.isKeyWindow) { host = w.rootViewController; break; }
            }
        }
        while (host.presentedViewController) host = host.presentedViewController;
        if (!host) return;

        UIAlertController *alert =
            [UIAlertController alertControllerWithTitle:@"DeltaSkin"
                                                message:message
                                         preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                  style:UIAlertActionStyleDefault
                                                handler:nil]];
        [host presentViewController:alert animated:YES completion:nil];
    });
}

// ----------------------------------------------------------------- antiban
// Kept deliberately narrow: we never touch anogs/ACE code, never list our own
// module in a suspicious way, never create files outside NSUserDefaults, and we
// abort silently if a debugger/frida is present (that combination is what gets
// accounts flagged, not the object reads themselves).
static BOOL ds_hostile_environment(void) {
    if (getenv("FRIDA_AGENT_PATH")) return YES;
    if (dlopen("/usr/lib/frida/frida-agent.dylib", RTLD_LAZY)) return YES;
    int traced = 0;
    size_t sz = sizeof(traced);
    if (sysctlbyname("sysctl.proc_traced", &traced, &sz, NULL, 0) != 0) return NO;
    return traced != 0;
}

// ---------------------------------------------------- ACE (anogs) neutralise
// Nothing on the device bans anybody. anogs (Tencent ACE) collects evidence,
// the host app pulls that blob with AnoSDKGetReportData*() and uploads it, and
// ACE's server applies the ban. Those getters have no caller inside anogs, so
// rewriting their prologue erases the evidence without disturbing a detector
// (ACE re-checksums its own code, so we touch as few bytes as possible).
//
// mov w0,#0 ; ret - zero-extending, so it satisfies any int/pointer return.
// No pointer authentication involved, unlike redirecting the host's GOT slots.

static BOOL ds_prot_set(void *addr, size_t len, vm_prot_t prot) {
    uintptr_t a = (uintptr_t)addr;
    uintptr_t page = a & ~(uintptr_t)(vm_page_size - 1);
    uintptr_t end = (a + len + vm_page_size - 1) & ~(uintptr_t)(vm_page_size - 1);
    return vm_protect(mach_task_self(), (vm_address_t)page, (vm_size_t)(end - page),
                      FALSE, prot) == KERN_SUCCESS;
}

static BOOL ds_patch_ret0(void *fn) {
    if (!fn) return NO;
    uint32_t code[2] = { 0x52800000u, 0xD65F03C0u };
    if (!ds_prot_set(fn, sizeof(code), VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY)) return NO;
    memcpy(fn, code, sizeof(code));
    sys_icache_invalidate(fn, sizeof(code));
    ds_prot_set(fn, sizeof(code), VM_PROT_READ | VM_PROT_EXECUTE);
    return YES;
}

static void *ds_ace_sym(const char *name) {
    void *p = dlsym(RTLD_DEFAULT, name);
    if (p) return p;
    static void *ano = NULL;
    if (!ano) {
        NSString *path = [[[NSBundle mainBundle] privateFrameworksPath]
                          stringByAppendingPathComponent:@"anogs.framework/anogs"];
        ano = dlopen(path.UTF8String, RTLD_LAZY | RTLD_NOLOAD);
        if (!ano) ano = dlopen(path.UTF8String, RTLD_LAZY);
    }
    return ano ? dlsym(ano, name) : NULL;
}

// The four report getters + the three "drop it" calls. Killing both halves
// means the host never receives a report and never acknowledges one.
static int ds_install_ace(void) {
    NSArray<NSString *> *names = @[
        kAce0(), kAce1(), kAce2(), kAce3(), kAce4(), kAce5(), kAce6(),
    ];
    int ok = 0;
    for (NSString *n in names) {
        void *p = ds_ace_sym(n.UTF8String);
        if (p && ds_patch_ret0(p)) ok++;
    }
    NSLog(@"[DeltaSkin] ACE report channel: %d/%lu neutralised",
          ok, (unsigned long)names.count);
    return ok;
}

// Jailbroken devices only: ACE builds a "your device has been jailbroken /
// EXIT" dialog and drops the game. Locate that leaf function by the message it
// loads, walk back to its frame setup, and return early. Bounded; when the
// anchor is not where we expect, nothing is patched.
static BOOL ds_jb_hint(void) {
    return access("/var/jb/usr/bin/dpkg", F_OK) == 0
        || access("/Applications/Cydia.app", F_OK) == 0
        || access("/usr/sbin/sshd", F_OK) == 0;
}

static BOOL ds_kill_jb_warning(void) {
    // Built through the noinline decoder: an inline XOR loop here gets folded
    // back into a plaintext string at -O2, which is the whole thing we avoid.
    const char *needle = kJailbreakMessage().UTF8String;
    const size_t nlen = needle ? strlen(needle) : 0;
    if (!nlen) return NO;

    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        const char *b = strrchr(nm, '/');
        b = b ? b + 1 : nm;
        if (strcmp(b, "anogs") != 0) continue;

        const struct mach_header_64 *mh = (const struct mach_header_64 *)_dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) return NO;
        int64_t slide = _dyld_get_image_vmaddr_slide(i);

        uint64_t textLo = 0, textHi = 0;
        uint64_t p = (uint64_t)mh + sizeof(struct mach_header_64);
        for (uint32_t c = 0; c < mh->ncmds; c++) {
            const struct load_command *lc = (const struct load_command *)p;
            if (lc->cmd == LC_SEGMENT_64) {
                const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
                if (strcmp(seg->segname, "__TEXT") == 0) {
                    textLo = seg->vmaddr + slide;
                    textHi = textLo + seg->vmsize;
                }
            }
            if (lc->cmdsize < 8) break;
            p += lc->cmdsize;
        }
        if (!textLo || textHi - textLo < 0x1000) return NO;

        uint64_t strAddr = 0;
        for (uint64_t a = textLo; a + nlen < textHi; a++) {
            if (memcmp((const void *)a, needle, nlen) == 0) { strAddr = a; break; }
        }
        if (!strAddr) return NO;

        uint64_t site = 0;
        for (uint64_t a = (textLo + 3) & ~3ull; a + 8 <= textHi; a += 4) {
            uint32_t i0 = *(uint32_t *)a, i1 = *(uint32_t *)(a + 4);
            if ((i0 & 0x9F000000u) != 0x90000000u) continue;   // ADRP
            if ((i1 & 0xFF800000u) != 0x91000000u) continue;   // ADD (imm, no shift)
            int64_t imm = ((int64_t)((i0 >> 5) & 0x7FFFF) << 2) | ((i0 >> 29) & 3);
            if (imm & (1 << 20)) imm -= (1 << 21);
            uint64_t page = (a & ~0xFFFull) + ((uint64_t)imm << 12);
            if (page + ((i1 >> 10) & 0xFFF) == strAddr) { site = a; break; }
        }
        if (!site) return NO;

        uint64_t start = 0;
        for (int64_t a = (int64_t)site - 4; a >= (int64_t)textLo && a >= (int64_t)site - 0x400; a -= 4) {
            if (*(uint32_t *)a == 0xD65F03C0u) { start = (uint64_t)a + 4; break; }
        }
        if (!start || start >= site || site - start > 0x200) return NO;

        uint32_t first = *(uint32_t *)start;
        if (first == 0xD503233Fu) first = *(uint32_t *)(start + 4);   // pacibsp
        BOOL framed = ((first & 0xFFC07FFFu) == 0xA9807BFDu)          // stp x29,x30,[sp,#-n]!
                   || ((first & 0xFF8003FFu) == 0xD10003FFu);         // sub sp,sp,#n
        if (!framed) return NO;

        return ds_patch_ret0((void *)start);
    }
    return NO;
}

static void ds_start(void) {
    if (ds_hostile_environment()) {
        NSLog(@"[DeltaSkin] hostile environment, staying dormant");
        return;
    }
    @try {
        gAceHits = ds_install_ace();
        if (ds_jb_hint()) {
            NSLog(@"[DeltaSkin] jailbreak dialog patched: %d", ds_kill_jb_warning());
        }
    } @catch (NSException *e) {
        NSLog(@"[DeltaSkin] ace stage threw %@", e);
    }
    // jitter: fixed-death timers are a fingerprint
    double delay = 1.4 + ((double)(arc4random_uniform(900)) / 1000.0);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(delay * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        [[DSMenu shared] install];
        dispatch_async(dispatch_get_global_queue(0, 0), ^{ ds_bootstrap(); });
    });
}

__attribute__((constructor)) static void DeltaSkinInit(void) {
    @autoreleasepool {
        ds_start();
    }
}
