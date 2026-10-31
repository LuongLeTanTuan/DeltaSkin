// DeltaSkin — UE5 skin mod bridge for DeltaForceClient (iOS, arm64)
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
#import <mach/mach_vm.h>
#import <mach/vm_region.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <sys/sysctl.h>
#import <dlfcn.h>
#import <string.h>
#import <stdlib.h>

// ---------------------------------------------------------------- obfuscation
// Engine identifiers are stored XOR'd so the strings never appear in __cstring.
// This is cheap hygiene against naive string scanning by the anti-cheat.
static NSString *DSDecode(const unsigned char *buf, size_t len, unsigned char key) {
    char tmp[128] = {0};
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    for (size_t i = 0; i < len; i++) tmp[i] = (char)(buf[i] ^ key);
    return [NSString stringWithUTF8String:tmp];
}

#define DSSTR(name, key, ...) \
    static NSString *name(void) { \
        static const unsigned char b[] = { __VA_ARGS__ }; \
        return DSDecode(b, sizeof(b), key); \
    }

��DSSTR(kClassWeaponDesc, 0x5A,
      0x17, 0x35, 0x3E, 0x2F, 0x36, 0x3B, 0x28, 0x0D, 0x3F, 0x3B, 0x2A, 0x35, 0x34, 0x1E, 0x3F, 0x29, 0x39)
DSSTR(kClassGPWeaponDesc, 0x5A,
      0x1D, 0x0A, 0x17, 0x35, 0x3E, 0x2F, 0x36, 0x3B, 0x28, 0x0D, 0x3F, 0x3B, 0x2A, 0x35, 0x34, 0x1E, 0x3F, 0x29, 0x39)
DSSTR(kClassDataAppearance, 0x33,
      0x7E, 0x5C, 0x57, 0x46, 0x5F, 0x52, 0x41, 0x64, 0x56, 0x52, 0x43, 0x5C, 0x5D, 0x77, 0x52, 0x47, 0x52, 0x70, 0x5C, 0x5E, 0x43, 0x5C, 0x5D, 0x56, 0x5D, 0x47, 0x72, 0x43, 0x43, 0x56, 0x52, 0x41, 0x52, 0x5D, 0x50, 0x56)
DSSTR(kClassFuncAppearance, 0x33,
      0x7E, 0x5C, 0x57, 0x46, 0x5F, 0x52, 0x41, 0x64, 0x56, 0x52, 0x43, 0x5C, 0x5D, 0x75, 0x46, 0x5D, 0x50, 0x70, 0x5C, 0x5E, 0x43, 0x5C, 0x5D, 0x56, 0x5D, 0x47, 0x72, 0x43, 0x43, 0x56, 0x52, 0x41, 0x52, 0x5D, 0x50, 0x56)
DSSTR(kFnSetSkinId, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F, 0x08, 0x25)
DSSTR(kFnSetSkin, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F)
DSSTR(kFnSetSkinAppearance, 0x41,
      0x12, 0x24, 0x35, 0x12, 0x2A, 0x28, 0x2F, 0x00, 0x31, 0x31, 0x24, 0x33, 0x20, 0x2F, 0x22, 0x24, 0x08, 0x25)
DSSTR(kFnApplySkin, 0x41,
      0x00, 0x31, 0x31, 0x2D, 0x38, 0x12, 0x2A, 0x28, 0x2F)
DSSTR(kHostImage, 0x13,
      0x57, 0x76, 0x7F, 0x67, 0x72, 0x55, 0x7C, 0x61, 0x70, 0x76, 0x50, 0x7F, 0x7A, 0x76, 0x7D, 0x67)

// ------------------------------------------------------------------- globals
static uint64_t gGenObjects = 0;   // async, set on main thread
static BOOL     gReady = NO;
static NSString *gStatus = @"idle";

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

    mach_vm_address_t address = 0;
    int guard = 0;
    while (guard++ < DS_MAX_RANGES) {
        mach_vm_size_t size = 0;
        natural_t depth = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &address, &size, &depth,
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
static void ds_locate_host(void) {
    if (gHostHeader) return;
    NSString *want = kHostImage();
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        const char *base = strrchr(nm, '/');
        base = base ? base + 1 : nm;
        if (strcmp(base, want.UTF8String) != 0) continue;

        const struct mach_header_64 *mh = _dyld_get_image_header(i);
        if (!mh || mh->magic != MH_MAGIC_64) continue;

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
            NSLog(@"[DeltaSkin] GNames @0x%llx", p);
            return YES;
        }
    }
    return NO;
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
    NSLog(@"[DeltaSkin] GObjects @0x%llx hits=%d", best, bestHits);
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

// Ranked so the most specific setter wins in a single pass.
static int ds_setter_rank(const char *name) {
    if (strcmp(name, kFnSetSkinId().UTF8String) == 0) return 4;
    if (strcmp(name, kFnSetSkinAppearance().UTF8String) == 0) return 3;
    if (strcmp(name, kFnSetSkin().UTF8String) == 0) return 2;
    if (strcmp(name, kFnApplySkin().UTF8String) == 0) return 1;
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
    NSMutableArray<NSNumber *> *entries = [NSMutableArray array];
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
    if (!ds_find_gnames()) { gStatus = @"GNames not found"; return; }
    if (!ds_find_gobjects()) { gStatus = @"GObjects not found"; return; }
    gReady = YES;
    gStatus = @"ready";
    NSLog(@"[DeltaSkin] ready");
}

// ------------------------------------------------------------------- the UI
@interface DSMenu : NSObject
@property (nonatomic, strong) UIView *root;
@property (nonatomic, strong) UIView *panel;
@property (nonatomic, strong) UITextField *field;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, assign) BOOL open;
@end

@implementation DSMenu

+ (instancetype)shared {
    static DSMenu *m;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ m = [DSMenu new]; });
    return m;
}

// Attach to the app's own window instead of making a second key window: a new
// UIWindow breaks UE4's scene/rotation handling and is an extra detection signal.
- (UIWindow *)hostWindow {
    for (UIScene *sc in UIApplication.sharedApplication.connectedScenes) {
        if (![sc isKindOfClass:UIWindowScene.class]) continue;
        UIWindowScene *ws = (UIWindowScene *)sc;
        for (UIWindow *w in ws.windows) {
            if (w.isKeyWindow) return w;
        }
        if (ws.windows.count) return ws.windows.firstObject;
    }
    return UIApplication.sharedApplication.windows.firstObject;
}

- (void)install {
    if (self.root) return;
    UIWindow *host = [self hostWindow];
    if (!host) return;

    self.root = [[UIView alloc] initWithFrame:host.bounds];
    self.root.backgroundColor = UIColor.clearColor;
    self.root.userInteractionEnabled = YES;
    [host addSubview:self.root];

    UIButton *fab = [UIButton buttonWithType:UIButtonTypeCustom];
    fab.frame = CGRectMake(18, 120, 54, 54);
    fab.backgroundColor = [UIColor colorWithRed:0.08 green:0.09 blue:0.13 alpha:0.92];
    fab.layer.cornerRadius = 27;
    fab.layer.borderWidth = 1;
    fab.layer.borderColor = [UIColor colorWithRed:0.35 green:0.9 blue:0.7 alpha:0.9].CGColor;
    [fab setTitle:@"DS" forState:UIControlStateNormal];
    [fab setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [fab addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [self.root addSubview:fab];

    [self buildPanel];
    [self.root addSubview:self.panel];
}

- (UILabel *)label:(NSString *)text size:(CGFloat)size color:(UIColor *)color {
    UILabel *l = [UILabel new];
    l.text = text;
    l.font = [UIFont systemFontOfSize:size weight:UIFontWeightSemibold];
    l.textColor = color;
    return l;
}

- (void)buildPanel {
    CGFloat w = 300;
    self.panel = [[UIView alloc] initWithFrame:CGRectMake(18, 190, w, 250)];
    self.panel.backgroundColor = [UIColor colorWithRed:0.07 green:0.08 blue:0.11 alpha:0.97];
    self.panel.layer.cornerRadius = 16;
    self.panel.layer.borderWidth = 1;
    self.panel.layer.borderColor = [UIColor colorWithWhite:1 alpha:0.12].CGColor;
    self.panel.hidden = YES;

    UILabel *title = [self label:@"SKIN MOD" size:15 color:UIColor.whiteColor];
    title.frame = CGRectMake(16, 14, w - 32, 20);
    [self.panel addSubview:title];

    self.status = [self label:@"idle" size:11 color:[UIColor colorWithWhite:1 alpha:0.55]];
    self.status.frame = CGRectMake(16, 34, w - 32, 16);
    self.status.numberOfLines = 0;
    [self.panel addSubview:self.status];

    self.field = [[UITextField alloc] initWithFrame:CGRectMake(16, 62, w - 32, 40)];
    self.field.backgroundColor = [UIColor colorWithWhite:1 alpha:0.07];
    self.field.layer.cornerRadius = 10;
    self.field.textColor = UIColor.whiteColor;
    self.field.keyboardType = UIKeyboardTypeNumberPad;
    self.field.placeholder = @"skin id (decimal or 0x...)";
    self.field.attributedPlaceholder =
        [[NSAttributedString alloc] initWithString:@"skin id (decimal or 0x...)"
                                        attributes:@{NSForegroundColorAttributeName:[UIColor colorWithWhite:1 alpha:0.35]}];
    self.field.leftView = [[UIView alloc] initWithFrame:CGRectMake(0, 0, 12, 40)];
    self.field.leftViewMode = UITextFieldViewModeAlways;
    [self.panel addSubview:self.field];

    UIButton *apply = [UIButton buttonWithType:UIButtonTypeSystem];
    apply.frame = CGRectMake(16, 112, w - 32, 44);
    apply.backgroundColor = [UIColor colorWithRed:0.25 green:0.85 blue:0.62 alpha:1];
    apply.layer.cornerRadius = 10;
    [apply setTitle:@"APPLY SKIN" forState:UIControlStateNormal];
    [apply setTitleColor:[UIColor blackColor] forState:UIControlStateNormal];
    [apply addTarget:self action:@selector(applyTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.panel addSubview:apply];

    UIButton *restore = [UIButton buttonWithType:UIButtonTypeSystem];
    restore.frame = CGRectMake(16, 164, w - 32, 40);
    restore.backgroundColor = [UIColor colorWithWhite:1 alpha:0.08];
    restore.layer.cornerRadius = 10;
    [restore setTitle:@"RESTORE (skin 0)" forState:UIControlStateNormal];
    [restore setTitleColor:UIColor.whiteColor forState:UIControlStateNormal];
    [restore addTarget:self action:@selector(restoreTapped) forControlEvents:UIControlEventTouchUpInside];
    [self.panel addSubview:restore];

    UIButton *close = [UIButton buttonWithType:UIButtonTypeSystem];
    close.frame = CGRectMake(w - 44, 10, 34, 34);
    [close setTitle:@"x" forState:UIControlStateNormal];
    [close setTitleColor:[UIColor colorWithWhite:1 alpha:0.6] forState:UIControlStateNormal];
    [close addTarget:self action:@selector(toggle) forControlEvents:UIControlEventTouchUpInside];
    [self.panel addSubview:close];
}

- (void)setStatusText:(NSString *)s {
    dispatch_async(dispatch_get_main_queue(), ^{
        gStatus = s;
        self.status.text = s;
    });
}

- (void)toggle {
    self.open = !self.open;
    self.panel.hidden = !self.open;
    if (self.open) {
        self.status.text = gStatus;
        [self runReport];
    }
}

- (void)runReport {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        if (!gReady) ds_bootstrap();
        NSString *s = gReady
            ? [NSString stringWithFormat:@"ready · GNames 0x%llx · GObjects 0x%llx",
                                         (unsigned long long)0, (unsigned long long)gGenObjects]
            : gStatus;
        [self setStatusText:s];
    });
}

static unsigned long long ds_parse_id(NSString *s) {
    NSString *t = [s stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
    if (!t.length) return 0;
    if ([t hasPrefix:@"0x"] || [t hasPrefix:@"0X"]) return strtoull(t.UTF8String, NULL, 16);
    return strtoull(t.UTF8String, NULL, 10);
}

- (void)applyTapped {
    [self.field resignFirstResponder];
    int skinId = (int)ds_parse_id(self.field.text);
    [self setStatusText:@"applying..."];
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        if (!gReady) ds_bootstrap();
        if (!gReady) { [self setStatusText:gStatus]; return; }
        int n = ds_apply_all(skinId);
        [self setStatusText:n > 0 ? [NSString stringWithFormat:@"applied %d to %d object(s)", skinId, n]
                                  : [NSString stringWithFormat:@"no target matched (code %d)", n]];
    });
}

- (void)restoreTapped {
    self.field.text = @"0";
    [self applyTapped];
}

@end

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

static void ds_start(void) {
    if (ds_hostile_environment()) {
        NSLog(@"[DeltaSkin] hostile environment, staying dormant");
        return;
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
