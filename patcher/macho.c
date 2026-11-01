#include "macho.h"
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ Mach-O */
#define MH_MAGIC_64        0xfeedfacfu
#define MH_EXECUTE         2u
#define MH_DYLIB           6u
#define LC_SEGMENT_64      0x19u
#define LC_LOAD_DYLIB      0x0Cu
#define LC_CODE_SIGNATURE  0x1Du
#define LC_ENCRYPTION_INFO_64 0x2Cu
#define CPU_TYPE_ARM64     0x0100000Cu
#define CPU_SUBTYPE_MASK   0xFF000000u

typedef struct {
    uint32_t magic, cputype, cpusubtype, filetype;
    uint32_t ncmds, sizeofcmds, flags, reserved;
} hdr64;

typedef struct { uint32_t cmd, cmdsize; } lc;

typedef struct {
    uint32_t cmd, cmdsize;
    char     segname[16];
    uint64_t vmaddr, vmsize, fileoff, filesize;
    uint32_t maxprot, initprot, nsects, flags;
} seg64;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr, size;
    uint32_t offset, align, reloff, nreloc, flags;
    uint32_t reserved1, reserved2, reserved3;
} sect64;

typedef struct {
    uint32_t cmd, cmdsize;
    uint32_t name_offset, timestamp, current_version, compat_version;
} dylib_cmd;

typedef struct { uint32_t cmd, cmdsize, dataoff, datasize; } linkedit_cmd;

typedef struct {
    uint32_t cmd, cmdsize, cryptoff, cryptsize, cryptid, pad;
} encryption_info_64;

/* ------------------------------------------------------------ code signing */
#define CSMAGIC_EMBEDDED_SIGNATURE 0xfade0cc0u
#define CSMAGIC_CODEDIRECTORY      0xfade0c02u
#define CSMAGIC_ENTITLEMENTS       0xfade7171u
#define ENT_BLOB_HEADER            8u
#define CSSLOT_CODEDIRECTORY       0u
#define CSSLOT_ENTITLEMENTS        5u
#define CSSLOT_SIGNATURE           0x10000u
#define CSMAGIC_BLOBWRAPPER        0xfade0b01u
#define CS_ADHOC                   0x00000002u
#define CS_EXECSEG_MAIN_BINARY     0x00000001u
#define CS_EXECSEG_ALLOW_UNSIGNED  0x00000010u
#define CD_VERSION                 0x00020400u   /* 0x20400 adds execSeg* */
#define HASH_SIZE                  32u          /* SHA-256 */
#define HASH_TYPE_SHA256           2u
#define PAGE_SHIFT                 12u          /* 4 KiB: what Apple's own iOS signature on this game uses */
#define CD_HEADER_SIZE             0x58u

/* Code signing structures are stored big-endian in the Mach-O, unlike every
 * other field in the file. Verified against the game's own signature
 * (LC_CODE_SIGNATURE at 0x1830AB70 starts fa de 0c c0). Writing them
 * little-endian produces a blob our own verifier would happily accept and
 * dyld would not. */
static uint32_t rd32(const void *p) {
    const uint8_t *b = (const uint8_t *)p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

static uint32_t align_up(uint32_t v, uint32_t a) { return (v + a - 1u) & ~(a - 1u); }
static uint64_t align_up64(uint64_t v, uint64_t a) { return (v + a - 1u) & ~(a - 1u); }

static void set_err(char *err, size_t cap, const char *msg) {
    if (!err || !cap) return;
    snprintf(err, cap, "%s", msg);
}

static int read_file(const char *path, uint8_t **out, size_t *outLen) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *b = (uint8_t *)malloc((size_t)n);
    if (!b) { fclose(f); return -1; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return -1; }
    fclose(f);
    *out = b;
    *outLen = (size_t)n;
    return 0;
}

/* The file plus the room the signature may need, in one allocation. The tail is
 * left to calloc's zero pages so a 400 MB executable is not copied twice and the
 * headroom costs nothing until it is written. Nothing is reallocated later
 * because every pointer in the parsed layout points into this buffer. */
#define HEADROOM (4u << 20)
static int read_file_roomy(const char *path, uint8_t **out, size_t *outLen, size_t *outCap) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long n = ftell(f);
    if (n <= 0) { fclose(f); return -1; }
    rewind(f);
    size_t cap = (size_t)n + HEADROOM;
    uint8_t *b = (uint8_t *)calloc(1, cap);
    if (!b) { fclose(f); return -1; }
    if (fread(b, 1, (size_t)n, f) != (size_t)n) { free(b); fclose(f); return -1; }
    fclose(f);
    *out = b;
    *outLen = (size_t)n;
    *outCap = cap;
    return 0;
}

static int write_file(const char *path, const uint8_t *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t w = fwrite(buf, 1, len, f);
    int rc = fflush(f);
    fclose(f);
    return (w == len && rc == 0) ? 0 : -1;
}

/* ------------------------------------------------------------ header sweep */
typedef struct {
    hdr64  *h;
    seg64  *linkedit;      /* may be NULL */
    seg64  *text;
    linkedit_cmd *sig;     /* may be NULL */
    uint32_t hdrEnd;       /* end of the load command area */
    uint32_t firstContent; /* first byte of real section data */
} layout;

static int scan_layout(uint8_t *buf, size_t len, layout *L) {
    if (len < sizeof(hdr64)) return -1;
    hdr64 *h = (hdr64 *)buf;
    if (h->magic != MH_MAGIC_64) return -1;
    if (h->cputype != CPU_TYPE_ARM64) return -1;
    if (h->filetype != MH_EXECUTE && h->filetype != MH_DYLIB) return -1;

    memset(L, 0, sizeof(*L));
    L->h = h;
    L->firstContent = (uint32_t)len;

    uint64_t off = sizeof(hdr64);
    for (uint32_t i = 0; i < h->ncmds; i++) {
        if (off + sizeof(lc) > len) return -1;
        lc *c = (lc *)(buf + off);
        if (c->cmdsize < sizeof(lc) || off + c->cmdsize > len) return -1;

        if (c->cmd == LC_SEGMENT_64 && c->cmdsize >= sizeof(seg64)) {
            seg64 *s = (seg64 *)c;
            if (strncmp(s->segname, "__LINKEDIT", 11) == 0) L->linkedit = s;
            if (strncmp(s->segname, "__TEXT", 7) == 0) {
                L->text = s;
                sect64 *sec = (sect64 *)((uint8_t *)s + sizeof(seg64));
                for (uint32_t k = 0; k < s->nsects; k++) {
                    if (sec[k].offset && sec[k].offset < L->firstContent)
                        L->firstContent = sec[k].offset;
                    if (sec[k].offset && sec[k].size > 0 &&
                        sec[k].offset + sec[k].size > len) return -1;   /* truncated */
                }
            }
        } else if (c->cmd == LC_CODE_SIGNATURE && c->cmdsize >= sizeof(linkedit_cmd)) {
            L->sig = (linkedit_cmd *)c;
        }
        off += c->cmdsize;
    }
    L->hdrEnd = (uint32_t)(sizeof(hdr64) + h->sizeofcmds);
    if (L->firstContent < L->hdrEnd) L->firstContent = L->hdrEnd;
    return 0;
}

/* Reserve room for one more load command in the header padding. */
static lc *reserve_command(uint8_t *buf, size_t len, layout *L, uint32_t cmdSize) {
    if (L->hdrEnd + cmdSize > L->firstContent) return NULL;
    if (L->hdrEnd + cmdSize > len) return NULL;
    lc *c = (lc *)(buf + L->hdrEnd);
    memset(c, 0, cmdSize);
    c->cmd = 0;
    c->cmdsize = cmdSize;
    L->h->ncmds += 1;
    L->h->sizeofcmds += cmdSize;
    L->hdrEnd += cmdSize;
    return c;
}

/* ------------------------------------------------------------------ signer */
static uint32_t cd_put(uint8_t *p, uint32_t off, uint32_t v) {
    p[off] = (uint8_t)(v >> 24);
    p[off + 1] = (uint8_t)(v >> 16);
    p[off + 2] = (uint8_t)(v >> 8);
    p[off + 3] = (uint8_t)v;
    return off + 4;
}
static uint32_t cd_put64(uint8_t *p, uint32_t off, uint64_t v) {
    off = cd_put(p, off, (uint32_t)(v >> 32));
    return cd_put(p, off, (uint32_t)v);
}

typedef struct {
    uint32_t hashOff, cdLen, superHdr, entOff, entBlobLen, cmsOff, cmsBlobLen, total;
    uint32_t blobCount;
} sig_layout;

/* The signature's size depends only on the codeLimit (sigOff), the identifier
 * and which extra blobs ride along -- but nCode grows with the file, and a
 * 400 MB executable needs ~25000 page slots, i.e. ~800 kB of CodeDirectory. A
 * fixed "one page of slack" guess under-reserves there, so the size is measured
 * once, used to reserve the buffer, then reused to write into it. */
static void sig_measure(uint32_t sigOff, const char *ident, uint32_t entLen,
                        uint32_t cmsLen, sig_layout *S) {
    const uint32_t nCode = (sigOff + (1u << PAGE_SHIFT) - 1u) >> PAGE_SHIFT;
    const uint32_t nSpecial = entLen ? 1u : 0u;
    const uint32_t identLen = align_up((uint32_t)strlen(ident) + 1u, 8u);
    S->hashOff = CD_HEADER_SIZE + identLen + nSpecial * HASH_SIZE;
    S->cdLen = S->hashOff + nCode * HASH_SIZE;
    S->blobCount = 1u + (entLen ? 1u : 0u) + (cmsLen ? 1u : 0u);
    S->superHdr = align_up(12u + S->blobCount * 8u, 16u);
    S->entOff = align_up(S->superHdr + S->cdLen, 16u);
    S->entBlobLen = entLen ? ENT_BLOB_HEADER + entLen : 0u;
    S->cmsOff = align_up(S->entOff + S->entBlobLen, 16u);
    S->cmsBlobLen = cmsLen ? ENT_BLOB_HEADER + cmsLen : 0u;
    S->total = align_up(S->cmsOff + S->cmsBlobLen, 16u);
}

/* Writes the signature described by S. sigOff is also the CodeDirectory
 * codeLimit, i.e. the first byte that is not hashed. */
static void build_signature(uint8_t *sig, const uint8_t *file, uint32_t sigOff,
                            const char *ident, uint32_t execBase, uint32_t execLimit,
                            uint32_t execFlags,
                            const uint8_t *ent, uint32_t entLen,
                            const uint8_t *cms, uint32_t cmsLen, const sig_layout *S) {
    const uint32_t nCode = (sigOff + (1u << PAGE_SHIFT) - 1u) >> PAGE_SHIFT;
    const uint32_t nSpecial = entLen ? 1u : 0u;

    memset(sig, 0, S->total);

    /* SuperBlob header */
    cd_put(sig, 0x00, CSMAGIC_EMBEDDED_SIGNATURE);
    cd_put(sig, 0x04, S->total);
    cd_put(sig, 0x08, S->blobCount);
    uint32_t b = 0x0C;
    cd_put(sig, b, CSSLOT_CODEDIRECTORY);   cd_put(sig, b + 4, S->superHdr); b += 8;
    if (entLen)  { cd_put(sig, b, CSSLOT_ENTITLEMENTS); cd_put(sig, b + 4, S->entOff);  b += 8; }
    if (cmsLen)  { cd_put(sig, b, CSSLOT_SIGNATURE);    cd_put(sig, b + 4, S->cmsOff);  b += 8; }

    /* CodeDirectory */
    uint8_t *cd = sig + S->superHdr;
    uint32_t o = 0;
    o = cd_put(cd, o, CSMAGIC_CODEDIRECTORY);
    o = cd_put(cd, o, S->cdLen);
    o = cd_put(cd, o, CD_VERSION);
    o = cd_put(cd, o, cmsLen ? 0u : CS_ADHOC);
    o = cd_put(cd, o, S->hashOff);
    o = cd_put(cd, o, CD_HEADER_SIZE);
    o = cd_put(cd, o, nSpecial);
    o = cd_put(cd, o, nCode);
    o = cd_put(cd, o, sigOff);
    cd[o++] = (uint8_t)HASH_SIZE;
    cd[o++] = (uint8_t)HASH_TYPE_SHA256;
    cd[o++] = 0;                          /* platform */
    cd[o++] = (uint8_t)PAGE_SHIFT;
    o = cd_put(cd, o, 0);                 /* spare2 */
    o = cd_put(cd, o, 0);                 /* scatterOffset */
    o = cd_put(cd, o, 0);                 /* teamOffset */
    o = cd_put(cd, o, 0);                 /* spare3 */
    o = cd_put64(cd, o, 0);               /* codeLimit64 */
    o = cd_put64(cd, o, execBase);
    o = cd_put64(cd, o, execLimit);
    o = cd_put64(cd, o, execFlags);
    if (o != CD_HEADER_SIZE) return;      /* layout drifted: nothing written */

    memcpy(cd + CD_HEADER_SIZE, ident, strlen(ident) + 1);

    if (entLen) {
        uint8_t h[32];
        sha256(ent, entLen, h);
        memcpy(cd + S->hashOff - HASH_SIZE, h, HASH_SIZE);    /* slot -1 = entitlements */
    }

    /* Page hashes: one slot per 16 KiB, in file order. */
    for (uint32_t i = 0; i < nCode; i++) {
        uint32_t start = i << PAGE_SHIFT;
        uint32_t n = sigOff - start;
        if (n > (1u << PAGE_SHIFT)) n = 1u << PAGE_SHIFT;
        sha256(file + start, n, cd + S->hashOff + i * HASH_SIZE);
    }

    /* Entitlements go in as a real blob (0xfade7171 + length + XML), not a bare
     * XML run: the tools that read a signature back (TrollStore's own signer,
     * amfi) parse this slot as a blob and drop the entitlements on an unknown
     * magic, which would cost this app its no-sandbox entitlement. The special
     * slot hash covers the payload only, not the 8-byte header. */
    if (entLen) {
        cd_put(sig, S->entOff, CSMAGIC_ENTITLEMENTS);
        cd_put(sig, S->entOff + 4, S->entBlobLen);
        memcpy(sig + S->entOff + ENT_BLOB_HEADER, ent, entLen);
    }

    /* The original CMS is carried over byte for byte. TrollStore's CoreTrust
     * path is what accepts a re-signed app on iOS 14, and it will not accept a
     * bare ad-hoc CodeDirectory; an existing CMS blob is kept so the app is no
     * worse off than before the patch. It is not re-hashed -- the CodeDirectory
     * above is the authority for the page hashes. */
    if (cmsLen) {
        cd_put(sig, S->cmsOff, CSMAGIC_BLOBWRAPPER);
        cd_put(sig, S->cmsOff + 4, S->cmsBlobLen);
        memcpy(sig + S->cmsOff + ENT_BLOB_HEADER, cms, cmsLen);
    }
}

/* Writes an embedded signature into the buffer. *cap is the reserved capacity
 * (read_file_roomy) and must already cover sigOff + the blob; nothing is
 * reallocated here because every pointer in L points into that buffer. */
static int sign_buffer(uint8_t **bufp, size_t *len, size_t *cap, layout *L,
                       const char *ident, uint32_t execFlags,
                       const uint8_t *ent, uint32_t entLen,
                       const uint8_t *cms, uint32_t cmsLen, char *err, size_t errCap) {
    uint8_t *buf = *bufp;
    if (!L->linkedit) { set_err(err, errCap, "no __LINKEDIT segment"); return -1; }

    if (!L->sig) {
        uint32_t cmdSize = align_up((uint32_t)sizeof(linkedit_cmd), 8);
        lc *c = reserve_command(buf, *len, L, cmdSize);
        if (!c) { set_err(err, errCap, "no header room for LC_CODE_SIGNATURE"); return -1; }
        c->cmd = LC_CODE_SIGNATURE;
        c->cmdsize = cmdSize;
        L->sig = (linkedit_cmd *)c;
        L->sig->dataoff = 0;
        L->sig->datasize = 0;
    }

    /* The signature goes where the previous one was, else it is appended. */
    uint32_t sigOff = 0;
    if (L->sig->dataoff && (uint64_t)L->sig->dataoff + L->sig->datasize <= *len)
        sigOff = L->sig->dataoff;
    if (!sigOff) sigOff = align_up((uint32_t)*len, 16);
    if (sigOff < L->h->sizeofcmds + sizeof(hdr64)) {
        set_err(err, errCap, "code signature offset overlaps the header");
        return -1;
    }

    /* execSegBase/execSegLimit are the __TEXT segment's *file* offset and size,
     * not its vmaddr -- the vmaddr of an iOS main binary is 0x100000000 and
     * does not fit, and amfi compares these against the loaded image. */
    uint32_t execBase = 0, execLimit = 0;
    if (L->text) { execBase = (uint32_t)L->text->fileoff; execLimit = (uint32_t)L->text->filesize; }

    /* The page-slot table grows with the file, so the real size is measured
     * before anything is written -- see sig_measure. */
    sig_layout S;
    sig_measure(sigOff, ident, entLen, cmsLen, &S);

    size_t need = (size_t)sigOff + S.total;
    if (need > *cap) {
        set_err(err, errCap, "signature does not fit in the reserved headroom");
        return -1;
    }
    if (need > *len) memset(buf + *len, 0, need - *len);

    build_signature(buf + sigOff, buf, sigOff, ident,
                    execBase, execLimit, execFlags, ent, entLen, cms, cmsLen, &S);

    uint64_t end = (uint64_t)sigOff + S.total;
    if (end > *len) *len = (size_t)end;      /* file grows, tail already zeroed */

    L->sig->dataoff = sigOff;
    L->sig->datasize = S.total;

    /* __LINKEDIT must physically cover the blob, not just the old data. */
    uint64_t segEnd = L->linkedit->fileoff + L->linkedit->filesize;
    if (end > segEnd) {
        L->linkedit->filesize = end - L->linkedit->fileoff;
        L->linkedit->vmsize = align_up64(L->linkedit->filesize, 1u << PAGE_SHIFT);
    }
    return 0;
}

/* -------------------------------------------------------------------- API */
/* Copies the payload of one slot out of an embedded SuperBlob. The two blobs
 * this file cares about (entitlements, CMS) are wrapped in an 8-byte header
 * whose magic differs, and the special-slot hash covers the payload only. */
static int blob_payload(const uint8_t *s, uint32_t avail, uint32_t want,
                        uint8_t **out, uint32_t *outLen) {
    *out = NULL;
    *outLen = 0;
    if (avail < 12) return -1;

    if (rd32(s) != CSMAGIC_EMBEDDED_SIGNATURE) return -1;
    const uint32_t count = rd32(s + 8);
    if (count > 64 || 12u + count * 8u > avail) return -1;

    for (uint32_t i = 0; i < count; i++) {
        const uint32_t type = rd32(s + 12 + i * 8);
        const uint32_t off = rd32(s + 16 + i * 8);
        if (type != want) continue;
        if ((uint64_t)off + 8 > avail) return -1;

        const uint32_t blen = rd32(s + off + 4);
        if (blen < 8 || (uint64_t)off + blen > avail) return -1;

        uint32_t n = blen - 8;
        uint8_t *cp = (uint8_t *)malloc(n ? n : 1);
        if (!cp) return -1;
        memcpy(cp, s + off + 8, n);
        *out = cp;
        *outLen = n;
        return 0;
    }
    return -1;
}

int mo_is_arm64_macho(const char *path) {
    uint8_t *b = NULL;
    size_t n = 0;
    if (read_file(path, &b, &n) != 0) return 0;
    int ok = 0;
    if (n >= sizeof(hdr64)) {
        hdr64 *h = (hdr64 *)b;
        ok = (h->magic == MH_MAGIC_64 && h->cputype == CPU_TYPE_ARM64);
    }
    free(b);
    return ok;
}

int mo_adhoc_sign_file(const char *path, const uint8_t *ent, size_t entLen,
                       char *err, size_t errCap) {
    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    if (read_file_roomy(path, &buf, &len, &cap) != 0) { set_err(err, errCap, "cannot read the binary"); return -1; }

    layout L;
    if (scan_layout(buf, len, &L) != 0) { free(buf); set_err(err, errCap, "not a thin arm64 Mach-O"); return -1; }

    if (entLen > 0x10000) { free(buf); set_err(err, errCap, "entitlements too large"); return -1; }

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    char ident[128];
    snprintf(ident, sizeof(ident), "%s", base);

    /* Re-signing keeps an existing CMS blob so a signature that was accepted
     * before is not replaced by a bare ad-hoc one. */
    uint8_t *cms = NULL;
    uint32_t cmsLen = 0;
    if (L.sig && L.sig->dataoff && L.sig->datasize &&
        (uint64_t)L.sig->dataoff + L.sig->datasize <= len) {
        blob_payload(buf + L.sig->dataoff, L.sig->datasize, CSSLOT_SIGNATURE, &cms, &cmsLen);
    }

    int rc = sign_buffer(&buf, &len, &cap, &L, ident, 0, ent, (uint32_t)entLen,
                         cms, cmsLen, err, errCap);
    if (rc == 0) rc = write_file(path, buf, len);
    if (rc != 0 && err && !err[0]) set_err(err, errCap, "cannot write the binary");
    free(cms);
    free(buf);
    return rc;
}

int mo_inject_and_sign(const char *exePath, const char *dylibPath,
                       const uint8_t *ent, size_t entLen, char *err, size_t errCap) {
    if (!dylibPath || !dylibPath[0]) { set_err(err, errCap, "empty dylib path"); return -1; }
    if (entLen > 0x10000) { set_err(err, errCap, "entitlements too large"); return -1; }

    uint8_t *buf = NULL;
    size_t len = 0, cap = 0;
    if (read_file_roomy(exePath, &buf, &len, &cap) != 0) { set_err(err, errCap, "cannot read the executable"); return -1; }

    layout L;
    if (scan_layout(buf, len, &L) != 0) {
        free(buf);
        set_err(err, errCap, "not a thin arm64 Mach-O executable");
        return -1;
    }
    if (L.h->filetype != MH_EXECUTE) { free(buf); set_err(err, errCap, "not an executable"); return -1; }

    /* Already patched? Refuse instead of adding a second copy. */
    uint64_t off = sizeof(hdr64);
    for (uint32_t i = 0; i < L.h->ncmds; i++) {
        lc *c = (lc *)(buf + off);
        if (c->cmd == LC_LOAD_DYLIB && c->cmdsize > sizeof(dylib_cmd)) {
            const char *nm = (const char *)c + sizeof(dylib_cmd);
            const uint32_t room = c->cmdsize - (uint32_t)sizeof(dylib_cmd);
            const size_t want = strlen(dylibPath);
            if (room >= want && memcmp(nm, dylibPath, want) == 0 &&
                (room == want || nm[want] == '\0')) {
                free(buf);
                set_err(err, errCap, "already injected");
                return -2;
            }
        }
        /* A FairPlay-encrypted binary is decrypted by dyld at launch; the page
         * hashes we would sign cover ciphertext, so signing it produces a file
         * that will not start. Refuse rather than brick the app. */
        if (c->cmd == LC_ENCRYPTION_INFO_64 && c->cmdsize >= sizeof(encryption_info_64)) {
            if (((encryption_info_64 *)c)->cryptid != 0) {
                free(buf);
                set_err(err, errCap, "the binary is still FairPlay-encrypted");
                return -1;
            }
        }
        off += c->cmdsize;
    }

    /* Carry over what we cannot produce ourselves: the entitlements (unless the
     * caller brought its own) and the CMS blob, both read from the signature
     * still in the buffer. Must happen before anything is written. */
    uint8_t *cms = NULL, *own = NULL;
    uint32_t cmsLen = 0, ownLen = 0;
    if (L.sig && L.sig->dataoff && L.sig->datasize &&
        (uint64_t)L.sig->dataoff + L.sig->datasize <= len) {
        const uint8_t *s = buf + L.sig->dataoff;
        blob_payload(s, L.sig->datasize, CSSLOT_SIGNATURE, &cms, &cmsLen);
        if (!ent) {
            blob_payload(s, L.sig->datasize, CSSLOT_ENTITLEMENTS, &own, &ownLen);
            ent = own;
            entLen = ownLen;
        }
    }

    uint32_t cmdSize = align_up((uint32_t)(sizeof(dylib_cmd) + strlen(dylibPath) + 1u), 8u);
    lc *c = reserve_command(buf, len, &L, cmdSize);
    if (!c) {
        free(cms); free(own); free(buf);
        set_err(err, errCap, "no header room for LC_LOAD_DYLIB");
        return -1;
    }
    c->cmd = LC_LOAD_DYLIB;
    c->cmdsize = cmdSize;
    dylib_cmd *d = (dylib_cmd *)c;
    d->name_offset = sizeof(dylib_cmd);
    d->timestamp = 2;
    d->current_version = 0x10000;
    d->compat_version = 0x10000;
    memcpy((uint8_t *)c + sizeof(dylib_cmd), dylibPath, strlen(dylibPath) + 1);

    const char *base = strrchr(exePath, '/');
    base = base ? base + 1 : exePath;
    char ident[128];
    snprintf(ident, sizeof(ident), "%s", base);

    int rc = sign_buffer(&buf, &len, &cap, &L, ident,
                         CS_EXECSEG_MAIN_BINARY | CS_EXECSEG_ALLOW_UNSIGNED,
                         ent, (uint32_t)entLen, cms, cmsLen, err, errCap);
    if (rc == 0) rc = write_file(exePath, buf, len);
    if (rc != 0 && err && !err[0]) set_err(err, errCap, "cannot write the executable");
    free(cms);
    free(own);
    free(buf);
    return rc;
}

int mo_copy_entitlements(const char *path, uint8_t **out, uint32_t *outLen) {
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(path, &buf, &len) != 0) return -1;

    layout L;
    int rc = -1;
    if (scan_layout(buf, len, &L) == 0 && L.sig && L.sig->dataoff && L.sig->datasize &&
        (uint64_t)L.sig->dataoff + L.sig->datasize <= len) {
        rc = blob_payload(buf + L.sig->dataoff, L.sig->datasize,
                          CSSLOT_ENTITLEMENTS, out, outLen);
    }
    free(buf);
    return rc;
}
